"""Biznes məntiqi: vəziyyət maşınının qərarlarını DB-yə, bildirişlərə və audit jurnalına tətbiq edir."""
from __future__ import annotations

import json
import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from . import audit, notify, switch
from .crypto import primitives as P
from .kms import release_context
from .security import sha256_hex

BAKU = timezone(timedelta(hours=4))
RELEASED_RETENTION_DAYS = 365   # açılmış seyf 1 il sonra crypto-shred olunur


@dataclass
class Emanet:
    settings: object
    db: object
    kms: object
    storage: object
    notifier: object
    clock: object

    @property
    def audit_key(self) -> bytes:
        return self.settings.secret("audit_hmac_key")


_SWITCH_COLUMNS = frozenset({"state", "updated_at", "last_reminder_at", "reminders_sent", "release_at",
                             "released_at"})


def new_id(prefix: str) -> str:
    return f"{prefix}_{secrets.token_urlsafe(16)}"


def fmt_date(ts: float) -> str:
    return datetime.fromtimestamp(ts, BAKU).strftime("%d.%m.%Y %H:%M")


def switch_view(v) -> switch.SwitchView:
    return switch.SwitchView(state=v["state"], last_activity_at=v["last_activity_at"],
                             checkin_interval_days=v["checkin_interval_days"], inactivity_days=v["inactivity_days"],
                             waiting_days=v["waiting_days"], threshold=v["threshold"],
                             last_reminder_at=v["last_reminder_at"], paused_until=v["paused_until"],
                             release_at=v["release_at"])


def approvals_count(conn, v) -> int:
    return conn.execute("SELECT COUNT(*) FROM approvals a JOIN trustees t ON t.vault_id=a.vault_id "
                        "AND t.user_id=a.trustee_user_id AND t.status='accepted' "
                        "WHERE a.vault_id=? AND a.distribution_version=?",
                        (v["id"], v["distribution_version"])).fetchone()[0]


def accepted_trustees(conn, vault_id: str):
    return conn.execute("SELECT t.*, u.email AS u_email, u.display_name AS u_name, u.public_key AS u_pub "
                        "FROM trustees t JOIN users u ON u.id=t.user_id "
                        "WHERE t.vault_id=? AND t.status='accepted' ORDER BY t.created_at", (vault_id,)).fetchall()


def make_checkin_link(app: Emanet, conn, user_id: str, now: float) -> str:
    token = secrets.token_urlsafe(32)
    conn.execute("INSERT INTO checkin_tokens(token_hash, user_id, expires_at) VALUES(?,?,?)",
                 (sha256_hex(token), user_id, now + 14 * switch.DAY))
    # Token URL fraqmentindədir (#) — serverin/proksinin access log-larına və Referer-ə düşmür
    return f"{app.settings.public_origin}/checkin.html#t={token}"


def _owner(conn, v):
    return conn.execute("SELECT * FROM users WHERE id=?", (v["owner_id"],)).fetchone()


def apply_decision(app: Emanet, conn, v, d: switch.Decision, now: float, actor: str = "system") -> None:
    owner = _owner(conn, v)
    trustees = accepted_trustees(conn, v["id"])
    idle_days = int((now - switch.effective_last_activity(switch_view(v))) / switch.DAY)
    fields = {"state": d.state, "updated_at": now}

    for action in d.actions:
        if action in ("remind", "final_warning"):
            link = make_checkin_link(app, conn, owner["id"], now)
            notify.enqueue(conn, owner["email"], "reminder" if action == "remind" else "final_warning", now,
                           name=owner["display_name"], days=idle_days, link=link)
            fields["last_reminder_at"] = now
            fields["reminders_sent"] = (v["reminders_sent"] or 0) + 1
        elif action == "notify_trustees":
            for t in trustees:
                notify.enqueue(conn, t["u_email"], "trustees_may_request", now, owner=owner["display_name"],
                               days=idle_days, origin=app.settings.public_origin)
        elif action == "release_pending":
            fields["release_at"] = d.release_at
            link = make_checkin_link(app, conn, owner["id"], now)
            notify.enqueue(conn, owner["email"], "release_pending", now, name=owner["display_name"],
                           date=fmt_date(d.release_at), link=link)
            for t in trustees:
                notify.enqueue(conn, t["u_email"], "release_pending_trustee", now, owner=owner["display_name"],
                               date=fmt_date(d.release_at))
        elif action == "released":
            fields["released_at"] = now
            notify.enqueue(conn, owner["email"], "released_owner", now)
            for t in trustees:
                notify.enqueue(conn, t["u_email"], "released", now, owner=owner["display_name"],
                               origin=app.settings.public_origin)
        elif action == "release_cancelled":
            fields["release_at"] = None
            conn.execute("DELETE FROM approvals WHERE vault_id=?", (v["id"],))
            for t in trustees:
                notify.enqueue(conn, t["u_email"], "release_cancelled", now, owner=owner["display_name"])
        else:  # pragma: no cover
            raise ValueError(action)

    # Sütun adları yalnız sabit allowlist-dən gəlir, dəyərlər isə parametr kimi ötürülür
    unknown = set(fields) - _SWITCH_COLUMNS
    if unknown:
        raise ValueError(f"icazəsiz sütun: {sorted(unknown)}")
    sets = ", ".join(f"{k}=?" for k in fields)
    conn.execute(f"UPDATE vaults SET {sets} WHERE id=?", (*fields.values(), v["id"]))  # nosec B608 — allowlist
    if d.state != v["state"] or d.actions:
        audit.record(conn, app.audit_key, ts=now, actor=actor, action=f"switch.{v['state']}->{d.state}",
                     vault_id=v["id"], actions=",".join(d.actions) or "-")


def evaluate_vault(app: Emanet, vault_id: str, now: float | None = None) -> str:
    now = app.clock.now() if now is None else now
    with app.db.tx() as conn:
        v = conn.execute("SELECT * FROM vaults WHERE id=?", (vault_id,)).fetchone()
        if v is None:
            return "missing"
        owner = conn.execute("SELECT status FROM users WHERE id=?", (v["owner_id"],)).fetchone()
        if owner["status"] != "active" and v["state"] != "released":
            # R-26: dayandırılmış sahib "sağam" deyə bilmir — bu, açılmaya səbəb olmamalıdır.
            # Operatorun hesabı dayandırması seyfi "dondurur" (eskalasiya yoxdur).
            return v["state"]
        d = switch.evaluate(switch_view(v), now, approvals_count(conn, v))
        if d.changed(switch_view(v)):
            apply_decision(app, conn, v, d, now)
        return d.state


def touch_owner(app: Emanet, conn, user_id: str, now: float, reason: str, ip: str | None = None) -> str | None:
    """Sahibin aktivliyi: "sağam" düyməsi, giriş, seyfi redaktə, e-poçt linki."""
    v = conn.execute("SELECT * FROM vaults WHERE owner_id=?", (user_id,)).fetchone()
    if v is None:
        return None
    d = switch.on_owner_activity(v["state"])
    conn.execute("UPDATE vaults SET last_activity_at=?, reminders_sent=0, last_reminder_at=NULL WHERE id=?",
                 (now, v["id"]))
    if d.changed(switch_view(v)):
        apply_decision(app, conn, v, d, now, actor=user_id)
    if "release_cancelled" in d.actions:
        audit.record(conn, app.audit_key, ts=now, actor=user_id, action="release.cancelled_by_owner",
                     vault_id=v["id"], ip=ip, reason=reason)
        audit.security_event(conn, ts=now, kind="release_cancelled", actor=user_id, ip=ip, previous=v["state"])
    return d.state


def tick(app: Emanet) -> dict:
    """Planlaşdırıcı: bütün aktiv seyfləri qiymətləndir, məktubları göndər."""
    now = app.clock.now()
    ids = [r["id"] for r in app.db.all("SELECT id FROM vaults WHERE state NOT IN ('setup','released')")]
    counts: dict[str, int] = {}
    for vid in ids:
        st = evaluate_vault(app, vid, now)
        counts[st] = counts.get(st, 0) + 1
    with app.db.tx() as conn:
        # Saxlama siyasəti (isms/policies/data-retention-and-deletion.md)
        for v in conn.execute("SELECT * FROM vaults WHERE state='released' AND released_at < ?",
                              (now - RELEASED_RETENTION_DAYS * switch.DAY,)).fetchall():
            shred_vault(app, conn, v, now, "system", None)
        conn.execute("DELETE FROM outbox WHERE sent_at IS NOT NULL AND sent_at < ?", (now - 90 * switch.DAY,))
        conn.execute("DELETE FROM checkin_tokens WHERE expires_at < ? OR used_at IS NOT NULL AND used_at < ?",
                     (now, now - 30 * switch.DAY))
        import time as _t
        conn.execute("DELETE FROM sessions WHERE created_at < ?", (_t.time() - app.settings.session_absolute_seconds,))
    sent = notify.deliver_pending(app.db, app.notifier, now)
    app.db.set_kv("last_tick_at", str(now))
    return {"evaluated": len(ids), "states": counts, "emails_sent": sent, "at": now}


def release_key_plain(app: Emanet, v) -> bytes:
    return app.kms.decrypt(v["release_key_ct"], release_context(v["id"]))


def vault_status(app: Emanet, conn, v, now: float, *, for_owner: bool) -> dict:
    sv = switch_view(v)
    out = {
        "id": v["id"], "state": v["state"], "threshold": v["threshold"],
        "distribution_version": v["distribution_version"],
        "approvals": approvals_count(conn, v),
        "trustees_accepted": len(accepted_trustees(conn, v["id"])),
        "release_at": v["release_at"], "released_at": v["released_at"],
        "release_in_days": round(max(0.0, (v["release_at"] - now) / switch.DAY), 2) if v["release_at"] else None,
        "waiting_days": v["waiting_days"], "inactivity_days": v["inactivity_days"],
    }
    if for_owner:
        out.update({
            "version": v["version"], "blob_size": v["blob_size"],
            "checkin_interval_days": v["checkin_interval_days"],
            "last_activity_at": v["last_activity_at"], "paused_until": v["paused_until"],
            "days_until_awaiting": round(switch.days_until_awaiting(sv, now), 2),
            "reminders_sent": v["reminders_sent"],
        })
    return out


def shred_vault(app: Emanet, conn, v, now: float, actor: str, ip: str | None) -> None:
    """Crypto-shredding: R (KMS-sarınmış), bütün sarınmış DEK-lər və hissələr məhv edilir.

    S3 Object Lock köhnə şifrəmətn versiyalarını saxlasa da, açarlar olmadan onlar
    riyazi olaraq oxunmazdır — "unudulma hüququ" ilə dəyişməz ehtiyat nüsxə barışır."""
    app.storage.delete_vault(v["id"])
    audit.record(conn, app.audit_key, ts=now, actor=actor, action="vault.shredded", vault_id=v["id"], ip=ip,
                 versions=v["version"])
    conn.execute("DELETE FROM vaults WHERE id=?", (v["id"],))


def json_box(s: str | None):
    return json.loads(s) if s else None
