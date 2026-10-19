"""Sahibin seyf API-si: yaratma, məzmun, parametrlər, "sağam", etibarlı şəxslər, paylanma, silmə.

BOLA qorunması: hər sorğuda seyf `owner_id = sessiyanın istifadəçisi` şərti ilə
seçilir; URL-də seyf id-si heç vaxt qəbul edilmir — başqasının seyfinə müraciət
etmək üçün "id dəyişmək" imkanı ümumiyyətlə yoxdur.
"""
from __future__ import annotations

import json

from flask import Blueprint, g, jsonify, request

from .. import audit, notify, switch
from ..crypto import primitives as P
from ..kms import release_context
from ..security import (ApiError, client_ip, ctx, deferred_event, now, public_endpoint, rate_limit, require_auth,
                        sha256_hex)
from ..services import (accepted_trustees, evaluate_vault, new_id, release_key_plain, shred_vault, touch_owner,
                        vault_status)
from ..storage import object_key
from ..validation import B64U, EciesBox, Email, Hex64, Id, Int, ListOf, Obj, SealedBox, Text, parse

bp = Blueprint("vault", __name__, url_prefix="/api")


def _body() -> dict:
    data = request.get_json(silent=True)
    if data is None:
        raise ApiError(400, "bad_json", "JSON gövdə gözlənilirdi")
    return data


def _my_vault(conn=None, required: bool = True):
    db = ctx().db
    q = "SELECT * FROM vaults WHERE owner_id=?"
    v = (conn.execute(q, (g.user_id,)).fetchone() if conn else db.one(q, (g.user_id,)))
    if v is None and required:
        raise ApiError(404, "no_vault", "seyf hələ yaradılmayıb")
    return v


def _audit(conn, action: str, v=None, **details):
    audit.record(conn, ctx().audit_key, ts=now(), actor=g.user_id, action=action,
                 vault_id=v["id"] if v is not None else None, ip=client_ip(), **details)


@bp.post("/vault")
@require_auth()
def create_vault():
    c = ctx()
    data = parse(_body(), {"vault_id": Id("v"), "wrapped_dek_owner": SealedBox(), "wrapped_dek_recovery": SealedBox()})
    t = now()
    with c.db.tx() as conn:
        if _my_vault(conn, required=False):
            raise ApiError(409, "exists", "sizin artıq seyfiniz var")
        R, R_ct = c.kms.generate_key(release_context(data["vault_id"]))
        conn.execute("INSERT INTO vaults(id, owner_id, wrapped_dek_owner, wrapped_dek_recovery, release_key_ct, "
                     "last_activity_at, created_at, updated_at) VALUES(?,?,?,?,?,?,?,?)",
                     (data["vault_id"], g.user_id, json.dumps(data["wrapped_dek_owner"]),
                      json.dumps(data["wrapped_dek_recovery"]), R_ct, t, t, t))
        v = _my_vault(conn)
        _audit(conn, "vault.created", v, kms=c.kms.name)
    return jsonify({"vault_id": data["vault_id"], "release_key": P.b64u(R)}), 201


@bp.get("/vault")
@require_auth()
def get_vault():
    c = ctx()
    v = _my_vault()
    evaluate_vault(c, v["id"])
    with c.db.tx() as conn:
        v = _my_vault(conn)
        st = vault_status(c, conn, v, now(), for_owner=True)
        trustees = conn.execute(
            "SELECT t.id, t.invited_email, t.status, t.fingerprint_verified, t.x, t.user_id, "
            "u.display_name, u.public_key FROM trustees t LEFT JOIN users u ON u.id=t.user_id "
            "WHERE t.vault_id=? ORDER BY t.created_at", (v["id"],)).fetchall()
        approved = {r["trustee_user_id"] for r in conn.execute(
            "SELECT trustee_user_id FROM approvals WHERE vault_id=? AND distribution_version=?",
            (v["id"], v["distribution_version"]))}
    return jsonify({
        "status": st,
        "wrapped_dek_owner": json.loads(v["wrapped_dek_owner"]),
        "has_distribution": v["wrapped_dek_release"] is not None,
        "trustees": [{
            "id": t["id"], "email": t["invited_email"], "status": t["status"], "display_name": t["display_name"],
            "public_key": t["public_key"] if t["status"] == "accepted" else None,
            "fingerprint": P.fingerprint(P.b64u_d(t["public_key"])) if t["status"] == "accepted" else None,
            "fingerprint_verified": bool(t["fingerprint_verified"]), "has_share": t["x"] is not None,
            "user_id": t["user_id"] if t["status"] == "accepted" else None,
            "approved": t["user_id"] in approved,
        } for t in trustees],
    })


@bp.get("/vault/content")
@require_auth()
def get_content():
    c = ctx()
    v = _my_vault()
    if v["version"] == 0:
        return jsonify({"version": 0, "box": None})
    return jsonify({"version": v["version"], "box": c.storage.get(v["blob_key"])})


@bp.put("/vault/content")
@require_auth()
def put_content():
    c = ctx()
    data = parse(_body(), {"version": Int(1, 10**9), "box": SealedBox(max_ct_bytes=c.settings.max_vault_bytes)})
    rate_limit(f"content:{g.user_id}", 120, 3600, actor=g.user_id)
    t = now()
    with c.db.tx() as conn:
        v = _my_vault(conn)
        if v["state"] == "released":
            raise ApiError(409, "released", "açılmış seyf dəyişdirilə bilməz")
        if data["version"] != v["version"] + 1:     # optimistik paralellik nəzarəti
            raise ApiError(409, "version_conflict", "seyf başqa cihazda dəyişib — yeniləyin", current=v["version"])
        key = object_key(v["id"], data["version"])
        c.storage.put(key, data["box"])
        size = len(data["box"]["ct"]) * 3 // 4
        conn.execute("UPDATE vaults SET version=?, blob_key=?, blob_size=?, updated_at=? WHERE id=?",
                     (data["version"], key, size, t, v["id"]))
        _audit(conn, "vault.content_saved", v, version=data["version"], padded_bytes=size)
        touch_owner(c, conn, g.user_id, t, "content", client_ip())
    return jsonify({"version": data["version"]})


@bp.patch("/vault/settings")
@require_auth()
def update_settings():
    c = ctx()
    data = parse(_body(), {"checkin_interval_days": Int(1, 1000), "inactivity_days": Int(1, 1000),
                           "waiting_days": Int(1, 1000)})
    problems = switch.validate_settings(data["checkin_interval_days"], data["inactivity_days"], data["waiting_days"])
    if problems:
        raise ApiError(400, "invalid_settings", "; ".join(problems))
    with c.db.tx() as conn:
        v = _my_vault(conn)
        if v["state"] in ("pending_release", "released"):
            raise ApiError(409, "locked_state", "bu vəziyyətdə parametrlər dəyişdirilə bilməz")
        conn.execute("UPDATE vaults SET checkin_interval_days=?, inactivity_days=?, waiting_days=?, updated_at=? "
                     "WHERE id=?", (data["checkin_interval_days"], data["inactivity_days"], data["waiting_days"],
                                    now(), v["id"]))
        _audit(conn, "vault.settings_changed", v, **data)
        touch_owner(c, conn, g.user_id, now(), "settings", client_ip())
    return jsonify({"ok": True})


@bp.post("/vault/checkin")
@require_auth()
def checkin():
    c = ctx()
    t = now()
    with c.db.tx() as conn:
        v = _my_vault(conn)
        state = touch_owner(c, conn, g.user_id, t, "checkin", client_ip())
        _audit(conn, "vault.checkin", v, previous=v["state"])
    return jsonify({"state": state, "at": t})


@bp.post("/checkin-link")
@public_endpoint
def checkin_link():
    """E-poçtdakı bir kliklik "sağam" linki (giriş tələb etmir, birdəfəlikdir)."""
    c = ctx()
    data = parse(_body(), {"token": B64U(32)})
    rate_limit(f"checkin-link:{client_ip()}", 20, 3600)
    t = now()
    with c.db.tx() as conn:
        row = conn.execute("SELECT * FROM checkin_tokens WHERE token_hash=?", (sha256_hex(data["token"]),)).fetchone()
        if row is None or row["used_at"] is not None or row["expires_at"] < t:
            deferred_event("checkin_link_invalid")
            raise ApiError(400, "invalid_link", "link etibarsızdır və ya istifadə olunub")
        conn.execute("UPDATE checkin_tokens SET used_at=? WHERE token_hash=?", (t, row["token_hash"]))
        state = touch_owner(c, conn, row["user_id"], t, "email_link", client_ip())
        audit.record(conn, c.audit_key, ts=t, actor=row["user_id"], action="vault.checkin_link", ip=client_ip())
    return jsonify({"ok": True, "state": state})


@bp.post("/vault/pause")
@require_auth()
def pause():
    c = ctx()
    data = parse(_body(), {"days": Int(0, 90)})
    t = now()
    with c.db.tx() as conn:
        v = _my_vault(conn)
        until = t + data["days"] * switch.DAY if data["days"] else None
        conn.execute("UPDATE vaults SET paused_until=? WHERE id=?", (until, v["id"]))
        touch_owner(c, conn, g.user_id, t, "pause", client_ip())
        _audit(conn, "vault.paused" if until else "vault.unpaused", v, days=data["days"])
    return jsonify({"paused_until": until})


@bp.get("/vault/release-key")
@require_auth()
def get_release_key():
    """Sahib paylanmanı yenidən qurmaq üçün R-i alır (sahib R-i bilməyə haqlıdır)."""
    c = ctx()
    v = _my_vault()
    if v["state"] == "released":
        raise ApiError(409, "released", "seyf artıq açılıb")
    R = release_key_plain(c, v)
    with c.db.tx() as conn:
        _audit(conn, "vault.release_key_read_by_owner", v)
    return jsonify({"release_key": P.b64u(R)})


# ------------------------------------------------------------------ etibarlı şəxslər
@bp.post("/vault/trustees")
@require_auth()
def invite_trustee():
    c = ctx()
    data = parse(_body(), {"email": Email()})
    rate_limit(f"invite:{g.user_id}", 20, 86400, actor=g.user_id)
    t = now()
    with c.db.tx() as conn:
        v = _my_vault(conn)
        me = conn.execute("SELECT email, display_name FROM users WHERE id=?", (g.user_id,)).fetchone()
        if data["email"] == me["email"]:
            raise ApiError(400, "self", "özünüzü etibarlı şəxs təyin edə bilməzsiniz")
        n = conn.execute("SELECT COUNT(*) FROM trustees WHERE vault_id=? AND status!='declined'", (v["id"],)).fetchone()[0]
        if n >= 7:
            raise ApiError(400, "too_many", "ən çox 7 etibarlı şəxs")
        if conn.execute("SELECT 1 FROM trustees WHERE vault_id=? AND invited_email=?", (v["id"], data["email"])).fetchone():
            raise ApiError(409, "exists", "bu şəxs artıq dəvət olunub")
        u = conn.execute("SELECT id FROM users WHERE email=?", (data["email"],)).fetchone()
        tid = new_id("t")
        conn.execute("INSERT INTO trustees(id, vault_id, user_id, invited_email, created_at) VALUES(?,?,?,?,?)",
                     (tid, v["id"], u["id"] if u else None, data["email"], t))
        notify.enqueue(conn, data["email"], "trustee_invited", t, owner=me["display_name"],
                       origin=c.settings.public_origin)
        _audit(conn, "trustee.invited", v, target_trustee=tid)
    return jsonify({"id": tid}), 201


@bp.delete("/vault/trustees/<tid>")
@require_auth()
def remove_trustee(tid):
    c = ctx()
    with c.db.tx() as conn:
        v = _my_vault(conn)
        if v["state"] in ("pending_release", "released"):
            raise ApiError(409, "locked_state", "bu vəziyyətdə etibarlı şəxs silinə bilməz")
        row = conn.execute("SELECT * FROM trustees WHERE id=? AND vault_id=?", (tid, v["id"])).fetchone()
        if row is None:
            raise ApiError(404, "not_found", "tapılmadı")
        conn.execute("DELETE FROM trustees WHERE id=?", (tid,))
        if row["x"] is not None:
            # Hissəsi olan şəxs silindi → köhnə paylanma etibarsızdır, yenidən paylanma tələb olunur.
            # Diqqət: silinən şəxs öz hissəsini əvvəlcədən saxlaya bilərdi — buna görə S yenilənməlidir.
            conn.execute("UPDATE trustees SET x=NULL, share_box=NULL, commitment=NULL WHERE vault_id=?", (v["id"],))
            conn.execute("UPDATE vaults SET wrapped_dek_release=NULL, threshold=NULL, state='setup' WHERE id=?",
                         (v["id"],))
            conn.execute("DELETE FROM approvals WHERE vault_id=?", (v["id"],))
        _audit(conn, "trustee.removed", v, target_trustee=tid, had_share=row["x"] is not None)
    return jsonify({"ok": True, "redistribution_required": row["x"] is not None})


@bp.post("/vault/trustees/<tid>/verify")
@require_auth()
def verify_trustee(tid):
    """Sahib barmaq izini etibarlı şəxslə ayrıca kanalda (telefon/üz-üzə) müqayisə etdi."""
    c = ctx()
    fp = parse(_body(), {"fingerprint": Text(39, 39)})["fingerprint"].upper()
    with c.db.tx() as conn:
        v = _my_vault(conn)
        row = conn.execute("SELECT t.*, u.public_key FROM trustees t JOIN users u ON u.id=t.user_id "
                           "WHERE t.id=? AND t.vault_id=? AND t.status='accepted'", (tid, v["id"])).fetchone()
        if row is None:
            raise ApiError(404, "not_found", "qəbul edilmiş etibarlı şəxs tapılmadı")
        if not P.constant_eq(fp, P.fingerprint(P.b64u_d(row["public_key"]))):
            deferred_event("fingerprint_mismatch", actor=g.user_id)
            raise ApiError(400, "fingerprint_mismatch", "barmaq izi uyğun gəlmir")
        conn.execute("UPDATE trustees SET fingerprint_verified=1 WHERE id=?", (tid,))
        _audit(conn, "trustee.fingerprint_verified", v, target_trustee=tid)
    return jsonify({"ok": True})


SHARE_ITEM = Obj({"trustee_id": Id("t"), "x": Int(1, 255), "commitment": Hex64(), "box": EciesBox()})


@bp.post("/vault/distribution")
@require_auth()
def distribute():
    """Brauzerdə hazırlanmış paylanmanı qəbul et: şifrəli hissələr + KEK(S‖R) ilə sarınmış DEK."""
    c = ctx()
    data = parse(_body(), {"threshold": Int(2, 7), "wrapped_dek_release": SealedBox(),
                           "shares": ListOf(SHARE_ITEM, 2, 7)})
    t = now()
    with c.db.tx() as conn:
        v = _my_vault(conn)
        if v["state"] in ("pending_release", "released"):
            raise ApiError(409, "locked_state", "bu vəziyyətdə paylanma dəyişdirilə bilməz")
        if v["version"] == 0:
            raise ApiError(409, "empty_vault", "əvvəlcə seyfə məzmun əlavə edin")
        trustees = {r["id"]: r for r in accepted_trustees(conn, v["id"])}
        given = [s["trustee_id"] for s in data["shares"]]
        if sorted(given) != sorted(trustees):
            raise ApiError(400, "trustee_mismatch", "paylanma bütün qəbul etmiş etibarlı şəxsləri əhatə etməlidir")
        if len(set(s["x"] for s in data["shares"])) != len(given):
            raise ApiError(400, "dup_x", "hissə nömrələri təkrarlanır")
        if data["threshold"] > len(given):
            raise ApiError(400, "threshold", "hədd etibarlı şəxslərin sayından böyük ola bilməz")
        unverified = [tid for tid, r in trustees.items() if not r["fingerprint_verified"]]
        if unverified:
            raise ApiError(409, "unverified", "bütün etibarlı şəxslərin barmaq izi təsdiqlənməlidir", trustees=unverified)
        for s in data["shares"]:
            conn.execute("UPDATE trustees SET x=?, share_box=?, commitment=? WHERE id=?",
                         (s["x"], json.dumps(s["box"]), s["commitment"], s["trustee_id"]))
        conn.execute("UPDATE vaults SET wrapped_dek_release=?, threshold=?, distribution_version=distribution_version+1, "
                     "state='active', release_at=NULL, updated_at=? WHERE id=?",
                     (json.dumps(data["wrapped_dek_release"]), data["threshold"], t, v["id"]))
        conn.execute("DELETE FROM approvals WHERE vault_id=?", (v["id"],))
        conn.execute("DELETE FROM handoffs WHERE vault_id=?", (v["id"],))
        _audit(conn, "vault.distributed", v, threshold=data["threshold"], n=len(given))
        touch_owner(c, conn, g.user_id, t, "distribution", client_ip())
    return jsonify({"ok": True, "threshold": data["threshold"], "n": len(given)})


@bp.get("/vault/activity")
@require_auth()
def activity():
    """Şəffaflıq: sahib öz seyfi ilə bağlı HƏR hadisəni görür (kim, nə vaxt)."""
    c = ctx()
    v = _my_vault()
    rows = c.db.all("SELECT a.ts, a.action, a.actor, a.details, u.display_name FROM audit a "
                    "LEFT JOIN users u ON u.id=a.actor WHERE a.vault_id=? ORDER BY a.id DESC LIMIT 200", (v["id"],))
    return jsonify({"events": [{"ts": r["ts"], "action": r["action"],
                                "actor": r["display_name"] or r["actor"], "details": json.loads(r["details"])}
                               for r in rows]})


@bp.delete("/vault")
@require_auth()
def delete_vault():
    c = ctx()
    body = request.get_json(silent=True) or {}
    if body.get("confirm") != "SİL":
        raise ApiError(400, "confirm", "təsdiq üçün {\"confirm\": \"SİL\"} göndərin")
    with c.db.tx() as conn:
        v = _my_vault(conn)
        shred_vault(c, conn, v, now(), g.user_id, client_ip())
    return jsonify({"ok": True, "shredded": True})

