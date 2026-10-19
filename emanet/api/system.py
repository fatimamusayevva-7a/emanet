"""Sistem, operator, auditor və planlaşdırıcı endpoint-ləri.

Vəzifələrin bölünməsi (ISO 27001 A.5.3):
  * operator — istifadəçi metadata-sı, dayandırma, rol; audit jurnalını OXUYA BİLMİR,
    seyfi aça və ya açılmanı məcbur edə BİLMİR (belə endpoint ümumiyyətlə yoxdur).
  * auditor  — audit jurnalını və zəncirin bütövlüyünü yoxlayır; istifadəçiləri idarə edə bilmir.
"""
from __future__ import annotations

import hashlib
import json
import pathlib

from flask import Blueprint, g, jsonify, request

from .. import audit
from ..clock import DAY, OffsetClock
from ..security import (ApiError, client_ip, ctx, deferred_event, now, rate_limit, require_auth, revoke_all_sessions,
                        verify_scheduler_signature)
from ..services import tick
from ..validation import Int, Text, parse

bp = Blueprint("system", __name__)
WEB_ROOT = pathlib.Path(__file__).resolve().parents[2] / "web"


@bp.get("/api/health")
def health():
    c = ctx()
    c.db.one("SELECT 1")
    last = c.db.get_kv("last_tick_at")
    return jsonify({"status": "ok", "kms": c.kms.name, "storage": c.storage.name,
                    "last_tick_age_s": round(now() - float(last)) if last else None})


@bp.get("/api/integrity")
def integrity():
    """Brauzer kodunun SHA-256 manifesti — "server zərərli JS göndərsə?" riskinə qarşı şəffaflıq.

    Eyni manifest GitHub buraxılışında (release) dərc olunur; istifadəçi/auditor
    `scripts/verify_client.py` ilə canlı saytdakı faylları müqayisə edə bilər."""
    files = {}
    for p in sorted(WEB_ROOT.rglob("*")):
        if p.is_file() and p.suffix in {".js", ".html", ".css"}:
            files[p.relative_to(WEB_ROOT).as_posix()] = hashlib.sha256(p.read_bytes()).hexdigest()
    digest = hashlib.sha256(json.dumps(files, sort_keys=True).encode()).hexdigest()
    return jsonify({"files": files, "manifest_sha256": digest})


@bp.post("/internal/tick")
def scheduler_tick():
    c = ctx()
    ok = verify_scheduler_signature(c.settings.secret("scheduler_hmac_key"), "POST", "/internal/tick",
                                    request.headers.get("X-Emanet-Timestamp", ""),
                                    request.headers.get("X-Emanet-Signature", ""), now(), request.get_data())
    if not ok:
        with c.db.tx() as conn:
            audit.security_event(conn, ts=now(), kind="scheduler_bad_signature", ip=client_ip())
        raise ApiError(401, "bad_signature", "imza yanlışdır")
    sig = request.headers["X-Emanet-Signature"]
    with c.db.tx() as conn:   # təkrar (replay) qorunması
        if conn.execute("SELECT 1 FROM rate_hits WHERE bucket=?", (f"tick-sig:{sig}",)).fetchone():
            replay = True
        else:
            replay = False
            conn.execute("INSERT INTO rate_hits(bucket, ts) VALUES(?,?)", (f"tick-sig:{sig}", now()))
    if replay:
        deferred_event("scheduler_replay")
        raise ApiError(409, "replay", "bu imza artıq istifadə olunub")
    return jsonify(tick(c))


# ------------------------------------------------------------------ operator
@bp.get("/api/admin/users")
@require_auth("operator")
def admin_users():
    rows = ctx().db.all("SELECT u.id, u.email, u.display_name, u.role, u.status, u.totp_enabled, u.created_at, "
                        "v.state AS vault_state FROM users u LEFT JOIN vaults v ON v.owner_id=u.id ORDER BY u.created_at")
    return jsonify({"users": [dict(r) for r in rows]})


@bp.post("/api/admin/users/<uid>/role")
@require_auth("operator")
def admin_role(uid):
    c = ctx()
    data = parse(request.get_json(silent=True), {"role": Text(4, 10)})
    if data["role"] not in ("user", "operator", "auditor"):
        raise ApiError(400, "bad_role", "yanlış rol")
    if uid == g.user_id:
        raise ApiError(409, "self_role", "öz rolunuzu dəyişə bilməzsiniz (vəzifələrin bölünməsi)")
    with c.db.tx() as conn:
        u = conn.execute("SELECT role FROM users WHERE id=?", (uid,)).fetchone()
        if u is None:
            raise ApiError(404, "not_found", "tapılmadı")
        if u["role"] == "operator" and data["role"] != "operator":
            n = conn.execute("SELECT COUNT(*) FROM users WHERE role='operator' AND status='active'").fetchone()[0]
            if n <= 1:
                raise ApiError(409, "last_operator", "sonuncu operatoru silmək olmaz")
        conn.execute("UPDATE users SET role=? WHERE id=?", (data["role"], uid))
        revoke_all_sessions(conn, uid)
        audit.record(conn, c.audit_key, ts=now(), actor=g.user_id, action="admin.role_changed", target=uid,
                     ip=client_ip(), old=u["role"], new=data["role"])
    return jsonify({"ok": True})


@bp.post("/api/admin/users/<uid>/status")
@require_auth("operator")
def admin_status(uid):
    c = ctx()
    data = parse(request.get_json(silent=True), {"status": Text(6, 9)})
    if data["status"] not in ("active", "suspended"):
        raise ApiError(400, "bad_status", "yanlış status")
    if uid == g.user_id:
        raise ApiError(409, "self", "özünüzü dayandıra bilməzsiniz")
    with c.db.tx() as conn:
        if conn.execute("UPDATE users SET status=? WHERE id=?", (data["status"], uid)).rowcount == 0:
            raise ApiError(404, "not_found", "tapılmadı")
        revoke_all_sessions(conn, uid)
        if data["status"] == "active":
            # Dondurma bitdi: dayandırıldığı müddət sahibin hərəkətsizliyi sayılmır
            conn.execute("UPDATE vaults SET last_activity_at=MAX(last_activity_at, ?) WHERE owner_id=?", (now(), uid))
        audit.record(conn, c.audit_key, ts=now(), actor=g.user_id, action="admin.status_changed", target=uid,
                     ip=client_ip(), new=data["status"])
    return jsonify({"ok": True})


@bp.get("/api/admin/security-events")
@require_auth("operator", "auditor")
def security_events():
    rows = ctx().db.all("SELECT ts, kind, actor, ip, details FROM security_events ORDER BY id DESC LIMIT 200")
    return jsonify({"events": [{**dict(r), "details": json.loads(r["details"])} for r in rows]})


# ------------------------------------------------------------------ auditor
@bp.get("/api/audit")
@require_auth("auditor")
def audit_log():
    rows = ctx().db.all("SELECT id, ts, actor, action, vault_id, target, ip, details, entry_hash FROM audit "
                        "ORDER BY id DESC LIMIT 500")
    return jsonify({"entries": [{**dict(r), "details": json.loads(r["details"])} for r in rows]})


@bp.get("/api/audit/verify")
@require_auth("auditor")
def audit_verify():
    c = ctx()
    return jsonify(audit.verify(c.db, c.audit_key))


# ------------------------------------------------------------------ demo (yalnız EMANET_DEMO_MODE=1)
@bp.post("/api/demo/advance")
@require_auth("operator")
def demo_advance():
    c = ctx()
    if not c.settings.demo_mode or not isinstance(c.clock, OffsetClock):
        raise ApiError(404, "not_found", "tapılmadı")
    data = parse(request.get_json(silent=True), {"days": Int(1, 120)})
    rate_limit(f"demo:{g.user_id}", 60, 3600, actor=g.user_id)
    c.clock.advance(data["days"] * DAY)
    with c.db.tx() as conn:
        audit.record(conn, c.audit_key, ts=now(), actor=g.user_id, action="demo.clock_advanced", ip=client_ip(),
                     days=data["days"])
    return jsonify({"advanced_days": data["days"], "tick": tick(c), "offset_days": round(c.clock.offset() / DAY, 2)})


@bp.get("/api/demo/outbox")
@require_auth()
def demo_outbox():
    """Demo: istifadəçi öz "poçt qutusunu" UI-da görür (real e-poçt əvəzinə)."""
    c = ctx()
    if not c.settings.demo_mode:
        raise ApiError(404, "not_found", "tapılmadı")
    me = c.db.one("SELECT email FROM users WHERE id=?", (g.user_id,))
    rows = c.db.all("SELECT kind, subject, body, created_at FROM outbox WHERE to_email=? ORDER BY id DESC LIMIT 50",
                    (me["email"],))
    return jsonify({"messages": [dict(r) for r in rows]})



