"""Qeydiyyat, giriş, MFA, parol dəyişikliyi və bərpa kodu ilə bərpa.

Sıfır bilik (zero-knowledge) autentifikasiyası:
  brauzer: master = PBKDF2(parol, salt, 600k) → auth_key = HKDF(master, "auth")
  server : Argon2id(auth_key) saxlayır
Server parolu da, enc_key-i də heç vaxt görmür; auth_key-dən enc_key alınmır.
"""
from __future__ import annotations

import hashlib
import hmac
import json

from flask import Blueprint, g, jsonify, make_response, request

from .. import audit, notify
from ..crypto import passwords, totp
from ..crypto import primitives as P
from ..crypto.primitives import PBKDF2_ITERATIONS
from ..security import (ApiError, client_ip, create_session, ctx, destroy_session, now, public_endpoint,
                        rate_limit, require_auth, revoke_all_sessions)
from ..services import touch_owner
from ..validation import B64U, Digits, Email, Id, SealedBox, Text, parse

bp = Blueprint("auth", __name__, url_prefix="/api")

LOCK_AFTER = 10
LOCK_SECONDS = 15 * 60


def _body() -> dict:
    data = request.get_json(silent=True)
    if data is None:
        raise ApiError(400, "bad_json", "JSON gövdə gözlənilirdi")
    return data


def _profile(u) -> dict:
    return {"id": u["id"], "email": u["email"], "display_name": u["display_name"], "role": u["role"],
            "public_key": u["public_key"], "fingerprint": P.fingerprint(P.b64u_d(u["public_key"])),
            "mfa_enabled": bool(u["totp_enabled"]), "wrapped_privkey": json.loads(u["wrapped_privkey"])}


def _fake_salt(email: str) -> str:
    """Mövcud olmayan e-poçt üçün də sabit 'salt' — hesabın varlığı sızmasın (enumeration)."""
    key = ctx().settings.secret("secret_key")
    return P.b64u(hmac.new(key, b"fake-salt|" + email.encode(), hashlib.sha256).digest()[:16])


@bp.post("/auth/prelogin")
@public_endpoint
def prelogin():
    data = parse(_body(), {"email": Email()})
    rate_limit(f"prelogin:{client_ip()}", 30, 60)
    u = ctx().db.one("SELECT kdf_salt, kdf_iterations FROM users WHERE email=?", (data["email"],))
    if u is None:
        return jsonify({"kdf_salt": _fake_salt(data["email"]), "kdf_iterations": PBKDF2_ITERATIONS})
    return jsonify({"kdf_salt": u["kdf_salt"], "kdf_iterations": u["kdf_iterations"]})


REGISTER_SCHEMA = {
    "user_id": Id("u"), "email": Email(), "display_name": Text(2, 80),
    "kdf_salt": B64U(16), "auth_key": B64U(32), "public_key": B64U(65),
    "wrapped_privkey": SealedBox(), "recovery_auth": B64U(32), "wrapped_privkey_recovery": SealedBox(),
}


@bp.post("/auth/register")
@public_endpoint
def register():
    c = ctx()
    data = parse(_body(), REGISTER_SCHEMA)
    rate_limit(f"register:{client_ip()}", 10, 3600)
    try:
        P.load_public(P.b64u_d(data["public_key"]))   # əyri üzərində olmayan açarı rədd et
    except P.CryptoError:
        raise ApiError(400, "bad_public_key", "açıq açar etibarsızdır")
    t = now()
    role = "operator" if c.settings.bootstrap_operator_email and data["email"] == c.settings.bootstrap_operator_email \
        else "user"
    with c.db.tx() as conn:
        if conn.execute("SELECT 1 FROM users WHERE email=? OR id=?", (data["email"], data["user_id"])).fetchone():
            raise ApiError(409, "exists", "bu e-poçt ilə hesab artıq mövcuddur")
        conn.execute(
            "INSERT INTO users(id, email, display_name, role, kdf_salt, kdf_iterations, auth_hash, public_key, "
            "wrapped_privkey, recovery_auth_hash, wrapped_privkey_recovery, created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
            (data["user_id"], data["email"], data["display_name"], role, data["kdf_salt"], PBKDF2_ITERATIONS,
             passwords.hash_password(data["auth_key"]), data["public_key"], json.dumps(data["wrapped_privkey"]),
             passwords.hash_password(data["recovery_auth"]), json.dumps(data["wrapped_privkey_recovery"]), t))
        # Bu e-poçta əvvəlcədən göndərilmiş dəvətləri yeni hesaba bağla
        conn.execute("UPDATE trustees SET user_id=? WHERE invited_email=? AND user_id IS NULL",
                     (data["user_id"], data["email"]))
        audit.record(conn, c.audit_key, ts=t, actor=data["user_id"], action="user.registered", ip=client_ip(),
                     role=role)
        notify.enqueue(conn, data["email"], "welcome", t, name=data["display_name"])
    return jsonify({"id": data["user_id"], "role": role}), 201


@bp.post("/auth/login")
@public_endpoint
def login():
    c = ctx()
    data = parse(_body(), {"email": Email(), "auth_key": B64U(32), "totp": Digits(6)}, optional={"totp"})
    ip = client_ip()
    rate_limit(f"login-ip:{ip}", 30, 900)
    rate_limit(f"login-email:{data['email']}", 20, 900)
    t = now()
    u = c.db.one("SELECT * FROM users WHERE email=?", (data["email"],))
    if u is None:
        passwords.hash_password("dummy-to-equalize-timing")   # vaxt fərqi ilə hesab aşkarlanmasın
        with c.db.tx() as conn:
            audit.security_event(conn, ts=t, kind="login_failed", ip=ip, reason="unknown")
        raise ApiError(401, "bad_credentials", "e-poçt və ya parol yanlışdır")
    if u["locked_until"] and u["locked_until"] > t:
        raise ApiError(423, "locked", "hesab müvəqqəti bloklanıb", retry_after=int(u["locked_until"] - t))
    if u["status"] != "active":
        raise ApiError(403, "suspended", "hesab dayandırılıb")
    if not passwords.verify_password(data["auth_key"], u["auth_hash"]):
        with c.db.tx() as conn:
            fails = u["failed_logins"] + 1
            locked = t + LOCK_SECONDS if fails >= LOCK_AFTER else None
            conn.execute("UPDATE users SET failed_logins=?, locked_until=? WHERE id=?",
                         (0 if locked else fails, locked, u["id"]))
            audit.security_event(conn, ts=t, kind="login_failed", actor=u["id"], ip=ip, attempt=fails)
            if locked:
                audit.security_event(conn, ts=t, kind="account_locked", actor=u["id"], ip=ip)
                notify.enqueue(conn, u["email"], "account_locked", t)
        raise ApiError(401, "bad_credentials", "e-poçt və ya parol yanlışdır")
    if u["totp_enabled"]:
        if "totp" not in data:
            raise ApiError(401, "mfa_required", "autentifikator kodu lazımdır")
        step = totp.verify(u["totp_secret"], data["totp"], at=t, last_used_step=u["totp_last_step"])
        if step is None:
            with c.db.tx() as conn:
                audit.security_event(conn, ts=t, kind="mfa_failed", actor=u["id"], ip=ip)
            raise ApiError(401, "mfa_invalid", "autentifikator kodu yanlışdır")
        with c.db.tx() as conn:
            conn.execute("UPDATE users SET totp_last_step=? WHERE id=?", (step, u["id"]))
    resp = make_response()
    with c.db.tx() as conn:
        conn.execute("UPDATE users SET failed_logins=0, locked_until=NULL WHERE id=?", (u["id"],))
        if passwords.needs_rehash(u["auth_hash"]):
            conn.execute("UPDATE users SET auth_hash=? WHERE id=?", (passwords.hash_password(data["auth_key"]), u["id"]))
        audit.record(conn, c.audit_key, ts=t, actor=u["id"], action="user.login", ip=ip, mfa=bool(u["totp_enabled"]))
        touch_owner(c, conn, u["id"], t, "login", ip)
    csrf = create_session(resp, u["id"])
    resp.set_data(json.dumps({"user": _profile(u), "csrf": csrf}))
    resp.mimetype = "application/json"
    return resp


@bp.post("/auth/logout")
@require_auth()
def logout():
    resp = jsonify({"ok": True})
    destroy_session(resp)
    return resp


@bp.get("/session")
def session_probe():
    """Brauzer açılanda "sessiya varmı?" sualı — həmişə 200 (konsolda 401 səs-küyü olmasın)."""
    from ..security import load_session
    s = load_session()
    return jsonify({"authenticated": s is not None})


@bp.get("/me")
@require_auth()
def me():
    c = ctx()
    u = c.db.one("SELECT * FROM users WHERE id=?", (g.user_id,))
    v = c.db.one("SELECT id FROM vaults WHERE owner_id=?", (g.user_id,))
    return jsonify({"user": _profile(u), "csrf": g.session["csrf"], "vault_id": v["id"] if v else None,
                    "demo_mode": c.settings.demo_mode})


@bp.post("/auth/password")
@require_auth()
def change_password():
    c = ctx()
    data = parse(_body(), {"current_auth_key": B64U(32), "kdf_salt": B64U(16), "auth_key": B64U(32),
                           "wrapped_privkey": SealedBox(), "wrapped_dek_owner": SealedBox()},
                 optional={"wrapped_dek_owner"})
    rate_limit(f"pwchange:{g.user_id}", 5, 3600, actor=g.user_id)
    u = c.db.one("SELECT * FROM users WHERE id=?", (g.user_id,))
    if not passwords.verify_password(data["current_auth_key"], u["auth_hash"]):
        raise ApiError(403, "bad_credentials", "cari parol yanlışdır")
    t = now()
    resp = jsonify({"ok": True})
    with c.db.tx() as conn:
        conn.execute("UPDATE users SET kdf_salt=?, auth_hash=?, wrapped_privkey=? WHERE id=?",
                     (data["kdf_salt"], passwords.hash_password(data["auth_key"]), json.dumps(data["wrapped_privkey"]),
                      g.user_id))
        if "wrapped_dek_owner" in data:
            conn.execute("UPDATE vaults SET wrapped_dek_owner=? WHERE owner_id=?",
                         (json.dumps(data["wrapped_dek_owner"]), g.user_id))
        revoke_all_sessions(conn, g.user_id)   # bütün digər cihazlardan çıxış
        audit.record(conn, c.audit_key, ts=t, actor=g.user_id, action="user.password_changed", ip=client_ip())
    create_session(resp, g.user_id)
    return resp


# ------------------------------------------------------------------ bərpa kodu
def _recovery_user(data):
    c = ctx()
    rate_limit(f"recover:{data['email']}", 5, 3600)
    rate_limit(f"recover-ip:{client_ip()}", 20, 3600)
    u = c.db.one("SELECT * FROM users WHERE email=?", (data["email"],))
    if u is None or not passwords.verify_password(data["recovery_auth"], u["recovery_auth_hash"]):
        with c.db.tx() as conn:
            audit.security_event(conn, ts=now(), kind="recovery_failed", actor=u["id"] if u else None, ip=client_ip())
        raise ApiError(401, "bad_recovery", "e-poçt və ya bərpa kodu yanlışdır")
    return u


@bp.post("/auth/recover/begin")
@public_endpoint
def recover_begin():
    c = ctx()
    data = parse(_body(), {"email": Email(), "recovery_auth": B64U(32)})
    u = _recovery_user(data)
    v = c.db.one("SELECT id, wrapped_dek_recovery FROM vaults WHERE owner_id=?", (u["id"],))
    return jsonify({"user_id": u["id"], "wrapped_privkey_recovery": json.loads(u["wrapped_privkey_recovery"]),
                    "vault_id": v["id"] if v else None,
                    "wrapped_dek_recovery": json.loads(v["wrapped_dek_recovery"]) if v else None})


@bp.post("/auth/recover/complete")
@public_endpoint
def recover_complete():
    c = ctx()
    data = parse(_body(), {
        "email": Email(), "recovery_auth": B64U(32), "kdf_salt": B64U(16), "auth_key": B64U(32),
        "wrapped_privkey": SealedBox(), "new_recovery_auth": B64U(32), "new_wrapped_privkey_recovery": SealedBox(),
        "wrapped_dek_owner": SealedBox(), "wrapped_dek_recovery": SealedBox()},
        optional={"wrapped_dek_owner", "wrapped_dek_recovery"})
    u = _recovery_user(data)
    t = now()
    with c.db.tx() as conn:
        conn.execute("UPDATE users SET kdf_salt=?, auth_hash=?, wrapped_privkey=?, recovery_auth_hash=?, "
                     "wrapped_privkey_recovery=?, failed_logins=0, locked_until=NULL, totp_enabled=0, totp_secret=NULL "
                     "WHERE id=?",
                     (data["kdf_salt"], passwords.hash_password(data["auth_key"]), json.dumps(data["wrapped_privkey"]),
                      passwords.hash_password(data["new_recovery_auth"]), json.dumps(data["new_wrapped_privkey_recovery"]),
                      u["id"]))
        if "wrapped_dek_owner" in data and "wrapped_dek_recovery" in data:
            conn.execute("UPDATE vaults SET wrapped_dek_owner=?, wrapped_dek_recovery=? WHERE owner_id=?",
                         (json.dumps(data["wrapped_dek_owner"]), json.dumps(data["wrapped_dek_recovery"]), u["id"]))
        revoke_all_sessions(conn, u["id"])
        audit.record(conn, c.audit_key, ts=t, actor=u["id"], action="user.recovered", ip=client_ip())
        audit.security_event(conn, ts=t, kind="account_recovered", actor=u["id"], ip=client_ip())
        notify.enqueue(conn, u["email"], "recovered", t)
    return jsonify({"ok": True})


# ------------------------------------------------------------------ MFA (TOTP, RFC 6238)
@bp.post("/mfa/setup")
@require_auth()
def mfa_setup():
    c = ctx()
    u = c.db.one("SELECT email, totp_enabled FROM users WHERE id=?", (g.user_id,))
    if u["totp_enabled"]:
        raise ApiError(409, "mfa_enabled", "MFA artıq aktivdir")
    secret = totp.generate_secret()
    with c.db.tx() as conn:
        conn.execute("UPDATE users SET totp_secret=? WHERE id=?", (secret, g.user_id))
    return jsonify({"secret": secret, "uri": totp.provisioning_uri(secret, u["email"], "Emanet")})


@bp.post("/mfa/enable")
@require_auth()
def mfa_enable():
    c = ctx()
    data = parse(_body(), {"code": Digits(6)})
    rate_limit(f"mfa:{g.user_id}", 10, 900, actor=g.user_id)
    u = c.db.one("SELECT totp_secret FROM users WHERE id=?", (g.user_id,))
    if not u["totp_secret"]:
        raise ApiError(409, "no_setup", "əvvəlcə /mfa/setup çağırın")
    step = totp.verify(u["totp_secret"], data["code"], at=now())
    if step is None:
        raise ApiError(400, "mfa_invalid", "kod yanlışdır")
    with c.db.tx() as conn:
        conn.execute("UPDATE users SET totp_enabled=1, totp_last_step=? WHERE id=?", (step, g.user_id))
        audit.record(conn, c.audit_key, ts=now(), actor=g.user_id, action="user.mfa_enabled", ip=client_ip())
    return jsonify({"ok": True})
