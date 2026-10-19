"""Veb təhlükəsizlik qatı: sessiyalar, CSRF, sürət məhdudiyyəti, başlıqlar, rollar.

Sessiya
  * 256-bit təsadüfi token, yalnız HttpOnly + Secure + SameSite=Strict cookie-də
    (`__Host-` prefiksi ilə — alt domen cookie-ni əvəz edə bilməz).
  * DB-də token deyil, SHA-256(token) saxlanılır — DB sızsa, sessiyalar oğurlanmır.
  * 30 dəq. hərəkətsizlik və 12 saat mütləq limit.
CSRF — iki müstəqil qat
  * hər dəyişiklik edən sorğuda Origin/Referer icazə siyahısı ilə yoxlanılır;
  * X-CSRF-Token başlığı sessiyanın CSRF dəyəri ilə sabit zamanda müqayisə olunur.
Sürət məhdudiyyəti — DB əsaslı sürüşən pəncərə (proses yenidən başlasa da qalır).
"""
from __future__ import annotations

import functools
import hashlib
import hmac
import secrets
import time
from urllib.parse import urlsplit

from flask import current_app, g, jsonify, request

from . import audit

SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}

CSP = ("default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
       "connect-src 'self'; font-src 'self'; manifest-src 'self'; frame-ancestors 'none'; "
       "base-uri 'none'; form-action 'self'; object-src 'none'; "
       "require-trusted-types-for 'script'; trusted-types 'none'")


class ApiError(Exception):
    def __init__(self, status: int, code: str, message: str, **extra):
        super().__init__(message)
        self.status, self.code, self.message, self.extra = status, code, message, extra


def defer(fn) -> None:
    """Xəta ilə bitən sorğuda da QALMALI olan yazılar (təhlükəsizlik hadisəsi, sahibə xəbərdarlıq).

    ApiError tranzaksiyanı ROLLBACK edir; ona görə belə qeydlər sorğunun sonunda
    ayrıca tranzaksiyada yazılır (app.teardown_request → flush_deferred)."""
    g.setdefault("_deferred", []).append(fn)


def flush_deferred() -> None:
    items = g.pop("_deferred", [])
    if items:
        with ctx().db.tx() as conn:
            for fn in items:
                fn(conn)


def deferred_event(kind: str, actor: str | None = None, **details) -> None:
    ts, ip = now(), client_ip()
    defer(lambda conn: audit.security_event(conn, ts=ts, kind=kind, actor=actor, ip=ip, **details))


def ctx():
    return current_app.extensions["emanet"]


def now() -> float:
    """Biznes saatı ("sağam" vəziyyət maşını, audit). Demo rejimində sürüşdürülə bilər."""
    return ctx().clock.now()


def wall_now() -> float:
    """Real divar saatı — sessiyalar və sürət limitləri üçün. Demo saatı bunlara təsir etmir,
    yəni "60 gün irəli" düyməsi sessiyaların ömrünü uzatmır və limitləri sıfırlamır."""
    return time.time()


def client_ip() -> str:
    if ctx().settings.trust_proxy:
        fwd = request.headers.get("X-Forwarded-For", "")
        if fwd:
            return fwd.split(",")[-1].strip()[:64]   # Caddy-nin əlavə etdiyi SON ünvan
    return (request.remote_addr or "?")[:64]


def sha256_hex(s: str) -> str:
    return hashlib.sha256(s.encode()).hexdigest()


# ------------------------------------------------------------------ cookies
def cookie_names() -> tuple[str, str]:
    secure = ctx().settings.cookie_secure
    return ("__Host-emanet_session", "__Host-emanet_csrf") if secure else ("emanet_session", "emanet_csrf")


def create_session(resp, user_id: str) -> str:
    c = ctx()
    token = secrets.token_urlsafe(32)
    csrf = secrets.token_urlsafe(32)
    t = wall_now()
    with c.db.tx() as conn:
        conn.execute("INSERT INTO sessions(token_hash, user_id, csrf, created_at, last_seen, ip, user_agent) "
                     "VALUES(?,?,?,?,?,?,?)",
                     (sha256_hex(token), user_id, csrf, t, t, client_ip(), request.headers.get("User-Agent", "")[:200]))
    sname, cname = cookie_names()
    secure = c.settings.cookie_secure
    resp.set_cookie(sname, token, httponly=True, secure=secure, samesite="Strict", path="/",
                    max_age=c.settings.session_absolute_seconds)
    # CSRF cookie JS-ə görünür (double-submit), amma əsas yoxlama server tərəfdəki dəyərlədir
    resp.set_cookie(cname, csrf, httponly=False, secure=secure, samesite="Strict", path="/",
                    max_age=c.settings.session_absolute_seconds)
    return csrf


def destroy_session(resp=None) -> None:
    sname, cname = cookie_names()
    token = request.cookies.get(sname)
    if token:
        with ctx().db.tx() as conn:
            conn.execute("DELETE FROM sessions WHERE token_hash=?", (sha256_hex(token),))
    if resp is not None:
        resp.delete_cookie(sname, path="/")
        resp.delete_cookie(cname, path="/")


def revoke_all_sessions(conn, user_id: str) -> None:
    conn.execute("DELETE FROM sessions WHERE user_id=?", (user_id,))


def load_session():
    c = ctx()
    sname, _ = cookie_names()
    token = request.cookies.get(sname)
    if not token or len(token) > 100:
        return None
    row = c.db.one("SELECT s.*, u.role, u.status, u.email, u.display_name FROM sessions s "
                   "JOIN users u ON u.id = s.user_id WHERE s.token_hash=?", (sha256_hex(token),))
    if row is None:
        return None
    t = wall_now()
    if (t - row["last_seen"] > c.settings.session_idle_seconds
            or t - row["created_at"] > c.settings.session_absolute_seconds
            or row["status"] != "active"):
        with c.db.tx() as conn:
            conn.execute("DELETE FROM sessions WHERE token_hash=?", (row["token_hash"],))
        return None
    if t - row["last_seen"] > 30:   # hər sorğuda yazmamaq üçün
        with c.db.tx() as conn:
            conn.execute("UPDATE sessions SET last_seen=? WHERE token_hash=?", (t, row["token_hash"]))
    return row


# ------------------------------------------------------------------ CSRF
def origin_allowed() -> bool:
    allowed = {ctx().settings.public_origin}
    origin = request.headers.get("Origin")
    if origin:
        return origin.rstrip("/") in allowed
    ref = request.headers.get("Referer")
    if ref:
        p = urlsplit(ref)
        return f"{p.scheme}://{p.netloc}" in allowed
    # Origin/Referer yoxdursa: brauzer olmayan müştəri (curl/test). Sec-Fetch-Site varsa, ona bax.
    return request.headers.get("Sec-Fetch-Site", "same-origin") in {"same-origin", "none"}


def check_csrf(session) -> None:
    if request.method in SAFE_METHODS:
        return
    if not origin_allowed():
        raise ApiError(403, "csrf_origin", "sorğunun mənbəyi (Origin) icazəli deyil")
    if session is not None:
        sent = request.headers.get("X-CSRF-Token", "")
        if not sent or not hmac.compare_digest(sent, session["csrf"]):
            raise ApiError(403, "csrf_token", "CSRF tokeni yanlışdır və ya yoxdur")


# ------------------------------------------------------------------ dekoratorlar
def require_auth(*roles: str):
    def deco(fn):
        @functools.wraps(fn)
        def wrapper(*a, **kw):
            s = load_session()
            if s is None:
                raise ApiError(401, "unauthenticated", "daxil olmaq lazımdır")
            check_csrf(s)
            if roles and s["role"] not in roles:
                c = ctx()
                with c.db.tx() as conn:
                    audit.security_event(conn, ts=now(), kind="forbidden_role", actor=s["user_id"], ip=client_ip(),
                                         path=request.path[:120], need=",".join(roles))
                raise ApiError(403, "forbidden", "bu əməliyyat üçün icazəniz yoxdur")
            g.session = s
            g.user_id = s["user_id"]
            return fn(*a, **kw)
        return wrapper
    return deco


def public_endpoint(fn):
    @functools.wraps(fn)
    def wrapper(*a, **kw):
        check_csrf(None)
        return fn(*a, **kw)
    return wrapper


# ------------------------------------------------------------------ sürət məhdudiyyəti
def rate_limit(bucket: str, limit: int, window_s: int, *, actor: str | None = None) -> None:
    c = ctx()
    t = wall_now()
    with c.db.tx() as conn:
        conn.execute("DELETE FROM rate_hits WHERE ts < ?", (t - 86400,))
        n = conn.execute("SELECT COUNT(*) FROM rate_hits WHERE bucket=? AND ts > ?", (bucket, t - window_s)).fetchone()[0]
        if n >= limit:
            audit.security_event(conn, ts=t, kind="rate_limited", actor=actor, ip=client_ip(), bucket=bucket.split(":")[0])
        else:
            conn.execute("INSERT INTO rate_hits(bucket, ts) VALUES(?,?)", (bucket, t))
    if n >= limit:
        raise ApiError(429, "rate_limited", "çox sayda sorğu — bir az sonra yenidən cəhd edin", retry_after=window_s)


# ------------------------------------------------------------------ başlıqlar
def apply_security_headers(resp):
    h = resp.headers
    h["Content-Security-Policy"] = CSP
    h["X-Content-Type-Options"] = "nosniff"
    h["X-Frame-Options"] = "DENY"
    h["Referrer-Policy"] = "no-referrer"
    h["Cross-Origin-Opener-Policy"] = "same-origin"
    h["Cross-Origin-Resource-Policy"] = "same-origin"
    h["Permissions-Policy"] = "camera=(), microphone=(), geolocation=(), payment=(), usb=(), interest-cohort=()"
    if ctx().settings.cookie_secure:
        h["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains"
    if request.path.startswith("/api/") or request.path.startswith("/internal/"):
        h["Cache-Control"] = "no-store"
    h.pop("Server", None)
    return resp


def json_error(err: ApiError):
    body = {"error": err.code, "message": err.message, **err.extra}
    resp = jsonify(body)
    resp.status_code = err.status
    if err.status == 429 and "retry_after" in err.extra:
        resp.headers["Retry-After"] = str(err.extra["retry_after"])
    return resp


def verify_scheduler_signature(secret: bytes, method: str, path: str, ts_header: str, sig_header: str,
                               now_ts: float, body: bytes = b"") -> bool:
    """EventBridge → Lambda → /internal/tick sorğusunun HMAC imzası (±300 s)."""
    try:
        ts = int(ts_header)
    except (TypeError, ValueError):
        return False
    if abs(time.time() - ts) > 300 and abs(now_ts - ts) > 300:
        return False
    msg = f"{method}\n{path}\n{ts}\n{hashlib.sha256(body).hexdigest()}".encode()
    expected = hmac.new(secret, msg, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, sig_header or "")


def sign_scheduler_request(secret: bytes, method: str, path: str, ts: int, body: bytes = b"") -> str:
    msg = f"{method}\n{path}\n{ts}\n{hashlib.sha256(body).hexdigest()}".encode()
    return hmac.new(secret, msg, hashlib.sha256).hexdigest()
