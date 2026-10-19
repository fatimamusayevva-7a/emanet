"""TOTP (RFC 6238) — çoxfaktorlu autentifikasiya üçün birdəfəlik kodlar.

HOTP(K, C) = Truncate(HMAC-SHA1(K, C)) mod 10^d     (RFC 4226)
TOTP(K, T) = HOTP(K, floor((T - T0) / X)),  X = 30 s (RFC 6238)

Google Authenticator, Microsoft Authenticator, Aegis və s. ilə uyğundur.
Doğrulamada ±1 addımlıq pəncərə saat fərqini kompensasiya edir; eyni kodun
təkrar istifadəsi (replay) `last_used_step` ilə bloklanır.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import os
import struct
import time
from urllib.parse import quote

STEP = 30
DIGITS = 6


def generate_secret() -> str:
    return base64.b32encode(os.urandom(20)).decode().rstrip("=")


def _b32decode(secret: str) -> bytes:
    s = secret.strip().replace(" ", "").upper()
    return base64.b32decode(s + "=" * (-len(s) % 8))


def hotp(key: bytes, counter: int, digits: int = DIGITS, digest=hashlib.sha1) -> str:
    mac = hmac.new(key, struct.pack(">Q", counter), digest).digest()
    offset = mac[-1] & 0x0F  # dinamik kəsmə (dynamic truncation)
    code = struct.unpack(">I", mac[offset:offset + 4])[0] & 0x7FFFFFFF
    return str(code % (10 ** digits)).zfill(digits)


def totp(secret_b32: str, at: float | None = None, digits: int = DIGITS) -> str:
    t = time.time() if at is None else at
    return hotp(_b32decode(secret_b32), int(t // STEP), digits)


def verify(secret_b32: str, code: str, at: float | None = None,
           window: int = 1, last_used_step: int | None = None) -> int | None:
    """Uğurlu olduqda istifadə olunan zaman addımını qaytarır, əks halda None."""
    if not code or not code.isdigit() or len(code) != DIGITS:
        return None
    t = time.time() if at is None else at
    key = _b32decode(secret_b32)
    current = int(t // STEP)
    for step in range(current - window, current + window + 1):
        if last_used_step is not None and step <= last_used_step:
            continue  # replay qorunması
        if hmac.compare_digest(hotp(key, step), code):
            return step
    return None


def provisioning_uri(secret_b32: str, account: str, issuer: str = "Emanet") -> str:
    label = quote(f"{issuer}:{account}")
    return (f"otpauth://totp/{label}?secret={secret_b32}&issuer={quote(issuer)}"
            f"&algorithm=SHA1&digits={DIGITS}&period={STEP}")
