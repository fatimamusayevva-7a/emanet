"""Parolların Argon2id ilə təhlükəsiz saxlanması.

OWASP Password Storage Cheat Sheet minimumu: m=19 MiB, t=2, p=1.
Biz m=19456 KiB, t=2, p=1 istifadə edirik (konfiqurasiya ilə artırıla bilər).

Saxlama formatı (PHC string formatına yaxın):
    $argon2id$v=19$m=19456,t=2,p=1$<salt_b64>$<hash_b64>

Hər parol üçün 16 baytlıq unikal salt — eyni parollar eyni heş vermir və
rainbow-cədvəl hücumları mənasını itirir.
"""
from __future__ import annotations

import base64
import hmac
import os
from dataclasses import dataclass

from cryptography.hazmat.primitives.kdf.argon2 import Argon2id

COMMON_PASSWORDS = {
    "password", "password123", "123456789012", "qwertyuiop12", "admin123456",
    "parol1234567", "azerbaycan123", "baku12345678", "letmein12345",
    "iloveyou1234", "welcome12345", "qwerty123456",
}


@dataclass(frozen=True)
class Argon2Params:
    memory_kib: int = 19456
    iterations: int = 2
    lanes: int = 1
    salt_len: int = 16
    hash_len: int = 32


DEFAULT_PARAMS = Argon2Params()


def _b64e(b: bytes) -> str:
    return base64.b64encode(b).decode().rstrip("=")


def _b64d(s: str) -> bytes:
    return base64.b64decode(s + "=" * (-len(s) % 4))


def _derive(password: str, salt: bytes, p: Argon2Params) -> bytes:
    kdf = Argon2id(
        salt=salt,
        length=p.hash_len,
        iterations=p.iterations,
        lanes=p.lanes,
        memory_cost=p.memory_kib,
    )
    return kdf.derive(password.encode("utf-8"))


def hash_password(password: str, params: Argon2Params = DEFAULT_PARAMS) -> str:
    salt = os.urandom(params.salt_len)
    digest = _derive(password, salt, params)
    return (
        f"$argon2id$v=19$m={params.memory_kib},t={params.iterations},"
        f"p={params.lanes}${_b64e(salt)}${_b64e(digest)}"
    )


def verify_password(password: str, encoded: str) -> bool:
    try:
        _, alg, _ver, prm, salt_b64, hash_b64 = encoded.split("$")
        if alg != "argon2id":
            return False
        kv = dict(item.split("=") for item in prm.split(","))
        expected = _b64d(hash_b64)
        params = Argon2Params(
            memory_kib=int(kv["m"]), iterations=int(kv["t"]),
            lanes=int(kv["p"]), hash_len=len(expected),
        )
        actual = _derive(password, _b64d(salt_b64), params)
    except (ValueError, KeyError):
        return False
    # Sabit zamanlı müqayisə — timing hücumlarına qarşı
    return hmac.compare_digest(actual, expected)


def needs_rehash(encoded: str, params: Argon2Params = DEFAULT_PARAMS) -> bool:
    """Parametrlər artırılıbsa, növbəti uğurlu girişdə heşi yeniləmək lazımdır."""
    try:
        prm = encoded.split("$")[3]
        kv = dict(item.split("=") for item in prm.split(","))
        return (int(kv["m"]) < params.memory_kib or int(kv["t"]) < params.iterations)
    except (IndexError, ValueError, KeyError):
        return True


def check_password_policy(password: str, username: str = "") -> list[str]:
    """NIST SP 800-63B ruhunda sadə siyasət: uzunluq + məlum zəif parollar."""
    problems = []
    if len(password) < 12:
        problems.append("parol ən azı 12 simvol olmalıdır")
    if len(password) > 128:
        problems.append("parol 128 simvoldan uzun ola bilməz")
    if password.lower() in COMMON_PASSWORDS:
        problems.append("bu parol geniş yayılmış zəif parollar siyahısındadır")
    if username and username.lower() in password.lower():
        problems.append("parol istifadəçi adını ehtiva etməməlidir")
    return problems
