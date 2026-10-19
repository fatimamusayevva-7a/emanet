"""Əmanət-in kriptoqrafik "protokolu" — server və brauzer eyni formatı istifadə edir.

Bu modul `web/js/crypto.js`-in Python əkizidir. Hər funksiyanın formatı
(baytların düzülüşü, HKDF `info` sətirləri, AAD) iki dildə eynidir və
`tests/test_crossimpl.py` + `tests/js/crossimpl.test.mjs` ilə yoxlanılır.

Alqoritmlər (hamısı NIST/IETF standartıdır, WebCrypto-da mövcuddur):
  * AES-256-GCM (NIST SP 800-38D) — autentifikasiyalı şifrələmə
  * HKDF-SHA-256 (RFC 5869)       — açar törətmə
  * PBKDF2-HMAC-SHA-256 (RFC 8018), 600 000 iterasiya (OWASP 2023+)
  * ECDH P-256 (NIST SP 800-56A)  — açıq açarla şifrələmə (ECIES)
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import struct
import unicodedata
from dataclasses import dataclass

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

PROTOCOL = "emanet/v1"
PBKDF2_ITERATIONS = 600_000
KEY_LEN = 32
IV_LEN = 12


class CryptoError(Exception):
    """Şifrəaçma/yoxlama uğursuz oldu (səbəb qəsdən ümumidir)."""


# ---------------------------------------------------------------- kodlaşdırma
def b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def b64u_d(text: str) -> bytes:
    if not isinstance(text, str):
        raise CryptoError("base64url sətir gözlənilirdi")
    try:
        return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
    except (ValueError, TypeError) as exc:
        raise CryptoError("yanlış base64url") from exc


def utf8(s: str) -> bytes:
    return s.encode("utf-8")


# ---------------------------------------------------------------- KDF
def hkdf(ikm: bytes, info: str, *, salt: bytes = b"", length: int = KEY_LEN) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=length, salt=salt or None,
                info=utf8(info)).derive(ikm)


def normalize_password(password: str) -> bytes:
    # NFKC: "ə" klaviaturadan fərqli kodlarla daxil edilsə belə eyni açar alınsın
    return unicodedata.normalize("NFKC", password).encode("utf-8")


def master_key(password: str, kdf_salt: bytes, iterations: int = PBKDF2_ITERATIONS) -> bytes:
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=KEY_LEN,
                     salt=utf8(PROTOCOL + "|") + kdf_salt, iterations=iterations)
    return kdf.derive(normalize_password(password))


@dataclass(frozen=True)
class DerivedKeys:
    auth_key: bytes   # serverə göndərilir (server onu yenə Argon2id ilə heşləyir)
    enc_key: bytes    # heç vaxt brauzerdən çıxmır


def derive_user_keys(mk: bytes) -> DerivedKeys:
    """Açar ayrılığı: bir master açardan iki müstəqil açar.

    auth_key-dən enc_key-i hesablamaq mümkün deyil (HKDF bir istiqamətlidir),
    deməli server autentifikasiya məlumatını görsə də, seyfi aça bilmir."""
    return DerivedKeys(hkdf(mk, f"{PROTOCOL}/auth"), hkdf(mk, f"{PROTOCOL}/enc"))


# ---------------------------------------------------------------- AES-GCM
def seal(key: bytes, plaintext: bytes, aad: str) -> dict:
    iv = os.urandom(IV_LEN)
    ct = AESGCM(key).encrypt(iv, plaintext, utf8(aad))
    return {"v": 1, "iv": b64u(iv), "ct": b64u(ct)}


def open_sealed(key: bytes, box: dict, aad: str) -> bytes:
    try:
        if box.get("v") != 1:
            raise CryptoError("naməlum versiya")
        iv = b64u_d(box["iv"])
        if len(iv) != IV_LEN:
            raise CryptoError("yanlış IV")
        return AESGCM(key).decrypt(iv, b64u_d(box["ct"]), utf8(aad))
    except (InvalidTag, KeyError, TypeError, AttributeError) as exc:
        raise CryptoError("şifrəaçma uğursuz oldu") from exc


# ---------------------------------------------------------------- AAD-lar
def aad_vault(vault_id: str, version: int) -> str:
    return f"{PROTOCOL}/vault|{vault_id}|{version}"


def aad_dek(vault_id: str, purpose: str) -> str:
    if purpose not in {"owner", "release", "recovery"}:
        raise ValueError("purpose")
    return f"{PROTOCOL}/dek/{purpose}|{vault_id}"


def aad_privkey(user_id: str, purpose: str = "enc") -> str:
    return f"{PROTOCOL}/privkey/{purpose}|{user_id}"


def ctx_share(vault_id: str, trustee_id: str, x: int) -> str:
    return f"{PROTOCOL}/share|{vault_id}|{trustee_id}|{x}"


def ctx_handoff(vault_id: str, from_id: str, to_id: str, x: int) -> str:
    return f"{PROTOCOL}/handoff|{vault_id}|{from_id}|{to_id}|{x}"


# ---------------------------------------------------------------- "iki açarlı kilid"
def release_kek(shamir_secret: bytes, release_key: bytes, vault_id: str) -> bytes:
    """Etibarlı şəxslərin sirri S + serverin zaman kilidi açarı R → KEK.

    * S olmadan (etibarlı şəxslər birləşmədən) server açarı ala bilməz.
    * R olmadan (vaxt şərti ödənmədən) etibarlı şəxslər açarı ala bilməz.
    """
    if len(shamir_secret) != 32 or len(release_key) != 32:
        raise ValueError("S və R 32 bayt olmalıdır")
    return hkdf(shamir_secret + release_key, f"{PROTOCOL}/release-kek", salt=utf8(vault_id))


def share_commitment(vault_id: str, share_bytes: bytes) -> str:
    """Hissənin öhdəliyi (commitment): saxta/korlanmış hissəni dərhal tutur."""
    return hashlib.sha256(utf8(f"{PROTOCOL}/share-commit|{vault_id}|") + share_bytes).hexdigest()


# ---------------------------------------------------------------- ölçünü gizlətmə
def pad(data: bytes) -> bytes:
    """Uzunluq prefiksi + sıfırlarla doldurma: server seyfin dəqiq ölçüsünü görmür.

    4 KiB-a qədər yuvarlaqlaşdırılır, 64 KiB-dan sonra 64 KiB addımla."""
    raw = struct.pack(">I", len(data)) + data
    block = 4096 if len(raw) <= 65536 else 65536
    total = -(-len(raw) // block) * block
    return raw + b"\x00" * (total - len(raw))


def unpad(data: bytes) -> bytes:
    if len(data) < 4:
        raise CryptoError("yanlış doldurma")
    n = struct.unpack(">I", data[:4])[0]
    if n > len(data) - 4 or any(data[4 + n:]):
        raise CryptoError("yanlış doldurma")
    return data[4:4 + n]


# ---------------------------------------------------------------- ECIES (P-256)
def generate_keypair() -> ec.EllipticCurvePrivateKey:
    return ec.generate_private_key(ec.SECP256R1())


def public_raw(priv_or_pub) -> bytes:
    pub = priv_or_pub.public_key() if hasattr(priv_or_pub, "public_key") else priv_or_pub
    return pub.public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)


def load_public(raw: bytes) -> ec.EllipticCurvePublicKey:
    if len(raw) != 65 or raw[0] != 4:
        raise CryptoError("yanlış açıq açar formatı")
    try:
        return ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), raw)
    except ValueError as exc:  # əyri üzərində olmayan nöqtə (invalid-curve hücumu)
        raise CryptoError("açıq açar əyri üzərində deyil") from exc


def fingerprint(raw_pub: bytes) -> str:
    """İnsan üçün oxunaqlı barmaq izi: 'A1B2 C3D4 …' (128 bit, 8 qrup).

    Sahib və etibarlı şəxs bunu telefonda/üz-üzə müqayisə edir — server
    saxta açıq açar qoysa (MITM), barmaq izləri uyğun gəlməz."""
    h = hashlib.sha256(utf8(f"{PROTOCOL}/fp|") + raw_pub).hexdigest()[:32].upper()
    return " ".join(h[i:i + 4] for i in range(0, 32, 4))


def ecies_encrypt(recipient_raw: bytes, plaintext: bytes, context: str) -> dict:
    recipient = load_public(recipient_raw)
    eph = ec.generate_private_key(ec.SECP256R1())
    epk = public_raw(eph)
    shared = eph.exchange(ec.ECDH(), recipient)
    key = hkdf(shared, f"{PROTOCOL}/ecies|{context}", salt=epk)
    iv = os.urandom(IV_LEN)
    ct = AESGCM(key).encrypt(iv, plaintext, utf8(context))
    return {"v": 1, "epk": b64u(epk), "iv": b64u(iv), "ct": b64u(ct)}


def ecies_decrypt(priv: ec.EllipticCurvePrivateKey, box: dict, context: str) -> bytes:
    try:
        if box.get("v") != 1:
            raise CryptoError("naməlum versiya")
        epk = b64u_d(box["epk"])
        shared = priv.exchange(ec.ECDH(), load_public(epk))
        key = hkdf(shared, f"{PROTOCOL}/ecies|{context}", salt=epk)
        return AESGCM(key).decrypt(b64u_d(box["iv"]), b64u_d(box["ct"]), utf8(context))
    except (InvalidTag, KeyError, TypeError, AttributeError) as exc:
        raise CryptoError("ECIES şifrəaçma uğursuz oldu") from exc


# ---------------------------------------------------------------- bərpa kodu
RECOVERY_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"  # 0/O, 1/I qarışmasın


def new_recovery_code() -> str:
    """25 simvol × 5 bit = 125 bit entropiya, 5-li qruplarla."""
    chars = "".join(RECOVERY_ALPHABET[b % 32] for b in os.urandom(25))
    return "-".join(chars[i:i + 5] for i in range(0, 25, 5))


def recovery_keys(code: str) -> DerivedKeys:
    norm = code.replace("-", "").replace(" ", "").upper()
    if len(norm) != 25 or any(c not in RECOVERY_ALPHABET for c in norm):
        raise CryptoError("yanlış bərpa kodu")
    ikm = utf8(norm)
    return DerivedKeys(hkdf(ikm, f"{PROTOCOL}/recovery-auth"), hkdf(ikm, f"{PROTOCOL}/recovery-enc"))


def constant_eq(a: bytes | str, b: bytes | str) -> bool:
    if isinstance(a, str):
        a = a.encode()
    if isinstance(b, str):
        b = b.encode()
    return hmac.compare_digest(a, b)


def canonical(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
