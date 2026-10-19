"""Python ↔ JavaScript uyğunluq vektorlarını yarat: tests/js/vectors.json

Python tərəfi sabit (deterministik) girişlərdən nəticələr hesablayır, JS testi
eyni girişlərlə eyni nəticəni almalıdır; təsadüfi olanlar (ECIES, GCM) üçün
JS Python-un şifrəmətnini açmalıdır.

İşə salma:  python scripts/gen_vectors.py
"""
from __future__ import annotations

import hashlib
import json
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from cryptography.hazmat.primitives import serialization  # noqa: E402

from emanet.crypto import primitives as P  # noqa: E402
from emanet.crypto import shamir  # noqa: E402


def det_rng(seed: bytes):
    """Deterministik "təsadüfi" baytlar — yalnız test vektorları üçün!"""
    state = {"c": 0}

    def rb(n: int) -> bytes:
        out = b""
        while len(out) < n:
            out += hashlib.sha256(seed + state["c"].to_bytes(8, "big")).digest()
            state["c"] += 1
        return out[:n]
    return rb


def main() -> None:
    v: dict = {}

    # 1) Shamir: sabit sirr + deterministik əmsallar
    secret = bytes(range(32))
    sh = shamir.split(secret, 5, 3, randbytes=det_rng(b"shamir-1"))
    v["shamir"] = {"secret": P.b64u(secret), "n": 5, "t": 3, "seed": "shamir-1",
                   "shares": [P.b64u(s.to_bytes()) for s in sh]}
    v["gf"] = [[a, b, shamir.gf_mul(a, b)] for a, b in [(0x57, 0x83), (0x02, 0x87), (0xFF, 0xFF), (1, 0xAB), (0x53, 0xCA)]]

    # 2) KDF-lər
    salt = bytes.fromhex("00112233445566778899aabbccddeeff")
    mk = P.master_key("Bakı-Xəzər 2026!", salt)
    keys = P.derive_user_keys(mk)
    v["kdf"] = {"password": "Bakı-Xəzər 2026!", "salt": P.b64u(salt), "master": P.b64u(mk),
                "auth": P.b64u(keys.auth_key), "enc": P.b64u(keys.enc_key)}
    S, R = bytes([7]) * 32, bytes([9]) * 32
    v["release_kek"] = {"S": P.b64u(S), "R": P.b64u(R), "vault": "v_test",
                        "kek": P.b64u(P.release_kek(S, R, "v_test"))}
    v["commitment"] = {"vault": "v_test", "share": v["shamir"]["shares"][0],
                       "hex": P.share_commitment("v_test", sh[0].to_bytes())}
    rc = "ABCDE-FGHJK-LMNPQ-RSTUV-WXYZ2"
    rk = P.recovery_keys(rc)
    v["recovery"] = {"code": rc, "auth": P.b64u(rk.auth_key), "enc": P.b64u(rk.enc_key)}

    # 3) Doldurma
    v["pad"] = [{"len": n, "padded_len": len(P.pad(b"x" * n))} for n in (0, 1, 4092, 4093, 65532, 65533, 200000)]

    # 4) Python-un şifrələdiyini JS açmalıdır
    key = bytes([3]) * 32
    v["seal"] = {"key": P.b64u(key), "aad": P.aad_vault("v_test", 4),
                 "box": P.seal(key, P.pad("Salam, Əmanət!".encode()), P.aad_vault("v_test", 4)),
                 "plaintext": "Salam, Əmanət!"}
    priv = P.generate_keypair()
    ctx = P.ctx_share("v_test", "u_trustee", 2)
    v["ecies"] = {
        "pkcs8": P.b64u(priv.private_bytes(serialization.Encoding.DER, serialization.PrivateFormat.PKCS8,
                                           serialization.NoEncryption())),
        "public": P.b64u(P.public_raw(priv)),
        "fingerprint": P.fingerprint(P.public_raw(priv)),
        "context": ctx,
        "box": P.ecies_encrypt(P.public_raw(priv), b"share-bytes-123", ctx),
        "plaintext": P.b64u(b"share-bytes-123"),
    }
    out = ROOT / "tests" / "js" / "vectors.json"
    out.write_text(json.dumps(v, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"yazıldı: {out.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
