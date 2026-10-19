"""Demo 3 — "İki açarlı kilid": kim nəyi aça bilər?

   KEK = HKDF-SHA256( S ‖ R ,  salt = vault_id )
   S — Shamir ilə etibarlı şəxslər arasında bölünüb (server görmür)
   R — KMS-də, yalnız "sağam" şərti ödəniləndə buraxılır (etibarlı şəxslər görmür)

Bu demo 6 təhdid ssenarisini real kriptoqrafiya ilə sınayır.
"""
from __future__ import annotations

import os
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
from emanet.crypto import primitives as P  # noqa: E402
from emanet.crypto import shamir  # noqa: E402

vault = "v_demo"
dek = os.urandom(32)
S, R = os.urandom(32), os.urandom(32)
shares = shamir.split(S, 3, 2)
wrapped = P.seal(P.release_kek(S, R, vault), dek, P.aad_dek(vault, "release"))


def attempt(label: str, s_guess: bytes, r_guess: bytes) -> None:
    try:
        ok = P.open_sealed(P.release_kek(s_guess, r_guess, vault), wrapped, P.aad_dek(vault, "release")) == dek
    except P.CryptoError:
        ok = False
    print(f"  {'AÇILDI  ' if ok else 'açılmadı'} │ {label}")


print("  Nəticə   │ Ssenari")
print("──────────┼──────────────────────────────────────────────────────")
attempt("Server/admin təkbaşına (R var, S yox)", os.urandom(32), R)
attempt("Bir etibarlı şəxs (1 hissə + R)", shamir.combine([shares[0], shamir.Share(2, os.urandom(32))]), R)
attempt("2 etibarlı şəxs VAXTINDAN ƏVVƏL sui-qəsd (S var, R yox)", shamir.combine(shares[:2]), os.urandom(32))
attempt("DB oğurlandı (sarınmış R, şifrəli hissələr — açarlar yox)", os.urandom(32), os.urandom(32))
attempt("Vaxt çatdı: R buraxıldı + 2 hissə (1 və 3)", shamir.combine([shares[0], shares[2]]), R)
attempt("Vaxt çatdı: R buraxıldı + 3 hissə", shamir.combine(shares), R)
print("\nNəticə: yalnız \"insanlar + zaman\" şərti BİRLİKDƏ ödəniləndə seyf açılır.")
