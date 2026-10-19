"""Demo 1 — "Parolu üç yerə bölmək" niyə təhlükəlidir və Shamir niyə fərqlidir.

Sadəlövh yanaşma: 24 simvollu parolu 3 nəfərə 8-8-8 simvol bölmək.
  * Hər nəfər parolun 1/3-ni BİLİR → qalan axtarış sahəsi kəskin azalır.
  * İki nəfər birləşsə, yalnız 8 simvol qalır.
  * Bir nəfər itsə, parol həmişəlik itir (ehtiyat yoxdur).
Shamir (2-dən-3):
  * Bir hissə sirr haqqında 0 bit məlumat verir.
  * İstənilən iki hissə kifayətdir — bir nəfər itsə də sirr bərpa olunur.
"""
from __future__ import annotations

import math
import os
import pathlib
import string
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
from emanet.crypto import shamir  # noqa: E402

ALPH = string.ascii_letters + string.digits + "!@#$%^&*"
pw = "".join(ALPH[b % len(ALPH)] for b in os.urandom(24))
bits_total = 24 * math.log2(len(ALPH))
print(f"Parol (24 simvol, əlifba {len(ALPH)}): entropiya ≈ {bits_total:.0f} bit\n")

parts = [pw[0:8], pw[8:16], pw[16:24]]
print("SADƏLÖVH BÖLGÜ:")
for i, p in enumerate(parts, 1):
    print(f"  {i}-ci şəxs: {p}  (parolun {len(p)} simvolunu açıq görür)")
left1 = 16 * math.log2(len(ALPH))
left2 = 8 * math.log2(len(ALPH))
print(f"  1 nəfərin bildiyindən sonra qalan entropiya: {left1:.0f} bit  (−{bits_total - left1:.0f} bit sızdı)")
print(f"  2 nəfər birləşsə qalan: {left2:.0f} bit → 1 GPU (10^10 cəhd/s) ilə ≈ {2**left2 / 1e10 / 3600:.1f} saat")
print("  1 nəfər itsə: parol BƏRPA OLUNMUR\n")

secret = pw.encode()
sh = shamir.split(secret, 3, 2)
print("SHAMIR (2-dən-3):")
for s in sh:
    print(f"  {s.x}-ci şəxs: {s.y.hex()[:48]}…")
print("  1 hissədən sonra qalan entropiya: 100% (informasiya-nəzəri məxfilik)")
for a, b in [(0, 1), (0, 2), (1, 2)]:
    ok = shamir.combine([sh[a], sh[b]]) == secret
    print(f"  {sh[a].x}+{sh[b].x} birləşir → {'BƏRPA OLUNDU' if ok else 'xəta'}")

# Sübut: bir hissə ilə istənilən 'sirr' eyni dərəcədə mümkündür
x1, y1 = sh[0].x, sh[0].y[0]
# f(x) = s + a1·x  ⇒  a1 = (y1 − s)/x1 — hər s üçün belə a1 mövcuddur və f(x1) = y1 ödənir
consistent = sum(1 for s in range(256)
                 if s ^ shamir.gf_mul(shamir.gf_div(y1 ^ s, x1), x1) == y1)
print(f"\n  1-ci hissənin ilk baytı {y1:#04x} ilə uyğun gələn mümkün sirr baytlarının sayı: {consistent}/256")
