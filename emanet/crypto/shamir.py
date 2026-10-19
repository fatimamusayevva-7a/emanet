"""Shamir gizli bölgüsü (Shamir's Secret Sharing) — GF(2^8) üzərində.

Riyazi əsas
-----------
Sirrin hər baytı s üçün dərəcəsi (t-1) olan təsadüfi çoxhədli seçilir:

    f(x) = s + a1·x + a2·x² + … + a(t-1)·x^(t-1)      (bütün əməllər GF(256)-da)

i-ci etibarlı şəxs (x_i, f(x_i)) cütünü alır. Hər hansı t hissə Laqranj
interpolyasiyası ilə f(0) = s qiymətini bərpa edir:

    s = Σ_j  y_j · Π_{m≠j}  x_m / (x_m − x_j)

(t-1) və ya daha az hissə sirr haqqında **heç bir məlumat vermir**
(informasiya-nəzəri, yəni mütləq məxfilik): istənilən s üçün həmin
hissələrlə uyğun gələn tam olaraq bir çoxhədli mövcuddur.

GF(256) sahəsi AES-in çoxhədlisi x⁸+x⁴+x³+x+1 (0x11B) ilə qurulur,
generator 3-dür. Bu fayl brauzerdəki `web/js/shamir.js` ilə bayt-bayt
uyğundur — uyğunluq `tests/js/vectors.json` ilə yoxlanılır.
"""
from __future__ import annotations

import secrets
from dataclasses import dataclass
from typing import Callable, Iterable, Sequence

_EXP = [0] * 512
_LOG = [0] * 256


def _init_tables() -> None:
    x = 1
    for i in range(255):
        _EXP[i] = x
        _LOG[x] = i
        # x · 3 = x · (2 + 1) = xtime(x) XOR x
        x2 = (x << 1) ^ (0x11B if x & 0x80 else 0)
        x = x2 ^ x
    for i in range(255, 512):
        _EXP[i] = _EXP[i - 255]


_init_tables()


def gf_add(a: int, b: int) -> int:
    return a ^ b


def gf_mul(a: int, b: int) -> int:
    if a == 0 or b == 0:
        return 0
    return _EXP[_LOG[a] + _LOG[b]]


def gf_div(a: int, b: int) -> int:
    if b == 0:
        raise ZeroDivisionError("GF(256)-da sıfıra bölmə")
    if a == 0:
        return 0
    return _EXP[(_LOG[a] - _LOG[b]) % 255]


def gf_inv(a: int) -> int:
    return gf_div(1, a)


def _eval_poly(coeffs: Sequence[int], x: int) -> int:
    """Horner sxemi: coeffs[0] + coeffs[1]·x + …"""
    acc = 0
    for c in reversed(coeffs):
        acc = gf_mul(acc, x) ^ c
    return acc


@dataclass(frozen=True)
class Share:
    x: int          # 1..255 — etibarlı şəxsin nömrəsi
    y: bytes        # sirrin uzunluğu qədər bayt

    def to_bytes(self) -> bytes:
        return bytes([self.x]) + self.y

    @classmethod
    def from_bytes(cls, data: bytes) -> "Share":
        if len(data) < 2:
            raise ValueError("hissə çox qısadır")
        if data[0] == 0:
            raise ValueError("x=0 hissəsi qadağandır (o, sirrin özüdür)")
        return cls(data[0], bytes(data[1:]))


RandomBytes = Callable[[int], bytes]


def split(secret: bytes, n: int, t: int, *, randbytes: RandomBytes = secrets.token_bytes) -> list[Share]:
    """Sirri n hissəyə böl; istənilən t hissə onu bərpa edir."""
    if not secret:
        raise ValueError("sirr boş ola bilməz")
    if not (2 <= t <= n <= 255):
        raise ValueError("şərt: 2 ≤ t ≤ n ≤ 255")
    ys = [bytearray() for _ in range(n)]
    for s in secret:
        coeffs = [s] + list(randbytes(t - 1))
        for i in range(n):
            ys[i].append(_eval_poly(coeffs, i + 1))
    return [Share(i + 1, bytes(ys[i])) for i in range(n)]


def combine(shares: Iterable[Share]) -> bytes:
    """Laqranj interpolyasiyası ilə f(0)-ı hesabla.

    Diqqət: hissələrin sayı t-dən azdırsa, nəticə **səhv** sirr olur (xəta
    vermir — bu, Shamir sxeminin təbiətidir). Ona görə də bərpa olunmuş sirr
    həmişə autentifikasiya olunmuş şifrələmə (GCM teqi) ilə yoxlanılır.
    """
    shares = list(shares)
    if len(shares) < 2:
        raise ValueError("ən azı 2 hissə lazımdır")
    xs = [s.x for s in shares]
    if len(set(xs)) != len(xs):
        raise ValueError("təkrarlanan hissə nömrəsi")
    if any(not 1 <= x <= 255 for x in xs):
        raise ValueError("hissə nömrəsi 1..255 aralığında olmalıdır")
    length = len(shares[0].y)
    if any(len(s.y) != length for s in shares):
        raise ValueError("hissələrin uzunluğu fərqlidir")

    # Laqranj əmsalları x=0 nöqtəsində: L_j(0) = Π x_m / (x_m XOR x_j)
    basis = []
    for j, xj in enumerate(xs):
        num, den = 1, 1
        for m, xm in enumerate(xs):
            if m != j:
                num = gf_mul(num, xm)
                den = gf_mul(den, xm ^ xj)
        basis.append(gf_div(num, den))

    out = bytearray(length)
    for k in range(length):
        acc = 0
        for j, s in enumerate(shares):
            acc ^= gf_mul(s.y[k], basis[j])
        out[k] = acc
    return bytes(out)
