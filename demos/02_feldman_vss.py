"""Demo 2 — Feldman yoxlanıla bilən gizli bölgüsü (Verifiable Secret Sharing).

Adi Shamir sxemində etibarlı şəxs aldığı hissənin "düzgün" olub-olmadığını
yoxlaya bilmir: saxtakar paylayıcı (dealer) birinə yanlış hissə verə bilər və bu,
yalnız bərpa zamanı üzə çıxar. Feldman sxemi (1987) bunu həll edir:

  Paylayıcı f(x) = a0 + a1·x + … + a(t-1)·x^(t-1)  (mod q) seçir və
  ÖHDƏLİKLƏRİ dərc edir:  C_j = g^(a_j) mod p.
  i-ci şəxs öz hissəsini yoxlayır:   g^(f(i)) ≡ Π_j C_j^(i^j)   (mod p)

Diskret loqarifm çətin olduğu üçün C_j-lərdən a_j (o cümlədən sirr a0) tapılmır.

Əmanət-də sahib = paylayıcıdır və o, öz seyfini qorumaqda maraqlıdır, ona görə
produksiyada sadələşdirilmiş versiya istifadə olunur: hər hissənin SHA-256
öhdəliyi + bərpa olunan açarın AES-GCM teqi ilə yoxlanması. Bu demo isə tam VSS-i
göstərir — "saxtakar sahib" təhdidi əlavə olunsa, növbəti addım budur.

Qrup: RFC 3526 §3, 2048-bit MODP (Group 14), təhlükəsiz sadə ədəd p = 2q + 1, g = 4.
"""
from __future__ import annotations

import secrets
import time

P_HEX = (
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DD"
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
    "83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
    "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
    "15728E5A8AACAA68FFFFFFFFFFFFFFFF")
p = int(P_HEX, 16)
q = (p - 1) // 2
g = 4   # 2^2 — q tərtibli altqrupun generatoru


def deal(secret: int, n: int, t: int):
    coeffs = [secret] + [secrets.randbelow(q) for _ in range(t - 1)]
    shares = {i: sum(c * pow(i, j, q) for j, c in enumerate(coeffs)) % q for i in range(1, n + 1)}
    commitments = [pow(g, c, p) for c in coeffs]
    return shares, commitments


def verify(i: int, share: int, commitments) -> bool:
    lhs = pow(g, share, p)
    rhs = 1
    for j, C in enumerate(commitments):
        rhs = rhs * pow(C, pow(i, j, q), p) % p
    return lhs == rhs


def reconstruct(points: dict[int, int]) -> int:
    s = 0
    for j, yj in points.items():
        num, den = 1, 1
        for m in points:
            if m != j:
                num = num * m % q
                den = den * (m - j) % q
        s = (s + yj * num * pow(den, -1, q)) % q
    return s


if __name__ == "__main__":
    secret = secrets.randbelow(q)
    t0 = time.perf_counter()
    shares, C = deal(secret, n=3, t=2)
    print(f"Qrup: {p.bit_length()}-bit təhlükəsiz sadə ədəd (RFC 3526 Group 14), paylama {1000*(time.perf_counter()-t0):.1f} ms")
    print(f"Öhdəliklər (ictimai): C0 = g^s = {hex(C[0])[:34]}…, C1 = {hex(C[1])[:34]}…\n")

    print("1) Dürüst paylayıcı — hər şəxs öz hissəsini yoxlayır:")
    for i, s in shares.items():
        print(f"   şəxs {i}: {'✓ düzgündür' if verify(i, s, C) else '✗ SAXTA'}")

    print("\n2) Saxtakar paylayıcı 2-ci şəxsə yanlış hissə verir:")
    bad = dict(shares)
    bad[2] = (bad[2] + 12345) % q
    for i, s in bad.items():
        print(f"   şəxs {i}: {'✓ düzgündür' if verify(i, s, C) else '✗ SAXTA — dərhal aşkarlandı, bərpaya qədər gözləmək lazım deyil'}")

    print("\n3) Bərpa (istənilən 2 hissə):")
    for pair in [(1, 2), (1, 3), (2, 3)]:
        r = reconstruct({i: shares[i] for i in pair})
        print(f"   {pair}: {'sirr bərpa olundu ✓' if r == secret else 'xəta'}")
    print(f"\n   Yoxlama: g^bərpa == C0 ? {pow(g, reconstruct({1: shares[1], 3: shares[3]}), p) == C[0]}")
