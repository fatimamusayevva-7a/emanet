"""Shamir gizli bölgüsü və GF(256) arifmetikası."""
from __future__ import annotations

import itertools
import os
import random
import unittest

from emanet.crypto import shamir
from emanet.crypto.shamir import Share, combine, gf_div, gf_inv, gf_mul, split


class GaloisField(unittest.TestCase):
    def test_known_aes_products(self):
        # FIPS-197 §4.2: {57}·{83} = {c1}; {57}·{13} = {fe}
        self.assertEqual(gf_mul(0x57, 0x83), 0xC1)
        self.assertEqual(gf_mul(0x57, 0x13), 0xFE)

    def test_every_nonzero_element_has_inverse(self):
        for a in range(1, 256):
            self.assertEqual(gf_mul(a, gf_inv(a)), 1, a)

    def test_multiplication_is_commutative_full_table(self):
        for a in range(256):
            for b in range(a, 256):
                self.assertEqual(gf_mul(a, b), gf_mul(b, a))

    def test_distributive_and_associative_sampled(self):
        rnd = random.Random(1)
        for _ in range(20000):
            a, b, c = rnd.randrange(256), rnd.randrange(256), rnd.randrange(256)
            self.assertEqual(gf_mul(a, b ^ c), gf_mul(a, b) ^ gf_mul(a, c))
            self.assertEqual(gf_mul(gf_mul(a, b), c), gf_mul(a, gf_mul(b, c)))

    def test_division_inverts_multiplication(self):
        for a in range(256):
            for b in range(1, 256, 7):
                self.assertEqual(gf_div(gf_mul(a, b), b), a)

    def test_division_by_zero(self):
        with self.assertRaises(ZeroDivisionError):
            gf_div(5, 0)


class SplitCombine(unittest.TestCase):
    def test_every_t_subset_recovers_secret(self):
        """2 ≤ t ≤ n ≤ 7 üçün HƏR t-elementli alt çoxluq sirri bərpa edir (219 kombinasiya)."""
        checked = 0
        for n in range(2, 8):
            for t in range(2, n + 1):
                secret = os.urandom(32)
                shares = split(secret, n, t)
                for subset in itertools.combinations(shares, t):
                    self.assertEqual(combine(subset), secret)
                    checked += 1
        self.assertEqual(checked, 219)

    def test_more_than_t_shares_also_work(self):
        secret = os.urandom(32)
        shares = split(secret, 5, 3)
        for k in (3, 4, 5):
            for subset in itertools.combinations(shares, k):
                self.assertEqual(combine(subset), secret)

    def test_fewer_than_t_shares_give_wrong_secret(self):
        for _ in range(50):
            secret = os.urandom(32)
            shares = split(secret, 5, 3)
            for subset in itertools.combinations(shares, 2):
                self.assertNotEqual(combine(subset), secret)

    def test_perfect_secrecy_t_minus_1_shares(self):
        """(t-1) hissə ilə HƏR mümkün sirr baytı eyni dərəcədə uyğundur — informasiya-nəzəri məxfilik.

        t=2 üçün: bir hissə (x1, y1) verilib. İstənilən s ∈ GF(256) üçün a1 = (y1 − s)/x1 çoxhədlisi
        mövcuddur, yəni hissə s haqqında heç nə demir."""
        x1, y1 = 3, 0x9A
        candidates = set()
        for s in range(256):
            a1 = gf_div(y1 ^ s, x1)
            self.assertEqual(s ^ gf_mul(a1, x1), y1)
            candidates.add(s)
        self.assertEqual(len(candidates), 256)

    def test_single_share_distribution_is_uniform(self):
        """Statistik yoxlama: sabit sirr üçün bir hissənin baytları bərabər paylanır (χ² testi)."""
        counts = [0] * 256
        for _ in range(400):
            sh = split(b"\x00" * 64, 3, 2)[0]
            for byte in sh.y:
                counts[byte] += 1
        total = sum(counts)
        expected = total / 256
        chi2 = sum((c - expected) ** 2 / expected for c in counts)
        self.assertLess(chi2, 340)   # 255 sərbəstlik dərəcəsi, p≈0.0003 həddi

    def test_share_serialization_roundtrip(self):
        for sh in split(os.urandom(32), 4, 2):
            self.assertEqual(Share.from_bytes(sh.to_bytes()), sh)

    def test_deterministic_with_injected_rng(self):
        rb = lambda n: bytes(range(1, n + 1))  # noqa: E731
        self.assertEqual(split(b"\x2a", 3, 2, randbytes=rb), split(b"\x2a", 3, 2, randbytes=rb))

    def test_large_n(self):
        secret = os.urandom(16)
        shares = split(secret, 255, 10)
        self.assertEqual(combine(random.sample(shares, 10)), secret)


class Validation(unittest.TestCase):
    def test_bad_parameters(self):
        for n, t in [(1, 1), (3, 1), (2, 3), (256, 2), (0, 0)]:
            with self.subTest(n=n, t=t), self.assertRaises(ValueError):
                split(b"x", n, t)

    def test_empty_secret(self):
        with self.assertRaises(ValueError):
            split(b"", 3, 2)

    def test_duplicate_x(self):
        a, b = split(b"abc", 3, 2)[:2]
        with self.assertRaises(ValueError):
            combine([a, Share(a.x, b.y)])

    def test_length_mismatch(self):
        a, b = split(b"abc", 3, 2)[:2]
        with self.assertRaises(ValueError):
            combine([a, Share(b.x, b.y[:2])])

    def test_x_zero_rejected(self):
        with self.assertRaises(ValueError):
            Share.from_bytes(b"\x00abc")

    def test_single_share_rejected(self):
        with self.assertRaises(ValueError):
            combine(split(b"abc", 3, 2)[:1])

    def test_tampered_share_changes_result(self):
        secret = os.urandom(32)
        a, b, _ = split(secret, 3, 2)
        bad = Share(b.x, bytes([b.y[0] ^ 1]) + b.y[1:])
        self.assertNotEqual(combine([a, bad]), secret)


def _gen_threshold_tests():
    """Hər (n, t) cütü üçün ayrıca test metodu — hesabatda hər konfiqurasiya ayrı görünür."""
    for n in range(2, 11):
        for t in range(2, n + 1):
            def test(self, n=n, t=t):
                secret = os.urandom(32)
                shares = split(secret, n, t)
                rnd = random.Random(n * 100 + t)
                for _ in range(5):
                    self.assertEqual(combine(rnd.sample(shares, t)), secret)
                if t > 2:
                    self.assertNotEqual(combine(rnd.sample(shares, t - 1)), secret)
            setattr(SplitCombine, f"test_config_n{n:02d}_t{t:02d}", test)


_gen_threshold_tests()
_ = shamir

if __name__ == "__main__":
    unittest.main()
