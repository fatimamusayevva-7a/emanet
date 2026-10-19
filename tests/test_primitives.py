"""Kriptoqrafik primitivlər və protokol formatı."""
from __future__ import annotations

import os
import unittest

from cryptography.hazmat.primitives import hashes, hmac as chmac

from emanet.crypto import primitives as P
from emanet.crypto import passwords, totp
from emanet.crypto.audit_chain import GENESIS, link, verify_chain


class AesGcm(unittest.TestCase):
    def setUp(self):
        self.key = os.urandom(32)
        self.box = P.seal(self.key, b"gizli mesaj", "aad-1")

    def test_roundtrip(self):
        self.assertEqual(P.open_sealed(self.key, self.box, "aad-1"), b"gizli mesaj")

    def test_wrong_aad_rejected(self):
        with self.assertRaises(P.CryptoError):
            P.open_sealed(self.key, self.box, "aad-2")

    def test_wrong_key_rejected(self):
        with self.assertRaises(P.CryptoError):
            P.open_sealed(os.urandom(32), self.box, "aad-1")

    def test_every_ciphertext_bit_flip_detected(self):
        ct = bytearray(P.b64u_d(self.box["ct"]))
        for i in range(len(ct) * 8):
            mutated = bytearray(ct)
            mutated[i // 8] ^= 1 << (i % 8)
            with self.assertRaises(P.CryptoError):
                P.open_sealed(self.key, {**self.box, "ct": P.b64u(bytes(mutated))}, "aad-1")

    def test_iv_flip_detected(self):
        iv = bytearray(P.b64u_d(self.box["iv"]))
        iv[0] ^= 1
        with self.assertRaises(P.CryptoError):
            P.open_sealed(self.key, {**self.box, "iv": P.b64u(bytes(iv))}, "aad-1")

    def test_truncated_ciphertext(self):
        with self.assertRaises(P.CryptoError):
            P.open_sealed(self.key, {**self.box, "ct": self.box["ct"][:10]}, "aad-1")

    def test_nonces_unique(self):
        ivs = {P.seal(self.key, b"x", "a")["iv"] for _ in range(2000)}
        self.assertEqual(len(ivs), 2000)

    def test_unknown_version(self):
        with self.assertRaises(P.CryptoError):
            P.open_sealed(self.key, {**self.box, "v": 2}, "aad-1")

    def test_malformed_box(self):
        for bad in ({}, {"v": 1}, {"v": 1, "iv": "!!", "ct": "x"}, {"v": 1, "iv": P.b64u(b"short"), "ct": "AA"}):
            with self.subTest(bad=bad), self.assertRaises(P.CryptoError):
                P.open_sealed(self.key, bad, "aad-1")

    def test_vault_box_cannot_be_replayed_as_other_version(self):
        box = P.seal(self.key, b"v3", P.aad_vault("v_x", 3))
        with self.assertRaises(P.CryptoError):
            P.open_sealed(self.key, box, P.aad_vault("v_x", 4))      # köhnə versiyanın geri qaytarılması (rollback)

    def test_dek_wrap_purpose_binding(self):
        box = P.seal(self.key, b"dek", P.aad_dek("v_x", "owner"))
        with self.assertRaises(P.CryptoError):
            P.open_sealed(self.key, box, P.aad_dek("v_x", "release"))
        with self.assertRaises(ValueError):
            P.aad_dek("v_x", "admin")


class Kdf(unittest.TestCase):
    def test_auth_and_enc_keys_independent(self):
        k = P.derive_user_keys(os.urandom(32))
        self.assertNotEqual(k.auth_key, k.enc_key)
        self.assertEqual(len(k.auth_key), 32)

    def test_master_key_depends_on_salt_and_password(self):
        a = P.master_key("parol-bir-iki-üç", b"A" * 16, iterations=1000)
        self.assertNotEqual(a, P.master_key("parol-bir-iki-üç", b"B" * 16, iterations=1000))
        self.assertNotEqual(a, P.master_key("parol-bir-iki-üc", b"A" * 16, iterations=1000))
        self.assertEqual(a, P.master_key("parol-bir-iki-üç", b"A" * 16, iterations=1000))

    def test_nfkc_normalization(self):
        composed, decomposed = "Bakı Şəhəri", "Bakı Şəhəri"
        self.assertEqual(P.master_key(composed, b"s" * 16, iterations=1000),
                         P.master_key(decomposed, b"s" * 16, iterations=1000))

    def test_default_iterations_owasp(self):
        self.assertGreaterEqual(P.PBKDF2_ITERATIONS, 600_000)

    def test_hkdf_rfc5869_case1(self):
        ikm = bytes.fromhex("0b" * 22)
        salt = bytes.fromhex("000102030405060708090a0b0c")
        from cryptography.hazmat.primitives.kdf.hkdf import HKDF
        okm = HKDF(algorithm=hashes.SHA256(), length=42, salt=salt, info=bytes.fromhex("f0f1f2f3f4f5f6f7f8f9")).derive(ikm)
        self.assertEqual(okm.hex(), "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865")


class TwoKeyLock(unittest.TestCase):
    def test_needs_both_S_and_R(self):
        S, R = os.urandom(32), os.urandom(32)
        k = P.release_kek(S, R, "v_1")
        self.assertNotEqual(k, P.release_kek(os.urandom(32), R, "v_1"))
        self.assertNotEqual(k, P.release_kek(S, os.urandom(32), "v_1"))
        self.assertNotEqual(k, P.release_kek(S, R, "v_2"))

    def test_lengths_enforced(self):
        with self.assertRaises(ValueError):
            P.release_kek(b"short", os.urandom(32), "v")

    def test_commitment_binds_vault_and_share(self):
        c = P.share_commitment("v_1", b"\x01abc")
        self.assertNotEqual(c, P.share_commitment("v_2", b"\x01abc"))
        self.assertNotEqual(c, P.share_commitment("v_1", b"\x01abd"))
        self.assertEqual(len(c), 64)


class Padding(unittest.TestCase):
    def test_sizes_are_buckets(self):
        for n in [0, 1, 100, 4091, 4092, 4093, 10000, 65531, 65532, 65533, 300000]:
            with self.subTest(n=n):
                p = P.pad(os.urandom(n))
                block = 4096 if n + 4 <= 65536 else 65536
                self.assertEqual(len(p) % block, 0)
                self.assertGreaterEqual(len(p), n + 4)
                self.assertEqual(len(P.unpad(p)), n)

    def test_small_contents_indistinguishable_by_size(self):
        self.assertEqual(len(P.pad(b"a")), len(P.pad(b"a" * 3000)))

    def test_tampered_padding_rejected(self):
        p = bytearray(P.pad(b"salam"))
        p[-1] = 1
        with self.assertRaises(P.CryptoError):
            P.unpad(bytes(p))
        with self.assertRaises(P.CryptoError):
            P.unpad(b"\xff\xff\xff\xff" + b"\x00" * 10)


class Ecies(unittest.TestCase):
    def setUp(self):
        self.priv = P.generate_keypair()
        self.pub = P.public_raw(self.priv)

    def test_roundtrip(self):
        box = P.ecies_encrypt(self.pub, b"hisse", "ctx")
        self.assertEqual(P.ecies_decrypt(self.priv, box, "ctx"), b"hisse")

    def test_context_binding(self):
        box = P.ecies_encrypt(self.pub, b"hisse", P.ctx_share("v_1", "u_a", 1))
        for other in (P.ctx_share("v_2", "u_a", 1), P.ctx_share("v_1", "u_b", 1), P.ctx_share("v_1", "u_a", 2)):
            with self.subTest(other=other), self.assertRaises(P.CryptoError):
                P.ecies_decrypt(self.priv, box, other)

    def test_wrong_recipient(self):
        box = P.ecies_encrypt(self.pub, b"hisse", "ctx")
        with self.assertRaises(P.CryptoError):
            P.ecies_decrypt(P.generate_keypair(), box, "ctx")

    def test_ephemeral_key_fresh_each_time(self):
        a = P.ecies_encrypt(self.pub, b"x", "c")
        b = P.ecies_encrypt(self.pub, b"x", "c")
        self.assertNotEqual(a["epk"], b["epk"])
        self.assertNotEqual(a["ct"], b["ct"])

    def test_invalid_curve_point_rejected(self):
        bad = b"\x04" + b"\x01" * 64     # əyri üzərində olmayan nöqtə
        with self.assertRaises(P.CryptoError):
            P.load_public(bad)
        with self.assertRaises(P.CryptoError):
            P.load_public(b"\x02" + b"\x01" * 32)   # sıxılmış format qəbul edilmir

    def test_tampered_epk(self):
        box = P.ecies_encrypt(self.pub, b"x", "c")
        box["epk"] = P.b64u(P.public_raw(P.generate_keypair()))
        with self.assertRaises(P.CryptoError):
            P.ecies_decrypt(self.priv, box, "c")

    def test_fingerprint_format_and_uniqueness(self):
        fp = P.fingerprint(self.pub)
        self.assertRegex(fp, r"^([0-9A-F]{4} ){7}[0-9A-F]{4}$")
        self.assertNotEqual(fp, P.fingerprint(P.public_raw(P.generate_keypair())))


class RecoveryCode(unittest.TestCase):
    def test_format_and_entropy(self):
        codes = {P.new_recovery_code() for _ in range(500)}
        self.assertEqual(len(codes), 500)
        for c in list(codes)[:20]:
            self.assertRegex(c, r"^[A-HJ-NP-Z2-9]{5}(-[A-HJ-NP-Z2-9]{5}){4}$")

    def test_normalization(self):
        c = P.new_recovery_code()
        self.assertEqual(P.recovery_keys(c), P.recovery_keys(c.lower().replace("-", " ")))

    def test_invalid(self):
        for bad in ("", "ABCDE", "ABCDE-FGHJK-LMNPQ-RSTUV-WXYZ0", "ABCDE-FGHJK-LMNPQ-RSTUV-WXYZ22"):
            with self.subTest(bad=bad), self.assertRaises(P.CryptoError):
                P.recovery_keys(bad)

    def test_alphabet_unbiased(self):
        self.assertEqual(256 % len(P.RECOVERY_ALPHABET), 0)   # b % 32 bərabər paylanır


class Passwords(unittest.TestCase):
    def test_hash_verify(self):
        h = passwords.hash_password("auth-key-b64")
        self.assertTrue(passwords.verify_password("auth-key-b64", h))
        self.assertFalse(passwords.verify_password("auth-key-b65", h))
        self.assertTrue(h.startswith("$argon2id$v=19$m=19456,t=2,p=1$"))

    def test_unique_salts(self):
        self.assertNotEqual(passwords.hash_password("x"), passwords.hash_password("x"))

    def test_malformed_hash(self):
        self.assertFalse(passwords.verify_password("x", "garbage"))
        self.assertFalse(passwords.verify_password("x", "$bcrypt$a$b$c$d"))

    def test_needs_rehash(self):
        weak = passwords.hash_password("x", passwords.Argon2Params(memory_kib=8192, iterations=1))
        self.assertTrue(passwords.needs_rehash(weak))
        self.assertFalse(passwords.needs_rehash(passwords.hash_password("x")))


class Totp(unittest.TestCase):
    SECRET = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"   # RFC 6238 Əlavə B: "12345678901234567890"

    def test_rfc6238_vectors(self):
        for t, code in [(59, "94287082"), (1111111109, "07081804"), (1111111111, "14050471"),
                        (1234567890, "89005924"), (2000000000, "69279037"), (20000000000, "65353130")]:
            with self.subTest(t=t):
                self.assertEqual(totp.totp(self.SECRET, at=t, digits=8), code)

    def test_verify_window_and_replay(self):
        s = totp.generate_secret()
        code = totp.totp(s, at=1000)
        step = totp.verify(s, code, at=1000)
        self.assertIsNotNone(step)
        self.assertIsNone(totp.verify(s, code, at=1000, last_used_step=step))
        self.assertIsNotNone(totp.verify(s, code, at=1029))
        self.assertIsNone(totp.verify(s, code, at=1100))
        self.assertIsNone(totp.verify(s, "12345", at=1000))


class AuditChain(unittest.TestCase):
    def build(self, n=5, key=b"k" * 32):
        entries, prev = [], GENESIS
        for i in range(n):
            p = {"i": i, "action": "x"}
            h = link(key, prev, p)
            entries.append((prev, p, h))
            prev = h
        return entries

    def test_intact(self):
        self.assertEqual(verify_chain(b"k" * 32, self.build()), (True, None))

    def test_modified_deleted_reordered(self):
        e = self.build()
        mod = list(e); mod[2] = (mod[2][0], {"i": 2, "action": "y"}, mod[2][2])
        self.assertEqual(verify_chain(b"k" * 32, mod), (False, 2))
        dele = e[:2] + e[3:]
        self.assertEqual(verify_chain(b"k" * 32, dele), (False, 2))
        swap = [e[0], e[2], e[1]] + e[3:]
        self.assertEqual(verify_chain(b"k" * 32, swap), (False, 1))

    def test_wrong_key_cannot_forge(self):
        self.assertEqual(verify_chain(b"z" * 32, self.build()), (False, 0))


class HmacSanity(unittest.TestCase):
    def test_rfc4231_case2(self):
        h = chmac.HMAC(b"Jefe", hashes.SHA256())
        h.update(b"what do ya want for nothing?")
        self.assertEqual(h.finalize().hex(), "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843")


if __name__ == "__main__":
    unittest.main()
