"""Brauzer (JS) ↔ server (Python) kriptoqrafik uyğunluğu — JS → Python istiqaməti.

Python → JS istiqaməti `tests/js/crossimpl.test.mjs`-dədir (vektorlar: scripts/gen_vectors.py).
"""
from __future__ import annotations

import itertools
import json
import pathlib
import shutil
import subprocess
import unittest

from cryptography.hazmat.primitives.serialization import load_der_private_key

from emanet.crypto import primitives as P
from emanet.crypto import shamir

ROOT = pathlib.Path(__file__).resolve().parents[1]


@unittest.skipIf(shutil.which("node") is None, "node yoxdur")
class JsToPython(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        out = subprocess.run(["node", "tests/js/emit_for_python.mjs"], cwd=ROOT, capture_output=True, text=True,
                             check=True, timeout=60)
        cls.d = json.loads(out.stdout)

    def shares(self):
        d = self.d
        res = []
        for t, s in zip(d["trustees"], d["dist"]["shares"]):
            priv = load_der_private_key(P.b64u_d(t["pkcs8"]), None)
            sb = P.ecies_decrypt(priv, s["box"], P.ctx_share(d["vaultId"], t["id"], s["x"]))
            self.assertEqual(P.share_commitment(d["vaultId"], sb), s["commitment"])
            res.append(shamir.Share.from_bytes(sb))
        return res

    def test_python_decrypts_js_ecies_shares(self):
        self.assertEqual(len(self.shares()), 3)

    def test_python_recovers_dek_from_any_two_js_shares(self):
        d = self.d
        for pair in itertools.combinations(self.shares(), 2):
            S = shamir.combine(pair)
            kek = P.release_kek(S, P.b64u_d(d["R"]), d["vaultId"])
            dek = P.open_sealed(kek, d["dist"]["wrappedDekRelease"], P.aad_dek(d["vaultId"], "release"))
            self.assertEqual(P.b64u(dek), d["dek"])

    def test_python_decrypts_js_vault(self):
        d = self.d
        pt = P.unpad(P.open_sealed(P.b64u_d(d["dek"]), d["box"], P.aad_vault(d["vaultId"], 7)))
        self.assertEqual(json.loads(pt), d["content"])
        self.assertEqual(len(P.b64u_d(d["box"]["ct"])) - 16, 4096)   # doldurulmuş ölçü

    def test_kdf_matches(self):
        mk = P.master_key("JS parolu — 2026", bytes([5]) * 16)
        self.assertEqual(P.b64u(mk), self.d["kdf"]["master"])
        k = P.derive_user_keys(mk)
        self.assertEqual(P.b64u(k.auth_key), self.d["kdf"]["auth"])
        self.assertEqual(P.b64u(k.enc_key), self.d["kdf"]["enc"])

    def test_fingerprint_matches(self):
        self.assertEqual(P.fingerprint(P.b64u_d(self.d["trustees"][0]["public_key"])), self.d["fingerprint"])

    def test_vectors_file_is_current(self):
        """vectors.json Python kodunun cari çıxışına uyğundur (deterministik hissələr)."""
        v = json.loads((ROOT / "tests/js/vectors.json").read_text())
        from scripts_gen import det_rng  # noqa: E402  (aşağıda sys.path-ə əlavə olunur)
        sh = shamir.split(bytes(range(32)), 5, 3, randbytes=det_rng(b"shamir-1"))
        self.assertEqual([P.b64u(s.to_bytes()) for s in sh], v["shamir"]["shares"])


def _load_gen():
    import importlib.util
    import sys
    spec = importlib.util.spec_from_file_location("scripts_gen", ROOT / "scripts" / "gen_vectors.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    sys.modules["scripts_gen"] = mod


_load_gen()
