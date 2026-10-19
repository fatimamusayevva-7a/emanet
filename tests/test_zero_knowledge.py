"""Sıfır bilik iddiasının sübutu: tam ssenaridən sonra serverin bütün diskini skan edirik.

Axtarılanlar (açıq mətn və onların base64/hex formaları):
  seyfin məzmunu, istifadəçi parolu, enc_key, DEK, Shamir sirri S, hər açıq hissə, bərpa kodu.
Tapılmamalı olanlar DB faylında (WAL daxil), obyekt anbarında və loglarda yoxdur.
"""
from __future__ import annotations

import base64
import json
import pathlib

from emanet.crypto import primitives as P
from tests.helpers import AppTestCase

SECRET_TEXT = "Xüsusi-Gizli-Söz-ZK-7731"


def forms(b: bytes) -> list[bytes]:
    return [b, b.hex().encode(), base64.b64encode(b).rstrip(b"="), P.b64u(b).encode()]


class ZeroKnowledge(AppTestCase):
    def test_server_disk_contains_no_plaintext_secrets(self):
        owner, (a, b, c) = self.scenario(3, 2, {"items": [{"title": "Kripto cüzdan", "secret": SECRET_TEXT}],
                                                 "letter": "Gizli məktub mətni ZK"})
        S = owner.distribute(2)
        shares = []
        for t in (a, b, c):
            row = self.ctx.db.one("SELECT x, share_box FROM trustees WHERE user_id=?", (t.user_id,))
            shares.append(P.ecies_decrypt(t.priv, json.loads(row["share_box"]), P.ctx_share(owner.vault_id, t.user_id, row["x"])))

        needles = {
            "content": [SECRET_TEXT.encode(), "Gizli məktub mətni ZK".encode()],
            "password": [owner.password.encode()],
            "enc_key": forms(owner.keys.enc_key),
            "auth_key": forms(owner.keys.auth_key),
            "dek": forms(owner.dek),
            "S": forms(S),
            "recovery": [owner.recovery_code.encode(), owner.recovery_code.replace("-", "").encode()],
        }
        for i, sh in enumerate(shares):
            needles[f"share{i}"] = forms(sh)

        self.ctx.db.connect().execute("PRAGMA wal_checkpoint(FULL)")
        files = [p for p in pathlib.Path(self.tmp).rglob("*") if p.is_file()]
        self.assertTrue(any(p.name == "emanet.db" for p in files))
        blobs = {p: p.read_bytes() for p in files}
        for label, ns in needles.items():
            for n in ns:
                for p, data in blobs.items():
                    self.assertNotIn(n, data, f"{label} {p.name} faylında tapıldı")

    def test_release_key_alone_cannot_open(self):
        """R (server tərəfi) + şifrəli seyf olsa belə, S olmadan DEK açılmır."""
        owner, _ = self.scenario()
        v = self.ctx.db.one("SELECT * FROM vaults")
        from emanet.kms import release_context
        R = self.ctx.kms.decrypt(v["release_key_ct"], release_context(v["id"]))
        import os
        for _ in range(200):
            kek = P.release_kek(os.urandom(32), R, v["id"])
            with self.assertRaises(P.CryptoError):
                P.open_sealed(kek, json.loads(v["wrapped_dek_release"]), P.aad_dek(v["id"], "release"))

    def test_colluding_trustees_without_R_cannot_open(self):
        """Bütün etibarlı şəxslər vaxtından əvvəl birləşsə belə, R olmadan seyf açılmır."""
        owner, (a, b, c) = self.scenario()
        S = owner.distribute(2)
        v = self.ctx.db.one("SELECT * FROM vaults")
        import os
        kek = P.release_kek(S, os.urandom(32), v["id"])
        with self.assertRaises(P.CryptoError):
            P.open_sealed(kek, json.loads(v["wrapped_dek_release"]), P.aad_dek(v["id"], "release"))
        # düzgün R ilə isə açılır — deməli iki açarın hər biri zəruridir
        kek_ok = P.release_kek(S, owner.release_key, v["id"])
        self.assertEqual(P.open_sealed(kek_ok, json.loads(v["wrapped_dek_release"]), P.aad_dek(v["id"], "release")), owner.dek)

    def test_db_dump_has_only_wrapped_keys(self):
        owner, _ = self.scenario()
        v = dict(self.ctx.db.one("SELECT * FROM vaults"))
        for col in ("wrapped_dek_owner", "wrapped_dek_recovery", "wrapped_dek_release"):
            box = json.loads(v[col])
            self.assertEqual(set(box), {"v", "iv", "ct"})
        self.assertTrue(v["release_key_ct"].startswith("lk1:"))
