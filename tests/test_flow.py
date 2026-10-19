"""Uçdan-uca ssenarilər (API səviyyəsində): seyfin bütün həyat dövrü."""
from __future__ import annotations

import unittest

from emanet.crypto import primitives as P
from tests.helpers import AppTestCase


class FullLifecycle(AppTestCase):
    def test_happy_path_2_of_3_release(self):
        owner, (a, b, c) = self.scenario(3, 2, {"items": [{"title": "Bank", "secret": "PIN 4821"}]})
        self.assertEqual(owner.get("/api/vault").get_json()["status"]["state"], "active")

        # 30 gün: xatırlatma; 60 gün: etibarlı şəxslər tələb edə bilər
        self.advance_days(31); self.tick()
        self.assertEqual(self.ctx.db.one("SELECT state FROM vaults")["state"], "reminding")
        self.advance_days(30); self.tick()
        self.assertEqual(self.ctx.db.one("SELECT state FROM vaults")["state"], "awaiting")

        self.keep_sessions_alive(a, b)
        a.approve(owner.vault_id)
        self.assertEqual(self.ctx.db.one("SELECT state FROM vaults")["state"], "awaiting")
        r = b.approve(owner.vault_id).get_json()
        self.assertEqual(r["state"], "pending_release")

        # Gözləmə müddəti (7 gün) bitmədən material verilmir
        b.material(owner.vault_id, expect=409)
        self.advance_days(7.01); self.tick()
        self.keep_sessions_alive(a, b)
        self.assertEqual(self.ctx.db.one("SELECT state FROM vaults")["state"], "released")

        # Bir hissə ilə açmaq olmur
        with self.assertRaises(P.CryptoError):
            a.open_vault(owner.vault_id)
        # B hissəsini A-ya ötürür → A açır
        b.hand_off(owner.vault_id)
        content = a.open_vault(owner.vault_id)
        self.assertEqual(content["items"][0]["secret"], "PIN 4821")

    def test_owner_checkin_cancels_pending_release(self):
        owner, (a, b, c) = self.scenario()
        self.advance_days(61); self.tick()
        self.keep_sessions_alive(a, b)
        a.approve(owner.vault_id); b.approve(owner.vault_id)
        self.assertEqual(self.ctx.db.one("SELECT state FROM vaults")["state"], "pending_release")
        self.advance_days(3)
        owner.login()   # giriş özü də aktivlikdir
        self.assertEqual(self.ctx.db.one("SELECT state FROM vaults")["state"], "active")
        self.assertEqual(self.ctx.db.one("SELECT COUNT(*) n FROM approvals")["n"], 0)
        self.advance_days(10); self.tick()
        self.assertNotEqual(self.ctx.db.one("SELECT state FROM vaults")["state"], "released")
        kinds = [r["kind"] for r in self.ctx.db.all("SELECT kind FROM outbox")]
        self.assertIn("release_cancelled", kinds)

    def test_email_link_checkin(self):
        owner, _ = self.scenario()
        self.advance_days(31); self.tick()
        body = self.ctx.db.one("SELECT body FROM outbox WHERE kind='reminder'")["body"]
        token = body.split("#t=")[1].split()[0]
        anon = self.person("Anon")
        r = anon.post("/api/checkin-link", {"token": token})
        self.assertEqual(r.status_code, 200, r.get_json())
        self.assertEqual(self.ctx.db.one("SELECT state FROM vaults")["state"], "active")
        # birdəfəlikdir
        self.assertEqual(anon.post("/api/checkin-link", {"token": token}).status_code, 400)

    def test_premature_approval_rejected_and_owner_notified(self):
        owner, (a, b, c) = self.scenario()
        a.approve(owner.vault_id, expect=409)
        self.assertEqual(self.ctx.db.one("SELECT COUNT(*) n FROM approvals")["n"], 0)
        self.assertEqual(self.ctx.db.one("SELECT COUNT(*) n FROM outbox WHERE kind='premature_attempt'")["n"], 1)
        self.assertEqual(self.ctx.db.one(
            "SELECT COUNT(*) n FROM security_events WHERE kind='premature_release_attempt'")["n"], 1)

    def test_recovery_code_restores_access(self):
        owner, _ = self.scenario()
        owner.password = "Yeni parol, tamamilə başqa 99"
        import os
        new_salt = os.urandom(16)
        old_salt = owner.salt
        rk = P.recovery_keys(owner.recovery_code)
        r = owner.post("/api/auth/recover/begin", {"email": owner.email, "recovery_auth": P.b64u(rk.auth_key)})
        self.assertEqual(r.status_code, 200)
        data = r.get_json()
        dek = P.open_sealed(rk.enc_key, data["wrapped_dek_recovery"], P.aad_dek(owner.vault_id, "recovery"))
        self.assertEqual(dek, owner.dek)
        owner.salt = new_salt
        new_code = P.new_recovery_code()
        nrk = P.recovery_keys(new_code)
        r = owner.post("/api/auth/recover/complete", {
            "email": owner.email, "recovery_auth": P.b64u(rk.auth_key), "kdf_salt": P.b64u(new_salt),
            "auth_key": P.b64u(owner.keys.auth_key), "wrapped_privkey": owner.wrapped_privkey(owner.keys.enc_key),
            "new_recovery_auth": P.b64u(nrk.auth_key),
            "new_wrapped_privkey_recovery": owner.wrapped_privkey(nrk.enc_key, "recovery"),
            "wrapped_dek_owner": P.seal(owner.keys.enc_key, dek, P.aad_dek(owner.vault_id, "owner")),
            "wrapped_dek_recovery": P.seal(nrk.enc_key, dek, P.aad_dek(owner.vault_id, "recovery")),
        })
        self.assertEqual(r.status_code, 200, r.get_json())
        owner.recovery_code = new_code
        owner.login()
        v = owner.get("/api/vault").get_json()
        self.assertEqual(P.open_sealed(owner.keys.enc_key, v["wrapped_dek_owner"], P.aad_dek(owner.vault_id, "owner")), dek)
        # köhnə bərpa kodu artıq işləmir
        self.assertEqual(owner.post("/api/auth/recover/begin",
                                    {"email": owner.email, "recovery_auth": P.b64u(rk.auth_key)}).status_code, 401)
        del old_salt

    def test_crypto_shredding(self):
        owner, (a, b, c) = self.scenario()
        r = owner.req("DELETE", "/api/vault", json={"confirm": "SİL"})
        self.assertEqual(r.status_code, 200)
        self.assertIsNone(self.ctx.db.one("SELECT * FROM vaults"))
        self.assertEqual(self.ctx.db.one("SELECT COUNT(*) n FROM trustees")["n"], 0)
        self.assertFalse(any((self.tmp / "objects" / "vaults").glob("*/*.json")))


if __name__ == "__main__":
    unittest.main()
