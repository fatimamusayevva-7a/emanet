"""Seyf API-sinin biznes qaydaları: paylanma, versiyalar, parametrlər, açılma, ötürmə, bildirişlər."""
from __future__ import annotations

import json

from emanet.crypto import primitives as P
from tests.helpers import AppTestCase


def state(ctx):
    return ctx.db.one("SELECT state FROM vaults")["state"]


class VaultBasics(AppTestCase):
    def test_create_once(self):
        a = self.person("Aysel").signup()
        a.create_vault()
        r = a.post("/api/vault", {"vault_id": "v_" + "x" * 22, "wrapped_dek_owner": P.seal(a.dek, b"x", "a"),
                                  "wrapped_dek_recovery": P.seal(a.dek, b"x", "a")})
        self.assertEqual(r.status_code, 409)

    def test_release_key_returned_matches_kms(self):
        a = self.person("Aysel").signup()
        a.create_vault()
        R = P.b64u_d(a.get("/api/vault/release-key").get_json()["release_key"])
        self.assertEqual(R, a.release_key)
        self.assertEqual(self.ctx.db.one("SELECT COUNT(*) n FROM audit WHERE action='vault.release_key_read_by_owner'")["n"], 1)

    def test_content_versioning_and_conflict(self):
        a = self.person("Aysel").signup()
        a.create_vault({"items": [1]})
        a.save_content({"items": [1, 2]}, 2)
        r = a.save_content({"items": ["köhnə"]}, 2, expect=409)
        self.assertEqual(r.get_json()["current"], 2)
        a.save_content({"items": []}, 5, expect=409)
        got = a.get("/api/vault/content").get_json()
        self.assertEqual(got["version"], 2)
        pt = P.unpad(P.open_sealed(a.dek, got["box"], P.aad_vault(a.vault_id, 2)))
        self.assertEqual(json.loads(pt), {"items": [1, 2]})

    def test_old_versions_kept_in_storage(self):
        a = self.person("Aysel").signup()
        a.create_vault({"v": 1})
        a.save_content({"v": 2}, 2)
        files = sorted(p.name for p in (self.tmp / "objects" / "vaults" / a.vault_id).iterdir())
        self.assertEqual(files, ["v1.json", "v2.json"])

    def test_vault_too_large(self):
        a = self.person("Aysel").signup()
        a.create_vault()
        big = {"v": 1, "iv": P.b64u(b"0" * 12), "ct": "A" * (7 * 1024 * 1024)}
        r = a.req("PUT", "/api/vault/content", json={"version": 1, "box": big})
        self.assertEqual(r.status_code, 400)

    def test_settings_validation(self):
        a = self.person("Aysel").signup()
        a.create_vault()
        ok = a.req("PATCH", "/api/vault/settings", json={"checkin_interval_days": 14, "inactivity_days": 30, "waiting_days": 5})
        self.assertEqual(ok.status_code, 200)
        for bad in ({"checkin_interval_days": 3, "inactivity_days": 30, "waiting_days": 5},
                    {"checkin_interval_days": 30, "inactivity_days": 31, "waiting_days": 5},
                    {"checkin_interval_days": 30, "inactivity_days": 60, "waiting_days": 1}):
            with self.subTest(bad=bad):
                self.assertEqual(a.req("PATCH", "/api/vault/settings", json=bad).status_code, 400)

    def test_settings_locked_during_pending(self):
        owner, (a, b, c) = self.scenario()
        self.advance_days(61); self.tick()
        self.keep_sessions_alive(a, b)
        a.approve(owner.vault_id); b.approve(owner.vault_id)
        # parametr dəyişikliyi cəhdi — həm rədd olunur, həm də (aktivlik kimi) rədd olunmamalı deyil:
        r = owner.req("PATCH", "/api/vault/settings", json={"checkin_interval_days": 30, "inactivity_days": 365, "waiting_days": 30})
        self.assertEqual(r.status_code, 409)

    def test_pause(self):
        owner, (a, b, c) = self.scenario()
        owner.post("/api/vault/pause", {"days": 90})
        self.advance_days(89); self.tick()
        self.assertEqual(state(self.ctx), "active")
        self.advance_days(31); self.tick()
        self.assertEqual(state(self.ctx), "reminding")

    def test_delete_requires_confirmation(self):
        a = self.person("Aysel").signup()
        a.create_vault()
        self.assertEqual(a.req("DELETE", "/api/vault", json={}).status_code, 400)
        self.assertEqual(a.req("DELETE", "/api/vault", json={"confirm": "SIL"}).status_code, 400)


class TrusteesAndDistribution(AppTestCase):
    def test_cannot_invite_self_or_twice(self):
        a = self.person("Aysel").signup()
        a.create_vault()
        self.assertEqual(a.post("/api/vault/trustees", {"email": a.email}).status_code, 400)
        b = self.person("Rəşad").signup()
        a.invite(b)
        a.invite(b, expect=409)

    def test_max_seven(self):
        a = self.person("Aysel").signup()
        a.create_vault()
        for i in range(7):
            a.post("/api/vault/trustees", {"email": f"t{i}@example.az"})
        self.assertEqual(a.post("/api/vault/trustees", {"email": "t8@example.az"}).status_code, 400)

    def test_invite_before_registration_links_later(self):
        a = self.person("Aysel").signup()
        a.create_vault({"x": 1})
        a.post("/api/vault/trustees", {"email": "gelecek@example.az"})
        later = self.person("Gələcək", email="gelecek@example.az").signup()
        self.assertEqual(len(later.get("/api/trustee/invitations").get_json()["invitations"]), 1)

    def test_distribution_requires_verified_fingerprints(self):
        owner = self.person("Aysel").signup()
        owner.create_vault({"x": 1})
        ts = [self.person(n).signup() for n in ("Rəşad", "Nigar")]
        for t in ts:
            owner.invite(t); t.accept_all()
        body, _ = owner.build_distribution(2)
        r = owner.post("/api/vault/distribution", body)
        self.assertEqual((r.status_code, r.get_json()["error"]), (409, "unverified"))

    def test_wrong_fingerprint_rejected(self):
        owner = self.person("Aysel").signup()
        owner.create_vault({"x": 1})
        t = self.person("Rəşad").signup()
        owner.invite(t); t.accept_all()
        tid = owner.trustees()[0]["id"]
        r = owner.post(f"/api/vault/trustees/{tid}/verify", {"fingerprint": "0000 0000 0000 0000 0000 0000 0000 0000"})
        self.assertEqual(r.status_code, 400)
        self.assertEqual(self.ctx.db.one("SELECT COUNT(*) n FROM security_events WHERE kind='fingerprint_mismatch'")["n"], 1)

    def test_distribution_must_cover_all_trustees(self):
        owner, ts = self.scenario(3, 2)
        def drop(b): b["shares"].pop()
        body, _ = owner.build_distribution(2, tamper=drop)
        self.assertEqual(owner.post("/api/vault/distribution", body).get_json()["error"], "trustee_mismatch")

    def test_duplicate_x_rejected(self):
        owner, ts = self.scenario(3, 2)
        def dup(b): b["shares"][1]["x"] = b["shares"][0]["x"]
        body, _ = owner.build_distribution(2, tamper=dup)
        self.assertEqual(owner.post("/api/vault/distribution", body).get_json()["error"], "dup_x")

    def test_threshold_bounds(self):
        owner, ts = self.scenario(3, 2)
        body, _ = owner.build_distribution(2)
        body["threshold"] = 4
        self.assertEqual(owner.post("/api/vault/distribution", body).status_code, 400)
        body["threshold"] = 1
        self.assertEqual(owner.post("/api/vault/distribution", body).status_code, 400)

    def test_empty_vault_cannot_be_armed(self):
        owner = self.person("Aysel").signup()
        owner.create_vault()
        ts = [self.person(n).signup() for n in ("Rəşad", "Nigar")]
        for t in ts:
            owner.invite(t); t.accept_all()
        owner.verify_all()
        body, _ = owner.build_distribution(2)
        self.assertEqual(owner.post("/api/vault/distribution", body).get_json()["error"], "empty_vault")

    def test_removing_shareholder_disarms_vault(self):
        owner, (a, b, c) = self.scenario(3, 2)
        tid = owner.trustees()[0]["id"]
        r = owner.req("DELETE", f"/api/vault/trustees/{tid}")
        self.assertTrue(r.get_json()["redistribution_required"])
        self.assertEqual(state(self.ctx), "setup")
        self.assertEqual(self.ctx.db.one("SELECT COUNT(*) n FROM trustees WHERE share_box IS NOT NULL")["n"], 0)

    def test_redistribution_invalidates_old_shares(self):
        """Köhnə hissələr yeni paylanmadan sonra işə yaramır (S dəyişir)."""
        owner, (a, b, c) = self.scenario(3, 2)
        row = self.ctx.db.one("SELECT x, share_box FROM trustees WHERE user_id=?", (a.user_id,))
        old = P.ecies_decrypt(a.priv, json.loads(row["share_box"]), P.ctx_share(owner.vault_id, a.user_id, row["x"]))
        owner.distribute(2)
        self.advance_days(61); self.tick()
        self.keep_sessions_alive(a, b)
        a.approve(owner.vault_id); b.approve(owner.vault_id)
        self.advance_days(8); self.tick()
        self.keep_sessions_alive(a, b)
        m = a.material(owner.vault_id)
        new = a.my_share(m)
        self.assertNotEqual(old, new)
        self.assertNotIn(P.share_commitment(owner.vault_id, old), m["commitments"].values())

    def test_distribution_resets_approvals(self):
        owner, (a, b, c) = self.scenario(3, 2)
        self.advance_days(61); self.tick()
        self.keep_sessions_alive(a)
        a.approve(owner.vault_id)
        owner.login()
        owner.distribute(2)
        self.assertEqual(self.ctx.db.one("SELECT COUNT(*) n FROM approvals")["n"], 0)


class ReleaseFlow(AppTestCase):
    def release(self, n=3, t=2):
        owner, ts = self.scenario(n, t)
        self.advance_days(31); self.tick()
        self.advance_days(30); self.tick()
        self.keep_sessions_alive(*ts)
        for p in ts[:t]:
            p.approve(owner.vault_id)
        self.advance_days(7.1); self.tick()
        self.keep_sessions_alive(*ts)
        self.assertEqual(state(self.ctx), "released")
        return owner, ts

    def test_3_of_5(self):
        owner, ts = self.release(5, 3)
        ts[1].hand_off(owner.vault_id)
        with self.assertRaises(P.CryptoError):
            ts[0].open_vault(owner.vault_id)
        ts[4].hand_off(owner.vault_id)
        self.assertIn("PIN 4821", json.dumps(ts[0].open_vault(owner.vault_id), ensure_ascii=False))

    def test_non_approving_trustee_can_also_open(self):
        owner, (a, b, c) = self.release()
        a.hand_off(owner.vault_id)
        self.assertEqual(c.open_vault(owner.vault_id)["items"][0]["secret"], "PIN 4821")

    def test_material_requires_release(self):
        owner, (a, b, c) = self.scenario()
        a.material(owner.vault_id, expect=409)
        self.assertEqual(self.ctx.db.one(
            "SELECT COUNT(*) n FROM security_events WHERE kind='premature_material_request'")["n"], 1)

    def test_handoff_only_own_x_and_to_trustees(self):
        owner, (a, b, c) = self.release()
        m = a.material(owner.vault_id)
        sb = a.my_share(m)
        wrong_x = m["my_share"]["x"] % 3 + 1
        box = P.ecies_encrypt(b.pub, sb, P.ctx_handoff(owner.vault_id, a.user_id, b.user_id, wrong_x))
        r = a.post(f"/api/trustee/vaults/{owner.vault_id}/handoffs", {"items": [{"to_user": b.user_id, "x": wrong_x, "box": box}]})
        self.assertEqual(r.get_json()["error"], "wrong_x")
        r = a.post(f"/api/trustee/vaults/{owner.vault_id}/handoffs",
                   {"items": [{"to_user": owner.user_id, "x": m["my_share"]["x"], "box": box}]})
        self.assertEqual(r.get_json()["error"], "bad_recipient")

    def test_forged_share_detected_by_commitment(self):
        owner, (a, b, c) = self.release()
        m = b.material(owner.vault_id)
        x = m["my_share"]["x"]
        fake = bytes([x]) + b"\x00" * 32
        box = P.ecies_encrypt(a.pub, fake, P.ctx_handoff(owner.vault_id, b.user_id, a.user_id, x))
        b.post(f"/api/trustee/vaults/{owner.vault_id}/handoffs", {"items": [{"to_user": a.user_id, "x": x, "box": box}]})
        with self.assertRaises(P.CryptoError) as cm:
            a.open_vault(owner.vault_id)
        self.assertIn("saxta", str(cm.exception))

    def test_server_swapped_release_key_fails_closed(self):
        """Server (və ya DB-yə giriş əldə edən) R-i dəyişsə, açılma GCM teqi ilə uğursuz olur — səhv məlumat göstərilmir."""
        owner, (a, b, c) = self.release()
        b.hand_off(owner.vault_id)
        from emanet.kms import release_context
        _, ct = self.ctx.kms.generate_key(release_context(owner.vault_id))
        self.ctx.db.connect().execute("UPDATE vaults SET release_key_ct=?", (ct,))
        with self.assertRaises(P.CryptoError):
            a.open_vault(owner.vault_id)

    def test_released_vault_is_read_only(self):
        owner, ts = self.release()
        owner.login()
        owner.save_content({"x": 1}, 2, expect=409)
        self.assertEqual(state(self.ctx), "released")
        self.assertEqual(owner.get("/api/vault/release-key").status_code, 409)

    def test_withdraw_approval(self):
        owner, (a, b, c) = self.scenario()
        self.advance_days(61); self.tick()
        self.keep_sessions_alive(a, b)
        a.approve(owner.vault_id)
        a.req("DELETE", f"/api/trustee/vaults/{owner.vault_id}/approve")
        r = b.approve(owner.vault_id).get_json()
        self.assertEqual((r["state"], r["approvals"]), ("awaiting", 1))

    def test_removed_trustee_approval_does_not_count(self):
        owner, (a, b, c) = self.scenario()
        self.advance_days(61); self.tick()
        self.keep_sessions_alive(a)
        a.approve(owner.vault_id)
        self.assertEqual(self.ctx.db.one("SELECT COUNT(*) n FROM approvals")["n"], 1)

    def test_lazy_evaluation_without_scheduler(self):
        """Planlaşdırıcı işləməsə də, oxuma zamanı vəziyyət düzgün hesablanır (dayanıqlıq)."""
        owner, (a, b, c) = self.scenario()
        self.advance_days(61)
        self.keep_sessions_alive(a)
        v = a.get("/api/trustee/vaults").get_json()["vaults"][0]
        self.assertEqual(v["state"], "awaiting")

    def test_notifications_sequence(self):
        owner, ts = self.release()
        kinds = [r["kind"] for r in self.ctx.db.all("SELECT kind FROM outbox WHERE to_email=? ORDER BY id", (owner.email,))]
        self.assertEqual(kinds[0], "welcome")
        for k in ("reminder", "final_warning", "release_pending", "released_owner"):
            self.assertIn(k, kinds)
        tk = [r["kind"] for r in self.ctx.db.all("SELECT kind FROM outbox WHERE to_email=?", (ts[0].email,))]
        for k in ("trustee_invited", "trustees_may_request", "release_pending_trustee", "released"):
            self.assertIn(k, tk)

    def test_emails_never_contain_secrets(self):
        owner, ts = self.release()
        bodies = " ".join(r["subject"] + r["body"] for r in self.ctx.db.all("SELECT * FROM outbox"))
        self.assertNotIn("PIN 4821", bodies)
        self.assertNotIn(P.b64u(owner.release_key), bodies)

    def test_activity_log_visible_to_owner(self):
        owner, ts = self.release()
        ts[0].material(owner.vault_id)
        owner.login()
        actions = [e["action"] for e in owner.get("/api/vault/activity").get_json()["events"]]
        for a in ("vault.created", "vault.distributed", "release.approved", "release.material_fetched"):
            self.assertIn(a, actions)


class OperatorCannotCauseRelease(AppTestCase):
    """R-26: operator sahibin hesabını dayandırmaqla seyfin açılmasına səbəb ola bilməz."""

    def test_suspended_owner_vault_is_frozen(self):
        owner, (a, b, c) = self.scenario()
        op = self.person("Operator").signup()
        self.ctx.db.connect().execute("UPDATE users SET role='operator' WHERE id=?", (op.user_id,))
        op.login()
        self.assertEqual(op.post(f"/api/admin/users/{owner.user_id}/status", {"status": "suspended"}).status_code, 200)
        self.advance_days(200); self.tick()
        self.assertEqual(state(self.ctx), "active")
        self.keep_sessions_alive(a, b, op)
        a.approve(owner.vault_id, expect=409)
        op.post(f"/api/admin/users/{owner.user_id}/status", {"status": "active"})
        self.tick()
        self.assertEqual(state(self.ctx), "active")   # dondurma müddəti hərəkətsizlik sayılmadı


class Retention(AppTestCase):
    def test_released_vault_shredded_after_one_year(self):
        owner, ts = self.scenario()
        self.advance_days(31); self.tick(); self.advance_days(30); self.tick()
        self.keep_sessions_alive(*ts)
        ts[0].approve(owner.vault_id); ts[1].approve(owner.vault_id)
        self.advance_days(8); self.tick()
        self.assertEqual(state(self.ctx), "released")
        self.advance_days(364); self.tick()
        self.assertIsNotNone(self.ctx.db.one("SELECT id FROM vaults"))
        self.advance_days(2); self.tick()
        self.assertIsNone(self.ctx.db.one("SELECT id FROM vaults"))
        self.assertEqual(self.ctx.db.one("SELECT COUNT(*) n FROM audit WHERE action='vault.shredded'")["n"], 1)

    def test_old_sent_mail_purged(self):
        self.person("Aysel").signup()
        self.tick()
        self.advance_days(91); self.tick()
        self.assertEqual(self.ctx.db.one("SELECT COUNT(*) n FROM outbox")["n"], 0)
