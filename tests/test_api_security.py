"""API təhlükəsizliyi: autentifikasiya, sessiya, CSRF, BOLA, mass assignment, rate limit, vəzifə bölgüsü."""
from __future__ import annotations

import json
import os
import secrets

from emanet.crypto import primitives as P
from emanet.crypto import totp
from tests.helpers import ORIGIN, AppTestCase


class Authentication(AppTestCase):
    def test_register_login_me(self):
        a = self.person("Aysel").signup()
        me = a.get("/api/me").get_json()
        self.assertEqual(me["user"]["email"], a.email)
        self.assertEqual(me["user"]["fingerprint"], P.fingerprint(a.pub))

    def test_server_never_receives_password(self):
        a = self.person("Aysel")
        a.register()
        row = self.ctx.db.one("SELECT * FROM users")
        blob = json.dumps(dict(row))
        self.assertNotIn(a.password, blob)
        self.assertNotIn(P.b64u(a.keys.auth_key), blob)    # auth_key də açıq saxlanılmır (Argon2id)
        self.assertNotIn(P.b64u(a.keys.enc_key), blob)
        self.assertTrue(row["auth_hash"].startswith("$argon2id$"))

    def test_wrong_password(self):
        a = self.person("Aysel")
        a.register()
        a.login(expect=401, auth_key=os.urandom(32))

    def test_unknown_user_same_error(self):
        a = self.person("Yox")
        r = a.login(expect=401)
        self.assertEqual(r.get_json()["error"], "bad_credentials")

    def test_prelogin_does_not_reveal_existence(self):
        a = self.person("Aysel")
        a.register()
        real = a.post("/api/auth/prelogin", {"email": a.email}).get_json()
        fake1 = a.post("/api/auth/prelogin", {"email": "yoxdur@example.az"}).get_json()
        fake2 = a.post("/api/auth/prelogin", {"email": "yoxdur@example.az"}).get_json()
        self.assertEqual(set(real), set(fake1))
        self.assertEqual(fake1, fake2)                         # sabit — təkrar sorğu ilə fərqlənmir
        self.assertEqual(len(P.b64u_d(fake1["kdf_salt"])), 16)

    def test_duplicate_email(self):
        a = self.person("Aysel")
        a.register()
        b = self.person("Aysel2", email=a.email)
        b.register(expect=409)

    def test_invalid_public_key_rejected(self):
        a = self.person("Aysel")
        a.pub = b"\x04" + b"\x01" * 64
        a.register(expect=400)

    def test_lockout_after_10_failures(self):
        a = self.person("Aysel")
        a.register()
        for _ in range(10):
            a.login(expect=401, auth_key=os.urandom(32))
        a.login(expect=423)
        self.assertEqual(self.ctx.db.one("SELECT COUNT(*) n FROM security_events WHERE kind='account_locked'")["n"], 1)
        self.assertEqual(self.ctx.db.one("SELECT COUNT(*) n FROM outbox WHERE kind='account_locked'")["n"], 1)

    def test_mfa_flow(self):
        a = self.person("Aysel").signup()
        secret = a.post("/api/mfa/setup").get_json()["secret"]
        self.assertEqual(a.post("/api/mfa/enable", {"code": "000000"}).status_code, 400)
        code = totp.totp(secret, at=self.clock.now())
        self.assertEqual(a.post("/api/mfa/enable", {"code": code}).status_code, 200)
        a.csrf = None
        r = a.login(expect=401)
        self.assertEqual(r.get_json()["error"], "mfa_required")
        self.clock.advance(60)
        a.login(totp=totp.totp(secret, at=self.clock.now()))
        # eyni kod ikinci dəfə (replay) keçmir
        a.login(expect=401, totp=totp.totp(secret, at=self.clock.now()))

    def test_password_change_revokes_other_sessions(self):
        a = self.person("Aysel").signup()
        other = a.app.test_client()
        r = other.post("/api/auth/login", json={"email": a.email, "auth_key": P.b64u(a.keys.auth_key)},
                       headers={"Origin": ORIGIN}, base_url="https://emanet.test")
        self.assertEqual(r.status_code, 200)
        old_auth = a.keys.auth_key
        a.password = "Tamamilə yeni parol 2027!"
        a.salt = os.urandom(16)
        r = a.post("/api/auth/password", {"current_auth_key": P.b64u(old_auth), "kdf_salt": P.b64u(a.salt),
                                          "auth_key": P.b64u(a.keys.auth_key),
                                          "wrapped_privkey": a.wrapped_privkey(a.keys.enc_key)})
        self.assertEqual(r.status_code, 200)
        self.assertEqual(other.get("/api/me", base_url="https://emanet.test").status_code, 401)
        a.csrf = None
        a.login()

    def test_logout(self):
        a = self.person("Aysel").signup()
        a.post("/api/auth/logout")
        self.assertEqual(a.get("/api/me").status_code, 401)

    def test_session_probe_always_200(self):
        a = self.person("Anon")
        r = a.get("/api/session")
        self.assertEqual((r.status_code, r.get_json()), (200, {"authenticated": False}))


class Sessions(AppTestCase):
    def test_cookie_flags(self):
        a = self.person("Aysel")
        a.register()
        r = a.login()
        cookies = r.headers.getlist("Set-Cookie")
        sess = next(c for c in cookies if c.startswith("__Host-emanet_session="))
        for flag in ("HttpOnly", "Secure", "SameSite=Strict", "Path=/"):
            self.assertIn(flag, sess)
        self.assertNotIn("Domain=", sess)
        csrf = next(c for c in cookies if c.startswith("__Host-emanet_csrf="))
        self.assertNotIn("HttpOnly", csrf)

    def test_db_stores_only_token_hash(self):
        a = self.person("Aysel").signup()
        token = a.client.get_cookie("__Host-emanet_session", domain="emanet.test").value
        rows = [dict(r) for r in self.ctx.db.all("SELECT * FROM sessions")]
        self.assertNotIn(token, json.dumps(rows))

    def test_idle_timeout(self):
        import time
        a = self.person("Aysel").signup()
        self.ctx.db.connect().execute("UPDATE sessions SET last_seen=?", (time.time() - 31 * 60,))
        self.assertEqual(a.get("/api/me").status_code, 401)

    def test_absolute_timeout(self):
        import time
        a = self.person("Aysel").signup()
        self.ctx.db.connect().execute("UPDATE sessions SET created_at=?, last_seen=?", (time.time() - 13 * 3600, time.time()))
        self.assertEqual(a.get("/api/me").status_code, 401)

    def test_suspended_user_session_dies(self):
        a = self.person("Aysel").signup()
        self.ctx.db.connect().execute("UPDATE users SET status='suspended'")
        self.assertEqual(a.get("/api/me").status_code, 401)

    def test_forged_cookie(self):
        a = self.person("Aysel").signup()
        a.client.set_cookie("__Host-emanet_session", secrets.token_urlsafe(32), domain="emanet.test", secure=True)
        self.assertEqual(a.get("/api/me").status_code, 401)


class Csrf(AppTestCase):
    def test_missing_token(self):
        a = self.person("Aysel").signup()
        a.csrf = None
        r = a.post("/api/vault/checkin")
        self.assertEqual((r.status_code, r.get_json()["error"]), (403, "csrf_token"))

    def test_wrong_token(self):
        a = self.person("Aysel").signup()
        a.csrf = "x" * 43
        self.assertEqual(a.post("/api/vault/checkin").status_code, 403)

    def test_foreign_origin(self):
        a = self.person("Aysel").signup()
        r = a.post("/api/vault/checkin", headers={"Origin": "https://evil.example"})
        self.assertEqual((r.status_code, r.get_json()["error"]), (403, "csrf_origin"))

    def test_foreign_referer(self):
        a = self.person("Aysel").signup()
        r = a.client.post("/api/vault/checkin", json={}, base_url="https://emanet.test",
                          headers={"Referer": "https://evil.example/page", "X-CSRF-Token": a.csrf})
        self.assertEqual(r.status_code, 403)

    def test_cross_site_fetch_metadata(self):
        a = self.person("Aysel").signup()
        r = a.client.post("/api/vault/checkin", json={}, base_url="https://emanet.test",
                          headers={"Sec-Fetch-Site": "cross-site", "X-CSRF-Token": a.csrf})
        self.assertEqual(r.status_code, 403)

    def test_public_endpoints_check_origin(self):
        a = self.person("Aysel")
        r = a.post("/api/auth/prelogin", {"email": "a@b.az"}, headers={"Origin": "https://evil.example"})
        self.assertEqual(r.status_code, 403)

    def test_get_does_not_need_token(self):
        a = self.person("Aysel").signup()
        a.csrf = None
        self.assertEqual(a.get("/api/me").status_code, 200)


class InputValidation(AppTestCase):
    def test_mass_assignment_rejected_and_logged(self):
        a = self.person("Aysel")
        rk = P.recovery_keys(a.recovery_code)
        body = {"user_id": a.user_id, "email": a.email, "display_name": "A", "role": "operator",
                "kdf_salt": P.b64u(a.salt), "auth_key": P.b64u(a.keys.auth_key), "public_key": P.b64u(a.pub),
                "wrapped_privkey": a.wrapped_privkey(a.keys.enc_key), "recovery_auth": P.b64u(rk.auth_key),
                "wrapped_privkey_recovery": a.wrapped_privkey(rk.enc_key, "recovery")}
        r = a.post("/api/auth/register", body)
        self.assertEqual(r.status_code, 400)
        self.assertIn("role", r.get_json()["message"])
        self.assertIsNone(self.ctx.db.one("SELECT * FROM users"))
        self.assertEqual(self.ctx.db.one(
            "SELECT COUNT(*) n FROM security_events WHERE kind='mass_assignment_attempt'")["n"], 1)

    def test_nested_unknown_field(self):
        a = self.person("Aysel").signup()
        a.create_vault({"items": []})
        box = P.seal(a.dek, P.pad(b"{}"), P.aad_vault(a.vault_id, 2))
        box["extra"] = 1
        r = a.req("PUT", "/api/vault/content", json={"version": 2, "box": box})
        self.assertEqual(r.status_code, 400)

    def test_type_confusion(self):
        a = self.person("Aysel").signup()
        a.create_vault()
        for bad in ({"days": "5"}, {"days": True}, {"days": 5.5}, {"days": -1}, {"days": 91}, []):
            with self.subTest(bad=bad):
                self.assertEqual(a.post("/api/vault/pause", bad).status_code, 400)

    def test_non_json_rejected(self):
        a = self.person("Aysel").signup()
        r = a.client.post("/api/vault/checkin", data="x=1", content_type="application/x-www-form-urlencoded",
                          base_url="https://emanet.test", headers={"Origin": ORIGIN, "X-CSRF-Token": a.csrf})
        self.assertEqual(r.status_code, 415)

    def test_body_too_large(self):
        a = self.person("Aysel")
        r = a.client.post("/api/auth/prelogin", data=b"{" + b" " * (9 * 1024 * 1024) + b"}",
                          content_type="application/json", base_url="https://emanet.test", headers={"Origin": ORIGIN})
        self.assertEqual(r.status_code, 413)

    def test_bad_email(self):
        a = self.person("Aysel", email="not-an-email")
        a.register(expect=400)

    def test_control_chars_in_name(self):
        a = self.person("Ay\x00sel")
        a.register(expect=400)

    def test_errors_do_not_leak_internals(self):
        a = self.person("Aysel")
        r = a.post("/api/auth/prelogin", {"email": 123})
        body = json.dumps(r.get_json())
        for leak in ("Traceback", "sqlite", "File \"", "/home/"):
            self.assertNotIn(leak, body)


class ObjectLevelAuthorization(AppTestCase):
    def test_outsider_cannot_see_or_approve(self):
        owner, (a, b, c) = self.scenario()
        eve = self.person("Eve").signup()
        for path in (f"/api/trustee/vaults/{owner.vault_id}/release",):
            self.assertEqual(eve.get(path).status_code, 404)
        self.assertEqual(eve.post(f"/api/trustee/vaults/{owner.vault_id}/approve").status_code, 404)
        self.assertEqual(eve.post(f"/api/trustee/vaults/{owner.vault_id}/handoffs",
                                  {"items": [{"to_user": a.user_id, "x": 1, "box": {"v": 1, "epk": P.b64u(eve.pub),
                                                                                   "iv": P.b64u(b"0" * 12), "ct": "AAAA"}}]}).status_code, 404)
        self.assertGreaterEqual(self.ctx.db.one("SELECT COUNT(*) n FROM security_events WHERE kind='bola_denied'")["n"], 2)

    def test_vault_endpoints_scope_to_session_user(self):
        owner, (a, b, c) = self.scenario()
        # a-nın öz seyfi yoxdur → 404; owner-in seyfinə URL ilə çatmaq imkanı yoxdur
        self.assertEqual(a.get("/api/vault").status_code, 404)
        self.assertEqual(a.get("/api/vault/content").status_code, 404)
        self.assertEqual(a.get("/api/vault/release-key").status_code, 404)

    def test_owner_cannot_delete_foreign_trustee_row(self):
        owner, (a, b, c) = self.scenario()
        other = self.person("Other").signup()
        other.create_vault({"items": []})
        tid = owner.trustees()[0]["id"]
        self.assertEqual(other.req("DELETE", f"/api/vault/trustees/{tid}").status_code, 404)

    def test_declined_trustee_has_no_access(self):
        owner = self.person("Aysel").signup()
        owner.create_vault({"items": []})
        t = self.person("Rəşad").signup()
        owner.invite(t)
        inv = t.get("/api/trustee/invitations").get_json()["invitations"][0]
        t.post(f"/api/trustee/invitations/{inv['id']}/decline")
        self.assertEqual(t.get("/api/trustee/vaults").get_json()["vaults"], [])

    def test_trustee_cannot_answer_others_invitation(self):
        owner = self.person("Aysel").signup()
        owner.create_vault({"items": []})
        t = self.person("Rəşad").signup()
        eve = self.person("Eve").signup()
        owner.invite(t)
        inv = t.get("/api/trustee/invitations").get_json()["invitations"][0]
        self.assertEqual(eve.post(f"/api/trustee/invitations/{inv['id']}/accept").status_code, 404)

    def test_trustee_view_hides_owner_activity(self):
        owner, (a, b, c) = self.scenario()
        v = a.get("/api/trustee/vaults").get_json()["vaults"][0]
        for hidden in ("last_activity_at", "blob_size", "version", "paused_until", "days_until_awaiting"):
            self.assertNotIn(hidden, v)

    def test_invalid_vault_id_format(self):
        a = self.person("Aysel").signup()
        self.assertIn(a.post("/api/trustee/vaults/../../etc/approve").status_code, (404, 405))
        self.assertEqual(a.post("/api/trustee/vaults/v_'%20OR%201=1/approve").status_code, 400)


class SeparationOfDuties(AppTestCase):
    def setUp(self):
        super().setUp()
        self.op = self.person("Operator").signup()
        self.ctx.db.connect().execute("UPDATE users SET role='operator' WHERE id=?", (self.op.user_id,))
        self.aud = self.person("Auditor").signup()
        self.ctx.db.connect().execute("UPDATE users SET role='auditor' WHERE id=?", (self.aud.user_id,))
        self.usr = self.person("User").signup()

    def test_operator_cannot_read_audit(self):
        self.assertEqual(self.op.get("/api/audit").status_code, 403)
        self.assertEqual(self.op.get("/api/audit/verify").status_code, 403)

    def test_auditor_cannot_manage_users(self):
        self.assertEqual(self.aud.get("/api/admin/users").status_code, 403)
        self.assertEqual(self.aud.post(f"/api/admin/users/{self.usr.user_id}/status", {"status": "suspended"}).status_code, 403)

    def test_user_cannot_use_admin(self):
        self.assertEqual(self.usr.get("/api/admin/users").status_code, 403)
        self.assertEqual(self.ctx.db.one("SELECT COUNT(*) n FROM security_events WHERE kind='forbidden_role'")["n"], 1)

    def test_operator_cannot_change_own_role(self):
        self.assertEqual(self.op.post(f"/api/admin/users/{self.op.user_id}/role", {"role": "auditor"}).status_code, 409)

    def test_last_operator_protected(self):
        op2 = self.person("Op2").signup()
        self.ctx.db.connect().execute("UPDATE users SET role='operator' WHERE id=?", (op2.user_id,))
        self.assertEqual(self.op.post(f"/api/admin/users/{op2.user_id}/role", {"role": "user"}).status_code, 200)
        self.ctx.db.connect().execute("UPDATE users SET role='operator' WHERE id=?", (op2.user_id,))
        self.ctx.db.connect().execute("UPDATE users SET status='suspended' WHERE id=?", (op2.user_id,))
        op2.login(expect=403)

    def test_role_change_revokes_sessions(self):
        self.op.post(f"/api/admin/users/{self.usr.user_id}/role", {"role": "auditor"})
        self.assertEqual(self.usr.get("/api/me").status_code, 401)

    def test_auditor_verifies_chain(self):
        r = self.aud.get("/api/audit/verify").get_json()
        self.assertTrue(r["intact"])
        self.assertGreater(r["entries"], 0)

    def test_no_endpoint_lets_operator_force_release(self):
        owner, _ = self.scenario()
        for path in ("/api/admin/release", f"/api/admin/vaults/{owner.vault_id}/release", "/api/admin/vaults"):
            self.assertIn(self.op.post(path).status_code, (404, 405))

    def test_demo_endpoints_absent_without_demo_mode(self):
        self.assertEqual(self.op.post("/api/demo/advance", {"days": 30}).status_code, 404)
        self.assertEqual(self.usr.get("/api/demo/outbox").status_code, 404)


class RateLimits(AppTestCase):
    def test_prelogin_limited(self):
        a = self.person("Aysel")
        codes = [a.post("/api/auth/prelogin", {"email": "x@y.az"}).status_code for _ in range(32)]
        self.assertEqual(codes[:30], [200] * 30)
        self.assertEqual(codes[-1], 429)

    def test_429_has_retry_after_and_event(self):
        a = self.person("Aysel")
        for _ in range(31):
            r = a.post("/api/auth/prelogin", {"email": "x@y.az"})
        self.assertEqual(r.status_code, 429)
        self.assertEqual(r.headers["Retry-After"], "60")
        self.assertGreaterEqual(self.ctx.db.one("SELECT COUNT(*) n FROM security_events WHERE kind='rate_limited'")["n"], 1)

    def test_recovery_bruteforce_limited(self):
        a = self.person("Aysel")
        a.register()
        codes = [a.post("/api/auth/recover/begin", {"email": a.email, "recovery_auth": P.b64u(os.urandom(32))}).status_code
                 for _ in range(6)]
        self.assertEqual(codes[:5], [401] * 5)
        self.assertEqual(codes[5], 429)


class SecurityHeaders(AppTestCase):
    def test_headers_on_api_and_static(self):
        a = self.person("Anon")
        for path in ("/api/health", "/", "/js/app.js", "/css/app.css"):
            with self.subTest(path=path):
                r = a.get(path)
                self.assertEqual(r.status_code, 200)
                h = r.headers
                self.assertIn("script-src 'self'", h["Content-Security-Policy"])
                self.assertIn("require-trusted-types-for 'script'", h["Content-Security-Policy"])
                self.assertIn("frame-ancestors 'none'", h["Content-Security-Policy"])
                self.assertNotIn("unsafe-inline", h["Content-Security-Policy"])
                self.assertEqual(h["X-Content-Type-Options"], "nosniff")
                self.assertEqual(h["X-Frame-Options"], "DENY")
                self.assertEqual(h["Referrer-Policy"], "no-referrer")
                self.assertEqual(h["Cross-Origin-Opener-Policy"], "same-origin")
                self.assertIn("max-age=63072000", h["Strict-Transport-Security"])
                self.assertTrue(h["X-Request-ID"])

    def test_api_not_cached(self):
        self.assertEqual(self.person("A").get("/api/health").headers["Cache-Control"], "no-store")

    def test_static_whitelist_and_traversal(self):
        a = self.person("Anon")
        for path in ("/emanet/app.py", "/../emanet/config.py", "/js/../../emanet/db.py", "/data/secrets.json",
                     "/tests/helpers.py", "/.git/config"):
            with self.subTest(path=path):
                self.assertEqual(a.get(path).status_code, 404)

    def test_no_inline_scripts_or_styles_in_html(self):
        import pathlib
        import re
        for f in (pathlib.Path(__file__).parents[1] / "web").glob("*.html"):
            html = f.read_text()
            self.assertIsNone(re.search(r"<script(?![^>]*\bsrc=)[^>]*>", html), f.name)
            self.assertNotIn("style=", html)
            self.assertNotIn("onclick=", html)

    def test_client_code_never_uses_innerhtml_or_storage(self):
        import pathlib
        import re
        for f in (pathlib.Path(__file__).parents[1] / "web" / "js").glob("*.js"):
            src = re.sub(r"//[^\n]*", "", f.read_text())        # şərhlər nəzərə alınmır
            for bad in ("innerHTML", "outerHTML", "insertAdjacentHTML", "document.write", "eval(", "new Function",
                        "localStorage", "sessionStorage", "indexedDB"):
                self.assertFalse(bad in src, f"{f.name}: {bad}")

    def test_integrity_manifest(self):
        r = self.person("Anon").get("/api/integrity").get_json()
        self.assertIn("js/crypto.js", r["files"])
        self.assertEqual(len(r["manifest_sha256"]), 64)
