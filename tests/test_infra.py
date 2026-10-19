"""KMS, obyekt anbarı, planlaşdırıcı, konfiqurasiya, audit jurnalı, CLI."""
from __future__ import annotations

import base64
import json
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile
import time
import unittest

from emanet import audit
from emanet.config import ConfigError, Settings, load_settings
from emanet.kms import AwsKMS, KMSError, LocalKMS, release_context
from emanet.security import sign_scheduler_request
from emanet.storage import LocalStorage, StorageError, object_key
from tests.helpers import TEST_SECRETS, AppTestCase

ROOT = pathlib.Path(__file__).resolve().parents[1]


class TmpDir(unittest.TestCase):
    def setUp(self):
        self.tmp = pathlib.Path(tempfile.mkdtemp())

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)


class LocalKmsTests(TmpDir):
    def kms(self, master=b"m" * 32):
        return LocalKMS(self.tmp / "keyring.json", master)

    def test_generate_and_decrypt(self):
        k = self.kms()
        pt, ct = k.generate_key(release_context("v_1"))
        self.assertEqual(len(pt), 32)
        self.assertEqual(k.decrypt(ct, release_context("v_1")), pt)

    def test_context_binding(self):
        k = self.kms()
        _, ct = k.generate_key(release_context("v_1"))
        with self.assertRaises(KMSError):
            k.decrypt(ct, release_context("v_2"))

    def test_rotation_keeps_old_decryptable_and_rewrap(self):
        k = self.kms()
        pt, ct = k.generate_key(release_context("v_1"))
        self.assertEqual(k.rotate(), 2)
        self.assertEqual(k.decrypt(ct, release_context("v_1")), pt)
        ct2 = k.rewrap(ct, release_context("v_1"))
        self.assertEqual(LocalKMS.version_of(ct2), 2)
        self.assertEqual(k.decrypt(ct2, release_context("v_1")), pt)

    def test_keyring_persisted_and_encrypted(self):
        k = self.kms()
        pt, ct = k.generate_key({"a": 1})
        raw = (self.tmp / "keyring.json").read_text()
        self.assertNotIn(k._ring["keys"]["1"], raw)
        self.assertEqual(self.kms().decrypt(ct, {"a": 1}), pt)
        if os.name != "nt":  # Windows POSIX icazələrini dəstəkləmir
            self.assertEqual(oct((self.tmp / "keyring.json").stat().st_mode & 0o777), "0o600")

    def test_wrong_master_key(self):
        self.kms()
        with self.assertRaises(KMSError):
            self.kms(b"x" * 32)

    def test_tampered_keyring(self):
        self.kms()
        blob = json.loads((self.tmp / "keyring.json").read_text())
        ct = bytearray(base64.b64decode(blob["ct"])); ct[0] ^= 1
        blob["ct"] = base64.b64encode(bytes(ct)).decode()
        (self.tmp / "keyring.json").write_text(json.dumps(blob))
        with self.assertRaises(KMSError):
            self.kms()

    def test_garbage_ciphertext(self):
        k = self.kms()
        for bad in ("", "lk1:1", "aws1:xx", "lk1:9:AAAA", "lk1:1:!!!"):
            with self.subTest(bad=bad), self.assertRaises(KMSError):
                k.decrypt(bad, {})

    def test_short_master(self):
        with self.assertRaises(KMSError):
            self.kms(b"short")


class FakeAwsKms:
    """boto3 KMS interfeysinin minimal imitasiyası — EncryptionContext-i həqiqətən yoxlayır."""

    def __init__(self):
        self.calls = []
        self.store = {}

    def generate_data_key(self, KeyId, KeySpec, EncryptionContext):
        self.calls.append(("generate", EncryptionContext))
        pt = os.urandom(32)
        blob = os.urandom(48)
        self.store[blob] = (pt, dict(EncryptionContext))
        return {"Plaintext": pt, "CiphertextBlob": blob}

    def decrypt(self, CiphertextBlob, KeyId, EncryptionContext):
        self.calls.append(("decrypt", EncryptionContext))
        pt, ctx = self.store[CiphertextBlob]
        if ctx != EncryptionContext:
            raise RuntimeError("InvalidCiphertextException")
        return {"Plaintext": pt}

    def re_encrypt(self, CiphertextBlob, SourceEncryptionContext, DestinationKeyId, DestinationEncryptionContext):
        pt, ctx = self.store[CiphertextBlob]
        blob = os.urandom(48)
        self.store[blob] = (pt, DestinationEncryptionContext)
        return {"CiphertextBlob": blob}


class AwsKmsTests(unittest.TestCase):
    def test_roundtrip_with_context(self):
        fake = FakeAwsKms()
        k = AwsKMS("arn:aws:kms:eu-central-1:111:key/abc", "eu-central-1", client=fake)
        pt, ct = k.generate_key(release_context("v_1"))
        self.assertTrue(ct.startswith("aws1:"))
        self.assertEqual(k.decrypt(ct, release_context("v_1")), pt)
        with self.assertRaises(KMSError):
            k.decrypt(ct, release_context("v_2"))
        self.assertEqual(fake.calls[0][1], {"vault_id": "v_1", "purpose": "release-key", "app": "emanet"})
        self.assertEqual(k.decrypt(k.rewrap(ct, release_context("v_1")), release_context("v_1")), pt)

    def test_requires_key_id(self):
        with self.assertRaises(KMSError):
            AwsKMS("", "eu-central-1", client=FakeAwsKms())

    def test_rejects_local_ciphertext(self):
        k = AwsKMS("k", "r", client=FakeAwsKms())
        with self.assertRaises(KMSError):
            k.decrypt("lk1:1:AAAA", {})


class StorageTests(TmpDir):
    def test_object_key_validation(self):
        self.assertEqual(object_key("v_abc", 3), "vaults/v_abc/v3.json")
        for vid, ver in (("../etc", 1), ("v/x", 1), ("v_ok", 0), ("v_ok", "1"), ("", 1)):
            with self.subTest(vid=vid, ver=ver), self.assertRaises(StorageError):
                object_key(vid, ver)

    def test_put_get_delete(self):
        s = LocalStorage(self.tmp)
        s.put("vaults/v_a/v1.json", {"x": 1})
        self.assertEqual(s.get("vaults/v_a/v1.json"), {"x": 1})
        s.delete_vault("v_a")
        with self.assertRaises(StorageError):
            s.get("vaults/v_a/v1.json")

    def test_traversal_blocked(self):
        s = LocalStorage(self.tmp)
        with self.assertRaises(StorageError):
            s.put("../../evil.json", {})
        with self.assertRaises(StorageError):
            s.delete_vault("../x")

    def test_file_permissions(self):
        s = LocalStorage(self.tmp)
        s.put("vaults/v_a/v1.json", {})
        if os.name != "nt":  # Windows POSIX icazələrini dəstəkləmir
            self.assertEqual(oct((self.tmp / "vaults/v_a/v1.json").stat().st_mode & 0o777), "0o600")


class ConfigTests(TmpDir):
    def prod(self, **kw):
        base = dict(env="production", data_dir=self.tmp, public_origin="https://emanet.az", cookie_secure=True,
                    kms_backend="aws", secrets=dict(TEST_SECRETS))
        base.update(kw)
        return load_settings(**base)

    def test_valid_production(self):
        self.assertTrue(self.prod().is_production)

    def test_production_rejects_unsafe(self):
        for kw in ({"demo_mode": True}, {"cookie_secure": False}, {"public_origin": "http://emanet.az"},
                   {"kms_backend": "local"}):
            with self.subTest(kw=kw), self.assertRaises(ConfigError):
                self.prod(**kw)

    def test_production_refuses_dev_secret_file(self):
        env = {k: v for k, v in os.environ.items() if not k.startswith("EMANET_")}
        r = subprocess.run([sys.executable, "-c", "from emanet.config import load_settings; load_settings()"],
                           cwd=ROOT, capture_output=True, text=True,
                           env={**env, "EMANET_ENV": "production", "EMANET_DATA_DIR": str(self.tmp)})
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("ConfigError", r.stderr)

    def test_short_secret_rejected(self):
        bad = dict(TEST_SECRETS); bad["audit_hmac_key"] = b"short"
        with self.assertRaises(ConfigError):
            load_settings(data_dir=self.tmp, secrets=bad)

    def test_dev_secrets_file_created_0600(self):
        s = load_settings(data_dir=self.tmp)
        self.assertEqual(len(s.secret("audit_hmac_key")), 32)
        if os.name != "nt":  # Windows POSIX icazələrini dəstəkləmir
            self.assertEqual(oct((self.tmp / "secrets.json").stat().st_mode & 0o777), "0o600")
        self.assertEqual(load_settings(data_dir=self.tmp).secrets, s.secrets)

    def test_env_secrets(self):
        env_keys = {f"EMANET_{k.upper()}": base64.b64encode(v).decode() for k, v in TEST_SECRETS.items()}
        old = dict(os.environ)
        try:
            os.environ.update(env_keys)
            s = load_settings(data_dir=self.tmp)
            self.assertEqual(s.secrets, TEST_SECRETS)
            self.assertFalse((self.tmp / "secrets.json").exists())
        finally:
            os.environ.clear(); os.environ.update(old)

    def test_settings_repr_hides_secrets(self):
        self.assertNotIn("secret_key", repr(Settings(secrets=dict(TEST_SECRETS))))


class Scheduler(AppTestCase):
    def call(self, ts=None, sig=None, body=b""):
        ts = int(time.time()) if ts is None else ts
        key = self.ctx.settings.secret("scheduler_hmac_key")
        sig = sig or sign_scheduler_request(key, "POST", "/internal/tick", ts, body)
        return self.app.test_client().post("/internal/tick", data=body, base_url="https://emanet.test",
                                           headers={"X-Emanet-Timestamp": str(ts), "X-Emanet-Signature": sig})

    def test_valid_signature(self):
        r = self.call()
        self.assertEqual(r.status_code, 200)
        self.assertIn("evaluated", r.get_json())

    def test_bad_signature(self):
        self.assertEqual(self.call(sig="0" * 64).status_code, 401)
        self.assertEqual(self.ctx.db.one("SELECT COUNT(*) n FROM security_events WHERE kind='scheduler_bad_signature'")["n"], 1)

    def test_expired_timestamp(self):
        self.assertEqual(self.call(ts=int(time.time()) - 3600).status_code, 401)

    def test_replay(self):
        ts = int(time.time())
        self.assertEqual(self.call(ts=ts).status_code, 200)
        self.assertEqual(self.call(ts=ts).status_code, 409)

    def test_missing_headers(self):
        self.assertEqual(self.app.test_client().post("/internal/tick", base_url="https://emanet.test").status_code, 401)

    def test_tick_delivers_and_retries_failed_mail(self):
        class Flaky:
            name = "flaky"
            fail = True
            sent = []

            def send(self, to, subject, body):
                if Flaky.fail:
                    raise ConnectionError("SES down")
                Flaky.sent.append(to)
        self.ctx.notifier = Flaky()
        self.person("Aysel").signup()
        r1 = self.tick()
        self.assertEqual(r1["emails_sent"], 0)
        self.assertEqual(self.ctx.db.one("SELECT error FROM outbox")["error"], "ConnectionError")
        Flaky.fail = False
        self.assertEqual(self.tick()["emails_sent"], 1)
        self.assertEqual(self.tick()["emails_sent"], 0)   # təkrar göndərilmir

    def test_health_reports_tick_age(self):
        self.tick()
        r = self.person("A").get("/api/health").get_json()
        self.assertIsNotNone(r["last_tick_age_s"])


class AuditTests(AppTestCase):
    def test_chain_detects_db_tampering(self):
        owner, _ = self.scenario()
        key = self.ctx.audit_key
        self.assertTrue(audit.verify(self.ctx.db, key)["intact"])
        conn = self.ctx.db.connect()
        conn.execute("UPDATE audit SET actor='someone-else' WHERE id=3")
        res = audit.verify(self.ctx.db, key)
        self.assertFalse(res["intact"])
        self.assertEqual(res["first_broken_index"], 2)

    def test_chain_detects_deletion(self):
        self.scenario()
        self.ctx.db.connect().execute("DELETE FROM audit WHERE id=4")
        self.assertFalse(audit.verify(self.ctx.db, self.ctx.audit_key)["intact"])

    def test_forbidden_metadata_keys(self):
        with self.ctx.db.tx() as conn:
            for bad in ({"password": "x"}, {"release_key": "x"}, {"nested": {"auth_key": "y"}}, {"note": "x" * 301}):
                with self.subTest(bad=bad), self.assertRaises(audit.AuditLeakError):
                    audit.record(conn, b"k" * 32, ts=1.0, action="t", **bad)

    def test_audit_written_in_same_transaction(self):
        """Biznes əməliyyatı uğursuz olarsa, audit qeydi də yazılmır (atomarlıq)."""
        n0 = self.ctx.db.one("SELECT COUNT(*) n FROM audit")["n"]
        try:
            with self.ctx.db.tx() as conn:
                audit.record(conn, self.ctx.audit_key, ts=1.0, action="test.atomic")
                raise RuntimeError("biznes xətası")
        except RuntimeError:
            pass
        self.assertEqual(self.ctx.db.one("SELECT COUNT(*) n FROM audit")["n"], n0)


class Cli(TmpDir):
    def run_cli(self, *args):
        env = {k: v for k, v in os.environ.items() if not k.startswith("EMANET_")}
        return subprocess.run([sys.executable, "-m", "emanet.cli", *args], cwd=ROOT, capture_output=True, text=True,
                              env={**env, "EMANET_DATA_DIR": str(self.tmp), "EMANET_ENV": "test"})

    def test_tick_and_verify(self):
        r = self.run_cli("tick")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("evaluated", r.stdout)
        r = self.run_cli("verify-audit")
        self.assertEqual(r.returncode, 0)
        self.assertIn('"intact": true', r.stdout)

    def test_rotate_kms(self):
        r = self.run_cli("rotate-kms")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn('"new_version": 2', r.stdout)

    def test_pause_all(self):
        r = self.run_cli("pause-all", "7")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn('"paused": 0', r.stdout)
        self.assertEqual(self.run_cli("pause-all", "500").returncode, 1)

    def test_grant_role_unknown_user(self):
        self.assertEqual(self.run_cli("grant-role", "yox@example.az", "auditor").returncode, 1)

    def test_integrity(self):
        r = self.run_cli("integrity")
        self.assertIn("js/crypto.js", r.stdout)


class LambdaTick(AppTestCase):
    """infra/lambda/tick.py real HTTP üzərindən serverin imza yoxlamasından keçir."""

    def test_lambda_signs_compatible_and_calls_over_http(self):
        import importlib.util
        import threading
        from werkzeug.serving import make_server
        spec = importlib.util.spec_from_file_location("tick", ROOT / "infra" / "lambda" / "tick.py")
        tick = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(tick)
        key = self.ctx.settings.secret("scheduler_hmac_key")
        self.assertEqual(tick.sign(key, 1700000000), sign_scheduler_request(key, "POST", "/internal/tick", 1700000000))
        srv = make_server("127.0.0.1", 0, self.app, threaded=True)
        th = threading.Thread(target=srv.serve_forever, daemon=True)
        th.start()
        try:
            res = tick.call(f"http://127.0.0.1:{srv.server_port}", key)
            self.assertIn("evaluated", res)
            with self.assertRaises(Exception):
                tick.call(f"http://127.0.0.1:{srv.server_port}", b"w" * 32)
        finally:
            srv.shutdown()
