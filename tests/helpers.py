"""Test köməkçiləri: brauzerin etdiyi kriptoqrafiyanı Python-da edən "virtual istifadəçi".

`Person` brauzerdəki `web/js/app.js` ilə eyni protokolu izləyir (eyni
primitives modulundan istifadə edir), beləliklə API testləri real istifadəçi
axınını sınayır. Testlərdə PBKDF2 iterasiyası azaldılmır — sürət üçün master
açar bir dəfə hesablanıb keşlənir.
"""
from __future__ import annotations

import base64
import functools
import os
import pathlib
import secrets
import shutil
import tempfile
import unittest

from cryptography.hazmat.primitives import serialization

from emanet.app import create_app
from emanet.clock import FrozenClock
from emanet.config import load_settings
from emanet.crypto import primitives as P
from emanet.crypto import shamir

TEST_SECRETS = {n: secrets.token_bytes(32) for n in
                ("secret_key", "audit_hmac_key", "scheduler_hmac_key", "local_kms_master_key")}
ORIGIN = "https://emanet.test"


def _ascii(name: str) -> str:
    tr = str.maketrans("əöüğışçƏÖÜĞIŞÇ", "eougiscEOUGISC")
    return name.translate(tr).lower()


@functools.lru_cache(maxsize=64)
def cached_master(password: str, salt: bytes) -> bytes:
    return P.master_key(password, salt)


def make_app(tmp: pathlib.Path, clock=None, **overrides):
    s = load_settings(data_dir=tmp, env="test", public_origin=ORIGIN, cookie_secure=True,
                      secrets=dict(TEST_SECRETS), **overrides)
    clock = clock or FrozenClock()
    return create_app(s, clock=clock), clock


class Person:
    def __init__(self, app, name: str, email: str | None = None, password: str = "Çox-güclü parol 2026!"):
        self.app = app
        self.client = app.test_client()
        self.name = name
        self.email = email or f"{_ascii(name)}@example.az"
        self.password = password
        self.user_id = "u_" + secrets.token_urlsafe(16)
        self.salt = os.urandom(16)
        self.priv = P.generate_keypair()
        self.pub = P.public_raw(self.priv)
        self.recovery_code = P.new_recovery_code()
        self.csrf = None
        self.vault_id = None
        self.dek = None
        self.release_key = None

    # ------------------------------------------------------------- HTTP
    def _headers(self, extra=None):
        h = {"Origin": ORIGIN}
        if self.csrf:
            h["X-CSRF-Token"] = self.csrf
        h.update(extra or {})
        return h

    def req(self, method, path, json=None, headers=None, **kw):
        return self.client.open(path, method=method, json=json, headers=self._headers(headers),
                                base_url="https://emanet.test", **kw)

    def get(self, path, **kw):
        return self.req("GET", path, **kw)

    def post(self, path, json=None, **kw):
        return self.req("POST", path, json=json if json is not None else {}, **kw)

    # ------------------------------------------------------------- açarlar
    @property
    def keys(self):
        return P.derive_user_keys(cached_master(self.password, self.salt))

    def wrapped_privkey(self, enc_key: bytes, purpose="enc"):
        der = self.priv.private_bytes(serialization.Encoding.DER, serialization.PrivateFormat.PKCS8,
                                      serialization.NoEncryption())
        return P.seal(enc_key, der, P.aad_privkey(self.user_id, purpose))

    def register(self, expect=201):
        rk = P.recovery_keys(self.recovery_code)
        r = self.post("/api/auth/register", {
            "user_id": self.user_id, "email": self.email, "display_name": self.name,
            "kdf_salt": P.b64u(self.salt), "auth_key": P.b64u(self.keys.auth_key), "public_key": P.b64u(self.pub),
            "wrapped_privkey": self.wrapped_privkey(self.keys.enc_key),
            "recovery_auth": P.b64u(rk.auth_key),
            "wrapped_privkey_recovery": self.wrapped_privkey(rk.enc_key, "recovery"),
        })
        assert r.status_code == expect, r.get_json()
        return r

    def login(self, expect=200, totp=None, auth_key=None):
        body = {"email": self.email, "auth_key": P.b64u(auth_key or self.keys.auth_key)}
        if totp:
            body["totp"] = totp
        r = self.post("/api/auth/login", body)
        assert r.status_code == expect, r.get_json()
        if r.status_code == 200:
            self.csrf = r.get_json()["csrf"]
        return r

    def signup(self):
        self.register()
        self.login()
        return self

    # ------------------------------------------------------------- seyf
    def create_vault(self, content=None):
        self.vault_id = "v_" + secrets.token_urlsafe(16)
        self.dek = os.urandom(32)
        rk = P.recovery_keys(self.recovery_code)
        r = self.post("/api/vault", {
            "vault_id": self.vault_id,
            "wrapped_dek_owner": P.seal(self.keys.enc_key, self.dek, P.aad_dek(self.vault_id, "owner")),
            "wrapped_dek_recovery": P.seal(rk.enc_key, self.dek, P.aad_dek(self.vault_id, "recovery")),
        })
        assert r.status_code == 201, r.get_json()
        self.release_key = P.b64u_d(r.get_json()["release_key"])
        if content is not None:
            self.save_content(content, 1)
        return r

    def save_content(self, content: dict, version: int, expect=200):
        import json as _j
        box = P.seal(self.dek, P.pad(_j.dumps(content, ensure_ascii=False).encode()), P.aad_vault(self.vault_id, version))
        r = self.req("PUT", "/api/vault/content", json={"version": version, "box": box})
        assert r.status_code == expect, r.get_json()
        return r

    def invite(self, other: "Person", expect=201):
        r = self.post("/api/vault/trustees", {"email": other.email})
        assert r.status_code == expect, r.get_json()
        return r

    def trustees(self):
        return self.get("/api/vault").get_json()["trustees"]

    def verify_all(self):
        for t in self.trustees():
            if t["status"] == "accepted":
                r = self.post(f"/api/vault/trustees/{t['id']}/verify", {"fingerprint": t["fingerprint"]})
                assert r.status_code == 200, r.get_json()

    def build_distribution(self, threshold: int, tamper=None):
        accepted = [t for t in self.trustees() if t["status"] == "accepted"]
        S = os.urandom(32)
        shares = shamir.split(S, len(accepted), threshold)
        kek = P.release_kek(S, self.release_key, self.vault_id)
        items = []
        for t, sh in zip(accepted, shares):
            sb = sh.to_bytes()
            items.append({"trustee_id": t["id"], "x": sh.x, "commitment": P.share_commitment(self.vault_id, sb),
                          "box": P.ecies_encrypt(P.b64u_d(t["public_key"]), sb,
                                                 P.ctx_share(self.vault_id, t["user_id"], sh.x))})
        body = {"threshold": threshold, "wrapped_dek_release": P.seal(kek, self.dek, P.aad_dek(self.vault_id, "release")),
                "shares": items}
        if tamper:
            tamper(body)
        return body, S

    def distribute(self, threshold: int, expect=200):
        body, S = self.build_distribution(threshold)
        r = self.post("/api/vault/distribution", body)
        assert r.status_code == expect, r.get_json()
        return S

    def checkin(self):
        return self.post("/api/vault/checkin")

    # ------------------------------------------------------------- etibarlı şəxs
    def accept_all(self):
        for inv in self.get("/api/trustee/invitations").get_json()["invitations"]:
            r = self.post(f"/api/trustee/invitations/{inv['id']}/accept")
            assert r.status_code == 200

    def approve(self, vault_id, expect=200):
        r = self.post(f"/api/trustee/vaults/{vault_id}/approve")
        assert r.status_code == expect, r.get_json()
        return r

    def material(self, vault_id, expect=200):
        r = self.get(f"/api/trustee/vaults/{vault_id}/release")
        assert r.status_code == expect, r.get_json()
        return r.get_json()

    def my_share(self, m) -> bytes:
        return P.ecies_decrypt(self.priv, m["my_share"]["box"], P.ctx_share(m["vault_id"], self.user_id, m["my_share"]["x"]))

    def hand_off(self, vault_id):
        m = self.material(vault_id)
        sb = self.my_share(m)
        items = [{"to_user": o["user_id"], "x": m["my_share"]["x"],
                  "box": P.ecies_encrypt(P.b64u_d(o["public_key"]), sb,
                                         P.ctx_handoff(vault_id, self.user_id, o["user_id"], m["my_share"]["x"]))}
                 for o in m["others"]]
        r = self.post(f"/api/trustee/vaults/{vault_id}/handoffs", {"items": items})
        assert r.status_code == 200, r.get_json()

    def open_vault(self, vault_id) -> dict:
        """Brauzerdəki "seyfi aç" düyməsinin Python əkizi."""
        import json as _j
        m = self.material(vault_id)
        shares = [shamir.Share.from_bytes(self.my_share(m))]
        for h in m["handoffs"]:
            sb = P.ecies_decrypt(self.priv, h["box"], P.ctx_handoff(vault_id, h["from_user"], self.user_id, h["x"]))
            if P.share_commitment(vault_id, sb) != m["commitments"][str(h["x"])]:
                raise P.CryptoError(f"saxta hissə #{h['x']}")
            shares.append(shamir.Share.from_bytes(sb))
        if len(shares) < m["threshold"]:
            raise P.CryptoError(f"hissə çatmır: {len(shares)}/{m['threshold']}")
        S = shamir.combine(shares)
        kek = P.release_kek(S, P.b64u_d(m["release_key"]), vault_id)
        dek = P.open_sealed(kek, m["wrapped_dek_release"], P.aad_dek(vault_id, "release"))
        c = m["content"]
        return _j.loads(P.unpad(P.open_sealed(dek, c["box"], P.aad_vault(vault_id, c["version"]))))


class AppTestCase(unittest.TestCase):
    clock_start = 1_800_000_000.0

    def setUp(self):
        self.tmp = pathlib.Path(tempfile.mkdtemp(prefix="emanet-test-"))
        self.app, self.clock = make_app(self.tmp, FrozenClock(self.clock_start))
        self.ctx = self.app.extensions["emanet"]

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def person(self, name, **kw) -> Person:
        return Person(self.app, name, **kw)

    def scenario(self, n_trustees=3, threshold=2, content=None):
        """Sahib + n etibarlı şəxs, paylanma hazır (ACTIVE vəziyyət)."""
        owner = self.person("Aysel").signup()
        owner.create_vault(content or {"items": [{"title": "Bank", "secret": "PIN 4821"}]})
        ts = [self.person(n).signup() for n in ["Rəşad", "Nigar", "Elvin", "Ləman", "Tural"][:n_trustees]]
        for t in ts:
            owner.invite(t)
            t.accept_all()
        owner.verify_all()
        owner.distribute(threshold)
        return owner, ts

    def advance_days(self, d):
        self.clock.advance_days(d)

    def tick(self):
        from emanet.services import tick
        return tick(self.ctx)

    def keep_sessions_alive(self, *people):
        for p in people:
            p.login()


def b64(b: bytes) -> str:
    return base64.b64encode(b).decode()
