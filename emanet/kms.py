"""Açar idarəetmə xidməti (KMS) — "zaman kilidi" açarı R-in qoruyucusu.

Hər seyf üçün 32 baytlıq R yaradılır və yalnız KMS ilə sarınmış (wrapped)
halda DB-də saxlanılır. R-in açılması (Decrypt) yalnız iki halda baş verir:
  * sahib öz seyfinin paylanmasını yeniləyəndə (sahib R-i bilməyə haqlıdır);
  * vəziyyət maşını seyfi RELEASED vəziyyətinə keçirdikdən sonra.
Hər Decrypt çağırışı audit jurnalına, AWS-də isə əlavə olaraq CloudTrail-ə düşür.

EncryptionContext = {"vault_id": ..., "purpose": "release-key"} — sarınmış R
başqa seyfin sətrinə köçürülsə, açılmayacaq (AAD kimi işləyir).

* LocalKMS — inkişaf/demo: versiyalı açar halqası, master açar Secrets-dən.
* AwsKMS   — istehsal: AWS KMS (HSM-də saxlanan simmetrik açar, illik avtomatik rotasiya).
"""
from __future__ import annotations

import base64
import json
import os
import pathlib
import threading
from typing import Protocol

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .crypto.primitives import canonical


class KMSError(Exception):
    pass


class KMS(Protocol):
    name: str

    def generate_key(self, context: dict) -> tuple[bytes, str]: ...
    def decrypt(self, ciphertext: str, context: dict) -> bytes: ...
    def rewrap(self, ciphertext: str, context: dict) -> str: ...


class LocalKMS:
    """Açar halqası faylı master açarla şifrələnir: keyring.json = AES-GCM(master, {ver: key})."""

    name = "local"

    def __init__(self, path: pathlib.Path, master_key: bytes):
        if len(master_key) < 32:
            raise KMSError("master açar ən azı 32 bayt olmalıdır")
        self.path = path
        self.master = master_key[:32]
        self._lock = threading.Lock()
        self._ring = self._load()

    def _load(self) -> dict:
        if not self.path.exists():
            ring = {"current": 1, "keys": {"1": base64.b64encode(os.urandom(32)).decode()}}
            self._save(ring)
            return ring
        blob = json.loads(self.path.read_text())
        try:
            pt = AESGCM(self.master).decrypt(base64.b64decode(blob["iv"]), base64.b64decode(blob["ct"]),
                                             b"emanet/local-kms/keyring")
        except InvalidTag as exc:
            raise KMSError("açar halqası açılmadı — master açar yanlışdır və ya fayl dəyişdirilib") from exc
        return json.loads(pt)

    def _save(self, ring: dict) -> None:
        iv = os.urandom(12)
        ct = AESGCM(self.master).encrypt(iv, json.dumps(ring).encode(), b"emanet/local-kms/keyring")
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(".tmp")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as fh:
            json.dump({"iv": base64.b64encode(iv).decode(), "ct": base64.b64encode(ct).decode()}, fh)
        os.replace(tmp, self.path)

    @property
    def current_version(self) -> int:
        return int(self._ring["current"])

    def _key(self, ver: int) -> bytes:
        try:
            return base64.b64decode(self._ring["keys"][str(ver)])
        except KeyError as exc:
            raise KMSError("açar versiyası yoxdur (məhv edilib?)") from exc

    def _wrap(self, plaintext: bytes, context: dict) -> str:
        ver = self.current_version
        iv = os.urandom(12)
        ct = AESGCM(self._key(ver)).encrypt(iv, plaintext, canonical(context))
        return f"lk1:{ver}:{base64.b64encode(iv + ct).decode()}"

    def generate_key(self, context: dict) -> tuple[bytes, str]:
        pt = os.urandom(32)
        return pt, self._wrap(pt, context)

    def decrypt(self, ciphertext: str, context: dict) -> bytes:
        try:
            tag, ver, data = ciphertext.split(":", 2)
            if tag != "lk1":
                raise ValueError
            raw = base64.b64decode(data)
            return AESGCM(self._key(int(ver))).decrypt(raw[:12], raw[12:], canonical(context))
        except (ValueError, InvalidTag) as exc:
            raise KMSError("KMS şifrəaçma rədd edildi") from exc

    def rotate(self) -> int:
        """Yeni açar versiyası; köhnələr yalnız açmaq üçün qalır (NIST SP 800-57)."""
        with self._lock:
            new = self.current_version + 1
            self._ring["keys"][str(new)] = base64.b64encode(os.urandom(32)).decode()
            self._ring["current"] = new
            self._save(self._ring)
            return new

    def rewrap(self, ciphertext: str, context: dict) -> str:
        return self._wrap(self.decrypt(ciphertext, context), context)

    @staticmethod
    def version_of(ciphertext: str) -> int:
        return int(ciphertext.split(":", 2)[1])


class AwsKMS:
    """AWS KMS. `client` test üçün inject oluna bilər (boto3 interfeysi ilə eyni)."""

    name = "aws"

    def __init__(self, key_id: str, region: str, client=None):
        if not key_id:
            raise KMSError("EMANET_AWS_KMS_KEY_ID təyin olunmayıb")
        self.key_id = key_id
        if client is None:
            import boto3
            client = boto3.client("kms", region_name=region)
        self.client = client

    @staticmethod
    def _ctx(context: dict) -> dict:
        return {str(k): str(v) for k, v in context.items()}

    def generate_key(self, context: dict) -> tuple[bytes, str]:
        r = self.client.generate_data_key(KeyId=self.key_id, KeySpec="AES_256", EncryptionContext=self._ctx(context))
        return r["Plaintext"], "aws1:" + base64.b64encode(r["CiphertextBlob"]).decode()

    def decrypt(self, ciphertext: str, context: dict) -> bytes:
        if not ciphertext.startswith("aws1:"):
            raise KMSError("AWS KMS şifrəmətni deyil")
        try:
            r = self.client.decrypt(CiphertextBlob=base64.b64decode(ciphertext[5:]), KeyId=self.key_id,
                                    EncryptionContext=self._ctx(context))
        except Exception as exc:  # botocore xətaları: InvalidCiphertextException, AccessDenied …
            raise KMSError("KMS şifrəaçma rədd edildi") from exc
        return r["Plaintext"]

    def rewrap(self, ciphertext: str, context: dict) -> str:
        r = self.client.re_encrypt(CiphertextBlob=base64.b64decode(ciphertext[5:]),
                                   SourceEncryptionContext=self._ctx(context), DestinationKeyId=self.key_id,
                                   DestinationEncryptionContext=self._ctx(context))
        return "aws1:" + base64.b64encode(r["CiphertextBlob"]).decode()


def release_context(vault_id: str) -> dict:
    return {"vault_id": vault_id, "purpose": "release-key", "app": "emanet"}


def build_kms(settings) -> KMS:
    if settings.kms_backend == "aws":
        return AwsKMS(settings.aws_kms_key_id, settings.aws_region)
    return LocalKMS(settings.data_dir / "keyring.json", settings.secret("local_kms_master_key"))
