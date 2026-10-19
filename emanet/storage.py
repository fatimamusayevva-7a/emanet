"""Şifrəli seyf obyektlərinin saxlanması (obyekt anbarı).

Server buraya yalnız brauzerdə şifrələnmiş, ölçüsü doldurulmuş (padded)
AES-GCM qutusunu yazır. Hər yazı yeni versiyadır — köhnə versiyalar
(S3 Versioning + Object Lock) ransomware/insan səhvinə qarşı qorunur.

* LocalStorage — data_dir/objects/<vault>/<version>.json
* S3Storage    — s3://bucket/vaults/<vault>/v<version>.json, SSE-KMS, Object Lock (bucket səviyyəsində)
"""
from __future__ import annotations

import json
import os
import pathlib
import re
import shutil

_SAFE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")


class StorageError(Exception):
    pass


def object_key(vault_id: str, version: int) -> str:
    if not _SAFE.match(vault_id) or not isinstance(version, int) or version < 1:
        raise StorageError("yanlış obyekt açarı")    # path traversal qorunması
    return f"vaults/{vault_id}/v{version}.json"


class LocalStorage:
    name = "local"

    def __init__(self, root: pathlib.Path):
        self.root = root.resolve()
        self.root.mkdir(parents=True, exist_ok=True)

    def _path(self, key: str) -> pathlib.Path:
        p = (self.root / key).resolve()
        if self.root not in p.parents:
            raise StorageError("anbardan kənar yol")
        return p

    def put(self, key: str, box: dict) -> None:
        p = self._path(key)
        p.parent.mkdir(parents=True, exist_ok=True)
        tmp = p.with_suffix(".tmp")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as fh:
            json.dump(box, fh)
        os.replace(tmp, p)

    def get(self, key: str) -> dict:
        try:
            return json.loads(self._path(key).read_text())
        except FileNotFoundError as exc:
            raise StorageError("obyekt tapılmadı") from exc

    def delete_vault(self, vault_id: str) -> None:
        if not _SAFE.match(vault_id):
            raise StorageError("yanlış id")
        shutil.rmtree(self._path(f"vaults/{vault_id}"), ignore_errors=True)


class S3Storage:
    name = "s3"

    def __init__(self, bucket: str, region: str, client=None):
        if not bucket:
            raise StorageError("EMANET_S3_BUCKET təyin olunmayıb")
        self.bucket = bucket
        if client is None:
            import boto3
            client = boto3.client("s3", region_name=region)
        self.client = client

    def put(self, key: str, box: dict) -> None:
        # Şifrələmə bucket-in defolt SSE-KMS qaydası ilə tətbiq olunur (Terraform: s3.tf).
        self.client.put_object(Bucket=self.bucket, Key=key, Body=json.dumps(box).encode(),
                               ContentType="application/json", ServerSideEncryption="aws:kms")

    def get(self, key: str) -> dict:
        try:
            return json.loads(self.client.get_object(Bucket=self.bucket, Key=key)["Body"].read())
        except Exception as exc:
            raise StorageError("obyekt tapılmadı") from exc

    def delete_vault(self, vault_id: str) -> None:
        # Object Lock aktivdirsə köhnə versiyalar saxlama müddəti bitənə qədər qalır.
        # Bu, problem deyil: DEK və R məhv edildiyi üçün onlar oxunmaz (crypto-shredding).
        prefix = f"vaults/{vault_id}/"
        resp = self.client.list_objects_v2(Bucket=self.bucket, Prefix=prefix)
        for obj in resp.get("Contents", []):
            self.client.delete_object(Bucket=self.bucket, Key=obj["Key"])


def build_storage(settings):
    if settings.storage_backend == "s3":
        return S3Storage(settings.s3_bucket, settings.aws_region)
    return LocalStorage(settings.data_dir / "objects")
