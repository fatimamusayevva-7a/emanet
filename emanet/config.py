"""Konfiqurasiya və sirlərin yüklənməsi.

Sirlər (HMAC açarları, lokal KMS master açarı) koda yazılmır. Mənbə sırası:
  1. AWS Secrets Manager  — EMANET_SECRETS_ID təyin olunubsa (istehsal)
  2. Mühit dəyişənləri    — EMANET_SECRET_KEY və s. (PaaS)
  3. data_dir/secrets.json — yalnız inkişaf mühitində avtomatik yaradılır (0600)
İstehsal rejimində (EMANET_ENV=production) 3-cü mənbə qadağandır.
"""
from __future__ import annotations

import base64
import json
import logging
import os
import pathlib
import secrets
from dataclasses import dataclass, field

log = logging.getLogger("emanet.config")

SECRET_NAMES = ("secret_key", "audit_hmac_key", "scheduler_hmac_key", "local_kms_master_key")


class ConfigError(RuntimeError):
    pass


def _env_bool(name: str, default: bool) -> bool:
    v = os.environ.get(name)
    return default if v is None else v.strip().lower() in {"1", "true", "yes", "on"}


def _env_int(name: str, default: int) -> int:
    v = os.environ.get(name)
    return default if v is None else int(v)


@dataclass
class Settings:
    env: str = "development"                       # development | test | production
    data_dir: pathlib.Path = pathlib.Path("./data")
    public_origin: str = "http://127.0.0.1:8000"   # CSRF Origin yoxlaması və e-poçt linkləri üçün
    cookie_secure: bool = False
    demo_mode: bool = False                        # saatı irəli çəkmək — istehsalda QADAĞAN
    kms_backend: str = "local"                     # local | aws
    aws_kms_key_id: str = ""
    aws_region: str = "eu-central-1"
    storage_backend: str = "local"                 # local | s3
    s3_bucket: str = ""
    notifier_backend: str = "outbox"               # outbox | ses
    ses_sender: str = ""
    secrets_id: str = ""
    bootstrap_operator_email: str = ""
    session_idle_seconds: int = 30 * 60
    session_absolute_seconds: int = 12 * 3600
    max_body_bytes: int = 8 * 1024 * 1024
    max_vault_bytes: int = 5 * 1024 * 1024
    trust_proxy: bool = False                      # X-Forwarded-For yalnız Caddy arxasında
    secrets: dict = field(default_factory=dict, repr=False)

    @property
    def is_production(self) -> bool:
        return self.env == "production"

    def secret(self, name: str) -> bytes:
        try:
            return self.secrets[name]
        except KeyError as exc:
            raise ConfigError(f"sirr yoxdur: {name}") from exc

    def validate(self) -> None:
        if self.is_production:
            problems = []
            if self.demo_mode:
                problems.append("EMANET_DEMO_MODE istehsalda aktiv ola bilməz")
            if not self.cookie_secure:
                problems.append("istehsalda cookie_secure=true olmalıdır")
            if not self.public_origin.startswith("https://"):
                problems.append("istehsalda public_origin https:// olmalıdır")
            if self.kms_backend != "aws":
                problems.append("istehsalda kms_backend=aws olmalıdır")
            if problems:
                raise ConfigError("; ".join(problems))
        for name in SECRET_NAMES:
            if len(self.secrets.get(name, b"")) < 32:
                raise ConfigError(f"sirr çox qısadır və ya yoxdur: {name}")


def _decode_secret_map(raw: dict) -> dict:
    return {k: base64.b64decode(v) for k, v in raw.items() if k in SECRET_NAMES}


def _load_from_aws(secret_id: str, region: str) -> dict:
    import boto3  # yalnız istehsalda lazımdır
    resp = boto3.client("secretsmanager", region_name=region).get_secret_value(SecretId=secret_id)
    return _decode_secret_map(json.loads(resp["SecretString"]))


def _load_or_create_dev_file(path: pathlib.Path) -> dict:
    if path.exists():
        return _decode_secret_map(json.loads(path.read_text()))
    path.parent.mkdir(parents=True, exist_ok=True)
    raw = {name: base64.b64encode(secrets.token_bytes(32)).decode() for name in SECRET_NAMES}
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as fh:
        json.dump(raw, fh)
    log.warning("inkişaf sirləri yaradıldı: %s (istehsalda Secrets Manager istifadə edin)", path)
    return _decode_secret_map(raw)


def load_settings(**overrides) -> Settings:
    s = Settings(
        env=os.environ.get("EMANET_ENV", "development"),
        data_dir=pathlib.Path(os.environ.get("EMANET_DATA_DIR", "./data")),
        public_origin=os.environ.get("EMANET_PUBLIC_ORIGIN", "http://127.0.0.1:8000").rstrip("/"),
        cookie_secure=_env_bool("EMANET_COOKIE_SECURE", False),
        demo_mode=_env_bool("EMANET_DEMO_MODE", False),
        kms_backend=os.environ.get("EMANET_KMS_BACKEND", "local"),
        aws_kms_key_id=os.environ.get("EMANET_AWS_KMS_KEY_ID", ""),
        aws_region=os.environ.get("AWS_REGION", "eu-central-1"),
        storage_backend=os.environ.get("EMANET_STORAGE_BACKEND", "local"),
        s3_bucket=os.environ.get("EMANET_S3_BUCKET", ""),
        notifier_backend=os.environ.get("EMANET_NOTIFIER", "outbox"),
        ses_sender=os.environ.get("EMANET_SES_SENDER", ""),
        secrets_id=os.environ.get("EMANET_SECRETS_ID", ""),
        bootstrap_operator_email=os.environ.get("EMANET_BOOTSTRAP_OPERATOR_EMAIL", "").strip().lower(),
        trust_proxy=_env_bool("EMANET_TRUST_PROXY", False),
        max_vault_bytes=_env_int("EMANET_MAX_VAULT_BYTES", 5 * 1024 * 1024),
    )
    for k, v in overrides.items():
        setattr(s, k, v)

    if not s.secrets:
        if s.secrets_id:
            s.secrets = _load_from_aws(s.secrets_id, s.aws_region)
        elif all(os.environ.get(f"EMANET_{n.upper()}") for n in SECRET_NAMES):
            s.secrets = {n: base64.b64decode(os.environ[f"EMANET_{n.upper()}"]) for n in SECRET_NAMES}
        elif s.is_production:
            raise ConfigError("istehsalda sirlər Secrets Manager və ya mühit dəyişənlərindən gəlməlidir")
        else:
            s.secrets = _load_or_create_dev_file(s.data_dir / "secrets.json")
    s.validate()
    return s
