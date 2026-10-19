"""AWS Lambda: EventBridge Scheduler hər saat bunu çağırır → HMAC imzalı POST /internal/tick.

Yalnız standart kitabxana + Lambda mühitindəki boto3. Sirr Secrets Manager-dən gəlir.
Uğurlu tick-də "TickSucceeded" metriki göndərilir; 3 saat metrik gəlməsə alarm yaranır.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import time
import urllib.request

_secret_cache: dict = {}


def _secret() -> bytes:
    if "k" not in _secret_cache:
        import base64
        import boto3
        raw = boto3.client("secretsmanager").get_secret_value(SecretId=os.environ["SCHEDULER_SECRET"])["SecretString"]
        _secret_cache["k"] = base64.b64decode(json.loads(raw)["scheduler_hmac_key"])
    return _secret_cache["k"]


def sign(key: bytes, ts: int, body: bytes = b"") -> str:
    msg = f"POST\n/internal/tick\n{ts}\n{hashlib.sha256(body).hexdigest()}".encode()
    return hmac.new(key, msg, hashlib.sha256).hexdigest()


def call(url: str, key: bytes, timeout: int = 30) -> dict:
    ts = int(time.time())
    req = urllib.request.Request(url.rstrip("/") + "/internal/tick", data=b"", method="POST", headers={
        "X-Emanet-Timestamp": str(ts), "X-Emanet-Signature": sign(key, ts), "User-Agent": "emanet-scheduler/1"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:   # noqa: S310 — URL konfiqurasiyadan, https
        if resp.status != 200:
            raise RuntimeError(f"tick HTTP {resp.status}")
        return json.loads(resp.read())


def handler(event, context):
    result = call(os.environ["APP_URL"], _secret())
    import boto3
    boto3.client("cloudwatch").put_metric_data(Namespace=os.environ.get("METRIC_NAMESPACE", "Emanet"), MetricData=[
        {"MetricName": "TickSucceeded", "Value": 1, "Unit": "Count"},
        {"MetricName": "EmailsSent", "Value": result.get("emails_sent", 0), "Unit": "Count"},
        {"MetricName": "VaultsEvaluated", "Value": result.get("evaluated", 0), "Unit": "Count"},
    ])
    print(json.dumps({"tick": "ok", **result}))
    return result
