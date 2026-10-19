"""Dəyişdirilə bilməyən (tamper-evident) audit jurnalı — HMAC heş zənciri.

    entry_hash_i = HMAC-SHA256(K_audit, entry_hash_{i-1} || canonical_json(payload_i))

Hər hansı qeydin silinməsi, dəyişdirilməsi və ya yerinin dəyişdirilməsi
zənciri qırır və `verify_chain` ilk pozulmuş qeydi göstərir. HMAC açarı
olmadan hücumçu zənciri "yenidən hesablaya" bilməz (adi SHA-256 zəncirindən
fərqli olaraq). ISO/IEC 27001:2022 A.8.15 (Logging) tələbinə cavab verir.
"""
from __future__ import annotations

import hashlib
import hmac
import json
from typing import Iterable

GENESIS = "0" * 64


def canonical_json(payload: dict) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode("utf-8")


def link(key: bytes, prev_hash: str, payload: dict) -> str:
    return hmac.new(key, prev_hash.encode() + canonical_json(payload),
                    hashlib.sha256).hexdigest()


def verify_chain(key: bytes, entries: Iterable[tuple[str, dict, str]]) -> tuple[bool, int | None]:
    """entries: (prev_hash, payload, entry_hash) ardıcıllığı.

    Qaytarır: (zəncir_bütövdür, ilk_pozulmuş_indeks)."""
    expected_prev = GENESIS
    for i, (prev_hash, payload, entry_hash) in enumerate(entries):
        if prev_hash != expected_prev:
            return False, i
        if not hmac.compare_digest(link(key, prev_hash, payload), entry_hash):
            return False, i
        expected_prev = entry_hash
    return True, None
