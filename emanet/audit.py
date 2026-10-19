"""Audit jurnalı (HMAC heş zənciri) və təhlükəsizlik hadisələri.

İki ayrı axın:
  * audit            — "kim, nə vaxt, nə etdi" (sahibə də öz seyfi üzrə göstərilir)
  * security_events  — "nə şübhəlidir" (monitorinq və alarm üçün)

Audit qeydi biznes dəyişikliyi ilə EYNİ tranzaksiyada yazılır. Metadata
icazə siyahısından keçir və sirr kimi görünən açarlar qadağandır — log
özü sızma mənbəyinə çevrilməsin.
"""
from __future__ import annotations

import json
import logging

from .crypto.audit_chain import GENESIS, link, verify_chain

log = logging.getLogger("emanet.audit")

FORBIDDEN_KEY_PARTS = ("password", "auth_key", "secret", "token", "private", "privkey", "dek", "share_box",
                       "release_key", "recovery")


class AuditLeakError(ValueError):
    pass


def _check_details(details: dict) -> None:
    for k, v in details.items():
        lk = k.lower()
        if any(p in lk for p in FORBIDDEN_KEY_PARTS):
            raise AuditLeakError(f"audit metadata-da qadağan açar: {k}")
        if isinstance(v, dict):
            _check_details(v)
        if isinstance(v, str) and len(v) > 300:
            raise AuditLeakError(f"audit metadata dəyəri çox uzundur: {k}")


def record(conn, key: bytes, *, ts: float, action: str, actor: str | None = None, vault_id: str | None = None,
           target: str | None = None, ip: str | None = None, **details) -> str:
    _check_details(details)
    row = conn.execute("SELECT entry_hash FROM audit ORDER BY id DESC LIMIT 1").fetchone()
    prev = row["entry_hash"] if row else GENESIS
    payload = {"ts": round(ts, 3), "actor": actor, "action": action, "vault_id": vault_id, "target": target,
               "ip": ip, "details": details}
    h = link(key, prev, payload)
    conn.execute("INSERT INTO audit(ts, actor, action, vault_id, target, ip, details, prev_hash, entry_hash) "
                 "VALUES(?,?,?,?,?,?,?,?,?)",
                 (payload["ts"], actor, action, vault_id, target, ip,
                  json.dumps(details, ensure_ascii=False, sort_keys=True), prev, h))
    log.info(json.dumps({"audit": action, "actor": actor, "vault": vault_id}, ensure_ascii=False))
    return h


def security_event(conn, *, ts: float, kind: str, actor: str | None = None, ip: str | None = None, **details) -> None:
    _check_details(details)
    conn.execute("INSERT INTO security_events(ts, kind, actor, ip, details) VALUES(?,?,?,?,?)",
                 (ts, kind, actor, ip, json.dumps(details, ensure_ascii=False, sort_keys=True)))
    # Strukturlaşdırılmış log → CloudWatch metric filter "security_event" bunu sayır və alarm verir
    log.warning(json.dumps({"security_event": kind, "actor": actor, "ip": ip}, ensure_ascii=False))


def rows_for_verify(db):
    for r in db.all("SELECT * FROM audit ORDER BY id"):
        payload = {"ts": r["ts"], "actor": r["actor"], "action": r["action"], "vault_id": r["vault_id"],
                   "target": r["target"], "ip": r["ip"], "details": json.loads(r["details"])}
        yield r["prev_hash"], payload, r["entry_hash"]


def verify(db, key: bytes) -> dict:
    ok, idx = verify_chain(key, rows_for_verify(db))
    total = db.one("SELECT COUNT(*) AS n FROM audit")["n"]
    return {"intact": ok, "first_broken_index": idx, "entries": total}
