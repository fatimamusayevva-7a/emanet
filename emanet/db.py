"""SQLite verilənlər bazası (WAL rejimi). Server yalnız şifrəli məlumat saxlayır.

Cədvəllərdə açıq mətn seyf məzmunu, açıq Shamir hissəsi, açıq DEK və ya
istifadəçinin parolu YOXDUR. Buna `tests/test_zero_knowledge.py` nəzarət edir.
"""
from __future__ import annotations

import pathlib
import sqlite3
import threading

SCHEMA = """
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    email TEXT NOT NULL UNIQUE,
    display_name TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'user' CHECK (role IN ('user','operator','auditor')),
    status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active','suspended')),
    kdf_salt TEXT NOT NULL,
    kdf_iterations INTEGER NOT NULL,
    auth_hash TEXT NOT NULL,                 -- Argon2id(auth_key); auth_key özü PBKDF2+HKDF nəticəsidir
    public_key TEXT NOT NULL,                -- P-256 açıq açar (raw, base64url)
    wrapped_privkey TEXT NOT NULL,           -- AES-GCM(enc_key, PKCS8) — server aça bilmir
    recovery_auth_hash TEXT NOT NULL,
    wrapped_privkey_recovery TEXT NOT NULL,
    totp_secret TEXT,
    totp_enabled INTEGER NOT NULL DEFAULT 0,
    totp_last_step INTEGER,
    failed_logins INTEGER NOT NULL DEFAULT 0,
    locked_until REAL,
    created_at REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS sessions (
    token_hash TEXT PRIMARY KEY,             -- SHA-256(token); token yalnız HttpOnly cookie-də
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    csrf TEXT NOT NULL,
    created_at REAL NOT NULL,
    last_seen REAL NOT NULL,
    ip TEXT,
    user_agent TEXT
);

CREATE TABLE IF NOT EXISTS vaults (
    id TEXT PRIMARY KEY,
    owner_id TEXT NOT NULL UNIQUE REFERENCES users(id) ON DELETE CASCADE,
    version INTEGER NOT NULL DEFAULT 0,
    blob_key TEXT,
    blob_size INTEGER NOT NULL DEFAULT 0,
    wrapped_dek_owner TEXT NOT NULL,
    wrapped_dek_recovery TEXT NOT NULL,
    wrapped_dek_release TEXT,
    release_key_ct TEXT NOT NULL,            -- KMS ilə sarınmış R (zaman kilidi açarı)
    threshold INTEGER,
    distribution_version INTEGER NOT NULL DEFAULT 0,
    state TEXT NOT NULL DEFAULT 'setup'
        CHECK (state IN ('setup','active','reminding','awaiting','pending_release','released')),
    checkin_interval_days INTEGER NOT NULL DEFAULT 30,
    inactivity_days INTEGER NOT NULL DEFAULT 60,
    waiting_days INTEGER NOT NULL DEFAULT 7,
    last_activity_at REAL NOT NULL,
    last_reminder_at REAL,
    reminders_sent INTEGER NOT NULL DEFAULT 0,
    paused_until REAL,
    release_at REAL,
    released_at REAL,
    created_at REAL NOT NULL,
    updated_at REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS trustees (
    id TEXT PRIMARY KEY,
    vault_id TEXT NOT NULL REFERENCES vaults(id) ON DELETE CASCADE,
    user_id TEXT REFERENCES users(id) ON DELETE CASCADE,
    invited_email TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'invited' CHECK (status IN ('invited','accepted','declined')),
    fingerprint_verified INTEGER NOT NULL DEFAULT 0,
    x INTEGER,
    share_box TEXT,                          -- ECIES(etibarlı şəxsin açıq açarı, hissə)
    commitment TEXT,
    created_at REAL NOT NULL,
    UNIQUE (vault_id, invited_email)
);

CREATE TABLE IF NOT EXISTS approvals (
    vault_id TEXT NOT NULL REFERENCES vaults(id) ON DELETE CASCADE,
    trustee_user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    distribution_version INTEGER NOT NULL,
    created_at REAL NOT NULL,
    PRIMARY KEY (vault_id, trustee_user_id)
);

CREATE TABLE IF NOT EXISTS handoffs (
    id TEXT PRIMARY KEY,
    vault_id TEXT NOT NULL REFERENCES vaults(id) ON DELETE CASCADE,
    from_user TEXT NOT NULL,
    to_user TEXT NOT NULL,
    x INTEGER NOT NULL,
    box TEXT NOT NULL,                       -- ECIES(alıcının açıq açarı, hissə)
    created_at REAL NOT NULL,
    UNIQUE (vault_id, from_user, to_user)
);

CREATE TABLE IF NOT EXISTS checkin_tokens (
    token_hash TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    expires_at REAL NOT NULL,
    used_at REAL
);

CREATE TABLE IF NOT EXISTS outbox (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    to_email TEXT NOT NULL,
    kind TEXT NOT NULL,
    subject TEXT NOT NULL,
    body TEXT NOT NULL,
    created_at REAL NOT NULL,
    sent_at REAL,
    error TEXT
);

CREATE TABLE IF NOT EXISTS audit (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts REAL NOT NULL,
    actor TEXT,
    action TEXT NOT NULL,
    vault_id TEXT,
    target TEXT,
    ip TEXT,
    details TEXT NOT NULL,
    prev_hash TEXT NOT NULL,
    entry_hash TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS audit_vault ON audit(vault_id);

CREATE TABLE IF NOT EXISTS security_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts REAL NOT NULL,
    kind TEXT NOT NULL,
    actor TEXT,
    ip TEXT,
    details TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS rate_hits (
    bucket TEXT NOT NULL,
    ts REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS rate_bucket ON rate_hits(bucket, ts);

CREATE TABLE IF NOT EXISTS kv (
    k TEXT PRIMARY KEY,
    v TEXT NOT NULL
);
"""


class Database:
    def __init__(self, path: pathlib.Path):
        self.path = path
        path.parent.mkdir(parents=True, exist_ok=True)
        self._local = threading.local()
        self.write_lock = threading.RLock()
        with self.connect() as c:
            c.executescript(SCHEMA)

    def connect(self) -> sqlite3.Connection:
        conn = getattr(self._local, "conn", None)
        if conn is None:
            conn = sqlite3.connect(self.path, timeout=10, isolation_level=None, check_same_thread=False)
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA foreign_keys=ON")
            conn.execute("PRAGMA busy_timeout=10000")
            conn.execute("PRAGMA secure_delete=ON")   # silinən məlumat diskdə üzərinə yazılır
            self._local.conn = conn
        return conn

    def tx(self):
        """Tranzaksiya: `with db.tx() as c:` — xəta olarsa ROLLBACK."""
        return _Tx(self)

    def one(self, sql: str, args=()):
        return self.connect().execute(sql, args).fetchone()

    def all(self, sql: str, args=()):
        return self.connect().execute(sql, args).fetchall()

    def get_kv(self, k: str, default: str | None = None) -> str | None:
        row = self.one("SELECT v FROM kv WHERE k=?", (k,))
        return row["v"] if row else default

    def set_kv(self, k: str, v: str) -> None:
        with self.tx() as c:
            c.execute("INSERT INTO kv(k,v) VALUES(?,?) ON CONFLICT(k) DO UPDATE SET v=excluded.v", (k, v))


class _Tx:
    def __init__(self, db: Database):
        self.db = db

    """Yenidən daxil oluna bilən (reentrant) tranzaksiya: daxili `tx()` xarici tranzaksiyaya qoşulur."""

    def __enter__(self) -> sqlite3.Connection:
        self.db.write_lock.acquire()
        self.conn = self.db.connect()
        depth = getattr(self.db._local, "depth", 0)
        if depth == 0:
            self.conn.execute("BEGIN IMMEDIATE")
        self.db._local.depth = depth + 1
        return self.conn

    def __exit__(self, exc_type, exc, tb):
        try:
            self.db._local.depth -= 1
            if self.db._local.depth == 0:
                self.conn.execute("COMMIT" if exc_type is None else "ROLLBACK")
            elif exc_type is not None:
                pass  # xəta xarici tranzaksiyaya ötürülür və orada ROLLBACK olur
        finally:
            self.db.write_lock.release()
        return False
