#!/usr/bin/env python3
"""
LinuxAuthGuard - Vault Database Interface
SQLite-backed storage for protected items, with Argon2 password hashing.
"""

from __future__ import annotations

import os
import secrets
import sqlite3
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Any


def _require_argon2() -> Any:
    try:
        from argon2 import PasswordHasher
        from argon2.exceptions import VerifyMismatchError, VerificationError
        return PasswordHasher, VerifyMismatchError, VerificationError
    except ImportError:
        raise RuntimeError(
            "argon2-cffi not installed. Run: pip install argon2-cffi"
        )


@dataclass
class ProtectedItem:
    id: int
    path: str
    password_hash: str
    salt: str
    totp_required: bool
    owner_uid: int
    recursive: bool
    created_at: float
    updated_at: float


SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS protected_items (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    path            TEXT    NOT NULL UNIQUE,
    password_hash   TEXT    NOT NULL,
    salt            TEXT    NOT NULL,
    totp_required   INTEGER NOT NULL DEFAULT 0,
    owner_uid       INTEGER NOT NULL,
    recursive       INTEGER NOT NULL DEFAULT 1,
    created_at      REAL    NOT NULL,
    updated_at      REAL    NOT NULL
);

CREATE TABLE IF NOT EXISTS access_log (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    item_path   TEXT    NOT NULL,
    accessed_by INTEGER NOT NULL,
    access_type TEXT    NOT NULL,
    granted     INTEGER NOT NULL,
    timestamp   REAL    NOT NULL
);

CREATE TABLE IF NOT EXISTS users (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    username    TEXT    NOT NULL UNIQUE,
    totp_enabled INTEGER NOT NULL DEFAULT 0,
    totp_secret  TEXT
);

CREATE INDEX IF NOT EXISTS idx_items_path  ON protected_items(path);
CREATE INDEX IF NOT EXISTS idx_log_path    ON access_log(item_path);
CREATE INDEX IF NOT EXISTS idx_log_ts      ON access_log(timestamp);
CREATE INDEX IF NOT EXISTS idx_users_name  ON users(username);
"""


class VaultDB:
    """Thread-safe SQLite interface for LinuxAuthGuard vault metadata."""

    # Argon2id parameters
    _TIME_COST   = 3
    _MEMORY_COST = 65536   # 64 MiB
    _PARALLELISM = 2
    _HASH_LEN    = 32
    _SALT_LEN    = 16

    def __init__(self, db_path: str = "/var/lib/linuxauthguard/vault.db") -> None:
        self._db_path = db_path
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    # ── Connection ─────────────────────────────────────────────────────────

    def _connect(self) -> sqlite3.Connection:
        con = sqlite3.connect(self._db_path, timeout=10)
        con.row_factory = sqlite3.Row
        con.execute("PRAGMA journal_mode=WAL")
        con.execute("PRAGMA foreign_keys=ON")
        con.execute("PRAGMA synchronous=NORMAL")
        return con

    def _init_db(self) -> None:
        with self._connect() as con:
            con.executescript(SCHEMA_SQL)

    # ── Password hashing ───────────────────────────────────────────────────

    def _hash_password(self, password: str) -> tuple[str, str]:
        """Return (hash_str, salt_hex) using Argon2id."""
        PasswordHasher, _, _ = _require_argon2()
        ph = PasswordHasher(
            time_cost=self._TIME_COST,
            memory_cost=self._MEMORY_COST,
            parallelism=self._PARALLELISM,
            hash_len=self._HASH_LEN,
            salt_len=self._SALT_LEN,
        )
        salt = secrets.token_bytes(self._SALT_LEN)
        hash_str = ph.hash(password, salt=salt)
        salt_hex = salt.hex()
        return hash_str, salt_hex

    def verify_password(self, path: str, password: str) -> bool:
        """Return True if password matches the hash stored for path."""
        PasswordHasher, VerifyMismatchError, VerificationError = _require_argon2()
        item = self.get_item(path)
        if item is None:
            return False
        ph = PasswordHasher(
            time_cost=self._TIME_COST,
            memory_cost=self._MEMORY_COST,
            parallelism=self._PARALLELISM,
        )
        try:
            return ph.verify(item.password_hash, password)
        except (VerifyMismatchError, VerificationError):
            return False
        except Exception:
            return False

    # ── CRUD ───────────────────────────────────────────────────────────────

    def add_item(
        self,
        path: str,
        password: str,
        owner_uid: int,
        recursive: bool = True,
        totp_required: bool = False,
    ) -> ProtectedItem:
        hash_str, salt_hex = self._hash_password(password)
        now = time.time()
        with self._connect() as con:
            cur = con.execute(
                """
                INSERT INTO protected_items
                    (path, password_hash, salt, totp_required, owner_uid,
                     recursive, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (path, hash_str, salt_hex, int(totp_required),
                 owner_uid, int(recursive), now, now),
            )
            row_id = cur.lastrowid
        item = self.get_item_by_id(row_id)
        assert item is not None
        return item

    def remove_item(self, path: str) -> bool:
        with self._connect() as con:
            cur = con.execute(
                "DELETE FROM protected_items WHERE path = ?", (path,)
            )
        return cur.rowcount > 0

    def get_item(self, path: str) -> Optional[ProtectedItem]:
        with self._connect() as con:
            row = con.execute(
                "SELECT * FROM protected_items WHERE path = ?", (path,)
            ).fetchone()
        return self._row_to_item(row) if row else None

    def get_item_by_id(self, item_id: int) -> Optional[ProtectedItem]:
        with self._connect() as con:
            row = con.execute(
                "SELECT * FROM protected_items WHERE id = ?", (item_id,)
            ).fetchone()
        return self._row_to_item(row) if row else None

    def get_parent_item(self, path: str) -> Optional[ProtectedItem]:
        """Find the nearest protected parent directory (for recursive protection)."""
        p = Path(path)
        for parent in p.parents:
            item = self.get_item(str(parent))
            if item is not None and item.recursive:
                return item
        return None

    def list_items(self) -> List[ProtectedItem]:
        with self._connect() as con:
            rows = con.execute(
                "SELECT * FROM protected_items ORDER BY path"
            ).fetchall()
        return [self._row_to_item(r) for r in rows]

    def update_password(self, path: str, new_password: str) -> bool:
        hash_str, salt_hex = self._hash_password(new_password)
        now = time.time()
        with self._connect() as con:
            cur = con.execute(
                """
                UPDATE protected_items
                SET password_hash = ?, salt = ?, updated_at = ?
                WHERE path = ?
                """,
                (hash_str, salt_hex, now, path),
            )
        return cur.rowcount > 0

    def update_totp(self, path: str, required: bool) -> bool:
        with self._connect() as con:
            cur = con.execute(
                "UPDATE protected_items SET totp_required = ?, updated_at = ? WHERE path = ?",
                (int(required), time.time(), path),
            )
        return cur.rowcount > 0

    # ── Access log ─────────────────────────────────────────────────────────

    def log_access(
        self,
        item_path: str,
        accessed_by: int,
        access_type: str,
        granted: bool,
    ) -> None:
        with self._connect() as con:
            con.execute(
                """
                INSERT INTO access_log (item_path, accessed_by, access_type, granted, timestamp)
                VALUES (?, ?, ?, ?, ?)
                """,
                (item_path, accessed_by, access_type, int(granted), time.time()),
            )

    def get_access_log(
        self,
        path: str,
        limit: int = 50,
    ) -> List[Dict[str, Any]]:
        with self._connect() as con:
            rows = con.execute(
                """
                SELECT accessed_by, access_type, granted, timestamp
                FROM access_log
                WHERE item_path = ?
                ORDER BY timestamp DESC
                LIMIT ?
                """,
                (path, limit),
            ).fetchall()
        return [dict(r) for r in rows]

    def get_access_stats(self, path: str) -> Dict[str, int]:
        with self._connect() as con:
            row = con.execute(
                """
                SELECT
                    COUNT(*) as total,
                    SUM(granted) as granted,
                    SUM(1 - granted) as denied
                FROM access_log
                WHERE item_path = ?
                """,
                (path,),
            ).fetchone()
        if row:
            return {
                "total":   row["total"] or 0,
                "granted": row["granted"] or 0,
                "denied":  row["denied"] or 0,
            }
        return {"total": 0, "granted": 0, "denied": 0}

    # ── User TOTP records ──────────────────────────────────────────────────

    def set_user_totp(self, username: str, enabled: bool, secret: Optional[str] = None) -> None:
        with self._connect() as con:
            con.execute(
                """
                INSERT INTO users (username, totp_enabled, totp_secret)
                VALUES (?, ?, ?)
                ON CONFLICT(username) DO UPDATE SET
                    totp_enabled = excluded.totp_enabled,
                    totp_secret  = excluded.totp_secret
                """,
                (username, int(enabled), secret),
            )

    def get_user_totp_secret(self, username: str) -> Optional[str]:
        with self._connect() as con:
            row = con.execute(
                "SELECT totp_secret FROM users WHERE username = ? AND totp_enabled = 1",
                (username,),
            ).fetchone()
        return row["totp_secret"] if row else None

    # ── Private helpers ────────────────────────────────────────────────────

    @staticmethod
    def _row_to_item(row: sqlite3.Row) -> ProtectedItem:
        return ProtectedItem(
            id=row["id"],
            path=row["path"],
            password_hash=row["password_hash"],
            salt=row["salt"],
            totp_required=bool(row["totp_required"]),
            owner_uid=row["owner_uid"],
            recursive=bool(row["recursive"]),
            created_at=float(row["created_at"]),
            updated_at=float(row["updated_at"]),
        )
