#!/usr/bin/env python3
"""
sudo_db.py — SQLite interface for LinuxAuthGuard sudo event log.
"""

from __future__ import annotations

import sqlite3
import time
from pathlib import Path
from typing import Any, Optional


class SudoDatabase:
    """Manages the sudo_events table and related queries."""

    DB_PATH = "/var/lib/linuxauthguard/sudo_log.db"

    def __init__(self, path: Optional[str] = None) -> None:
        self._path = path or self.DB_PATH
        Path(self._path).parent.mkdir(parents=True, exist_ok=True)
        self._con = sqlite3.connect(self._path, check_same_thread=False)
        self._con.row_factory = sqlite3.Row
        self._con.execute("PRAGMA journal_mode=WAL")
        self._con.execute("PRAGMA synchronous=NORMAL")
        self._migrate()

    # ------------------------------------------------------------------
    # Schema
    # ------------------------------------------------------------------

    def _migrate(self) -> None:
        self._con.executescript("""
            CREATE TABLE IF NOT EXISTS sudo_events (
                id             INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp      TEXT    NOT NULL,
                username       TEXT    NOT NULL,
                target_user    TEXT    NOT NULL DEFAULT 'root',
                command        TEXT    NOT NULL,
                cmd_path       TEXT    NOT NULL DEFAULT '',
                tty            TEXT    NOT NULL DEFAULT '',
                granted        INTEGER NOT NULL DEFAULT 1,
                anomaly_flag   INTEGER NOT NULL DEFAULT 0,
                anomaly_reason TEXT    NOT NULL DEFAULT ''
            );
            CREATE INDEX IF NOT EXISTS idx_sudo_ts
                ON sudo_events(timestamp);
            CREATE INDEX IF NOT EXISTS idx_sudo_user
                ON sudo_events(username);
            CREATE INDEX IF NOT EXISTS idx_sudo_path
                ON sudo_events(cmd_path);
            CREATE TABLE IF NOT EXISTS path_stats (
                cmd_path      TEXT PRIMARY KEY,
                first_seen    TEXT NOT NULL,
                last_seen     TEXT NOT NULL,
                access_count  INTEGER NOT NULL DEFAULT 1
            );
        """)
        self._con.commit()

    # ------------------------------------------------------------------
    # Write
    # ------------------------------------------------------------------

    def insert_event(
        self,
        *,
        timestamp: Optional[str] = None,
        username: str,
        target_user: str = "root",
        command: str,
        cmd_path: str = "",
        tty: str = "",
        granted: bool = True,
    ) -> int:
        ts = timestamp or time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        cur = self._con.execute(
            """INSERT INTO sudo_events
               (timestamp, username, target_user, command, cmd_path, tty, granted)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (ts, username, target_user, command, cmd_path, tty, int(granted))
        )
        # Update path_stats
        if cmd_path:
            self._con.execute(
                """INSERT INTO path_stats (cmd_path, first_seen, last_seen, access_count)
                   VALUES (?, ?, ?, 1)
                   ON CONFLICT(cmd_path) DO UPDATE SET
                     last_seen    = excluded.last_seen,
                     access_count = access_count + 1""",
                (cmd_path, ts, ts)
            )
        self._con.commit()
        return cur.lastrowid  # type: ignore[return-value]

    # ------------------------------------------------------------------
    # Read
    # ------------------------------------------------------------------

    def get_recent_events(self, limit: int = 100) -> list[dict[str, Any]]:
        rows = self._con.execute(
            """SELECT * FROM sudo_events
               ORDER BY timestamp DESC LIMIT ?""",
            (limit,)
        ).fetchall()
        return [dict(r) for r in rows]

    def get_events_by_user(self, username: str,
                           limit: int = 200) -> list[dict[str, Any]]:
        rows = self._con.execute(
            """SELECT * FROM sudo_events WHERE username = ?
               ORDER BY timestamp DESC LIMIT ?""",
            (username, limit)
        ).fetchall()
        return [dict(r) for r in rows]

    def get_top_paths(self, limit: int = 20) -> list[dict[str, Any]]:
        rows = self._con.execute(
            """SELECT cmd_path, access_count, first_seen, last_seen
               FROM path_stats
               ORDER BY access_count DESC LIMIT ?""",
            (limit,)
        ).fetchall()
        return [dict(r) for r in rows]

    def get_anomalies(self, limit: int = 50) -> list[dict[str, Any]]:
        rows = self._con.execute(
            """SELECT * FROM sudo_events WHERE anomaly_flag = 1
               ORDER BY timestamp DESC LIMIT ?""",
            (limit,)
        ).fetchall()
        return [dict(r) for r in rows]

    def get_hourly_counts(self, days: int = 7) -> list[dict[str, Any]]:
        """Return sudo counts grouped by hour for the last N days."""
        cutoff = time.strftime(
            "%Y-%m-%dT%H:%M:%SZ",
            time.gmtime(time.time() - days * 86400)
        )
        rows = self._con.execute(
            """SELECT strftime('%Y-%m-%dT%H:00:00Z', timestamp) AS hour,
                      COUNT(*) AS cnt
               FROM sudo_events
               WHERE timestamp >= ?
               GROUP BY hour
               ORDER BY hour""",
            (cutoff,)
        ).fetchall()
        return [dict(r) for r in rows]

    def get_user_summary(self) -> list[dict[str, Any]]:
        """Return per-user sudo counts and anomaly counts."""
        rows = self._con.execute(
            """SELECT username,
                      COUNT(*) AS total,
                      SUM(anomaly_flag) AS anomalies,
                      MAX(timestamp) AS last_seen
               FROM sudo_events
               GROUP BY username
               ORDER BY total DESC"""
        ).fetchall()
        return [dict(r) for r in rows]

    def close(self) -> None:
        self._con.close()
