#!/usr/bin/env python3
"""
anomaly_detector.py — Anomaly detection for sudo events in LinuxAuthGuard.

Identifies unusual sudo usage patterns:
  - sudo at unusual hours (outside user's normal window)
  - sudo on paths never previously accessed via sudo
  - burst of sudo events in a short window
"""

from __future__ import annotations

import logging
import sqlite3
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

DB_PATH = Path("/var/lib/linuxauthguard/sudo_log.db")
LOG_PATH = Path("/var/log/linuxauthguard/anomaly.log")

BURST_WINDOW_SECONDS: int = 60
BURST_THRESHOLD: int = 10
UNUSUAL_HOUR_SIGMA: float = 2.5  # std-devs from mean access hour

log = logging.getLogger("anomaly_detector")


def _setup_logging() -> None:
    if log.handlers:
        return
    LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
    fh = logging.FileHandler(LOG_PATH)
    fh.setFormatter(logging.Formatter(
        "[%(asctime)s] %(levelname)s %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S"
    ))
    log.setLevel(logging.INFO)
    log.addHandler(fh)


def _get_db() -> sqlite3.Connection:
    con = sqlite3.connect(str(DB_PATH), check_same_thread=False)
    con.execute("PRAGMA journal_mode=WAL")
    return con


# ---------------------------------------------------------------------------
# Anomaly checks
# ---------------------------------------------------------------------------

def _is_new_path(con: sqlite3.Connection, cmd_path: str) -> bool:
    """True if cmd_path has never been seen in sudo events before today."""
    if not cmd_path:
        return False
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    row = con.execute(
        """SELECT COUNT(*) FROM sudo_events
           WHERE cmd_path = ? AND date(timestamp) < date(?)""",
        (cmd_path, today)
    ).fetchone()
    return (row[0] == 0) if row else True


def _is_unusual_hour(con: sqlite3.Connection, username: str) -> bool:
    """True if current UTC hour is well outside user's historical sudo hours."""
    rows = con.execute(
        """SELECT CAST(strftime('%H', timestamp) AS INTEGER)
           FROM sudo_events WHERE username = ?""",
        (username,)
    ).fetchall()
    if len(rows) < 10:
        return False  # not enough data to establish a baseline
    import statistics  # noqa: PLC0415
    hours = [r[0] for r in rows]
    mean = statistics.mean(hours)
    stdev = statistics.stdev(hours) or 1.0
    current_hour = datetime.now(timezone.utc).hour
    return abs(current_hour - mean) > (UNUSUAL_HOUR_SIGMA * stdev)


def _is_burst(con: sqlite3.Connection, username: str) -> bool:
    """True if the user has issued more than BURST_THRESHOLD sudo commands
    within the last BURST_WINDOW_SECONDS."""
    cutoff = time.strftime(
        "%Y-%m-%dT%H:%M:%SZ",
        time.gmtime(time.time() - BURST_WINDOW_SECONDS)
    )
    row = con.execute(
        """SELECT COUNT(*) FROM sudo_events
           WHERE username = ? AND timestamp >= ?""",
        (username, cutoff)
    ).fetchone()
    return (row[0] >= BURST_THRESHOLD) if row else False


# ---------------------------------------------------------------------------
# Flag helpers
# ---------------------------------------------------------------------------

def _flag_anomaly(con: sqlite3.Connection, reason: str,
                  username: str, cmd_path: str) -> None:
    ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    con.execute(
        """UPDATE sudo_events
           SET anomaly_flag = 1, anomaly_reason = ?
           WHERE username = ? AND cmd_path = ?
             AND timestamp = (
               SELECT MAX(timestamp) FROM sudo_events
               WHERE username = ? AND cmd_path = ?
             )""",
        (reason, username, cmd_path, username, cmd_path)
    )
    con.commit()
    log.warning("ANOMALY [%s] user=%s path=%s", reason, username, cmd_path)


def _send_notification(reason: str, username: str, cmd_path: str) -> None:
    try:
        sys.path.insert(0, str(Path(__file__).parent.parent / "ml"))
        from notifier import notify_sudo_anomaly  # noqa: PLC0415
        notify_sudo_anomaly(username=username, cmd_path=cmd_path, reason=reason)
    except Exception as exc:
        log.debug("Notification error: %s", exc)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def check_and_alert(cmd_path: str, username: str) -> None:
    """Run all anomaly checks and alert if anything is found."""
    _setup_logging()
    try:
        con = _get_db()
    except Exception as exc:
        log.error("DB open error: %s", exc)
        return

    reasons: list[str] = []

    if _is_new_path(con, cmd_path):
        reasons.append("NEW_PATH")

    if _is_unusual_hour(con, username):
        reasons.append("UNUSUAL_HOUR")

    if _is_burst(con, username):
        reasons.append("BURST")

    for reason in reasons:
        _flag_anomaly(con, reason, username, cmd_path)
        _send_notification(reason, username, cmd_path)

    con.close()


def get_recent_anomalies(limit: int = 50) -> list[dict]:
    """Return recent anomaly events as a list of dicts (for dashboard)."""
    try:
        con = _get_db()
        rows = con.execute(
            """SELECT timestamp, username, command, cmd_path,
                      anomaly_flag, anomaly_reason
               FROM sudo_events
               WHERE anomaly_flag = 1
               ORDER BY timestamp DESC
               LIMIT ?""",
            (limit,)
        ).fetchall()
        con.close()
        keys = ["timestamp", "username", "command", "cmd_path",
                "anomaly_flag", "anomaly_reason"]
        return [dict(zip(keys, r)) for r in rows]
    except Exception as exc:
        log.error("get_recent_anomalies error: %s", exc)
        return []
