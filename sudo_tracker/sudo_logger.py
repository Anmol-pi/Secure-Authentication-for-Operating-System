#!/usr/bin/env python3
"""
sudo_logger.py — Sudo event logger for LinuxAuthGuard.

Listens on a UNIX socket for JSON payloads from pam_exec_hook.sh,
persists them to SQLite, and optionally drains the fallback flat-log file.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import signal
import socket
import sys
import threading
import time
from pathlib import Path

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

SOCKET_PATH = Path("/run/linuxauthguard/sudo_events.sock")
FALLBACK_LOG = Path("/var/log/linuxauthguard/sudo_fallback.log")
LOG_PATH = Path("/var/log/linuxauthguard/sudo_logger.log")
DB_PATH = Path("/var/lib/linuxauthguard/sudo_log.db")

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

def _setup_logging(verbose: bool = False) -> logging.Logger:
    LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
    logger = logging.getLogger("sudo_logger")
    logger.setLevel(logging.DEBUG if verbose else logging.INFO)
    fh = logging.FileHandler(LOG_PATH)
    fmt = logging.Formatter("[%(asctime)s] %(levelname)s %(message)s",
                            datefmt="%Y-%m-%dT%H:%M:%S")
    fh.setFormatter(fmt)
    logger.addHandler(fh)
    return logger


log = logging.getLogger("sudo_logger")

# ---------------------------------------------------------------------------
# DB helpers (deferred import of sudo_db to keep startup lean)
# ---------------------------------------------------------------------------

_db_lock = threading.Lock()
_con = None  # type: ignore[assignment]


def _get_con():  # type: ignore[return]
    global _con
    if _con is None:
        sys.path.insert(0, str(Path(__file__).parent))
        from sudo_db import SudoDatabase  # noqa: PLC0415
        _con = SudoDatabase(str(DB_PATH))
    return _con


# ---------------------------------------------------------------------------
# Event processing
# ---------------------------------------------------------------------------

def _process_payload(raw: str) -> None:
    """Parse and persist one JSON event payload."""
    raw = raw.strip()
    if not raw:
        return
    try:
        ev = json.loads(raw)
    except json.JSONDecodeError as exc:
        log.warning("Malformed payload: %s — %s", raw[:80], exc)
        return

    ts = ev.get("ts", time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()))
    user = ev.get("user", "unknown")
    target = ev.get("target", "root")
    command = ev.get("cmd", "unknown")
    cmd_path = ev.get("cmd_path", "")
    tty = ev.get("tty", "unknown")

    with _db_lock:
        db = _get_con()
        db.insert_event(
            timestamp=ts,
            username=user,
            target_user=target,
            command=command,
            cmd_path=cmd_path,
            tty=tty,
            granted=True,
        )

    log.info("Logged: user=%s cmd=%s", user, command[:80])

    # Trigger anomaly check in background
    t = threading.Thread(
        target=_check_anomaly,
        args=(cmd_path, user),
        daemon=True
    )
    t.start()


def _check_anomaly(cmd_path: str, user: str) -> None:
    """Delegate anomaly check to anomaly_detector module."""
    try:
        sys.path.insert(0, str(Path(__file__).parent))
        from anomaly_detector import check_and_alert  # noqa: PLC0415
        check_and_alert(cmd_path=cmd_path, username=user)
    except Exception as exc:
        log.debug("Anomaly check error: %s", exc)


# ---------------------------------------------------------------------------
# Fallback log drainer
# ---------------------------------------------------------------------------

def _drain_fallback_log() -> None:
    """Import lines from the flat fallback log into SQLite, then truncate."""
    if not FALLBACK_LOG.exists():
        return
    try:
        lines = FALLBACK_LOG.read_text().splitlines()
        if not lines:
            return
        for line in lines:
            _process_payload(line)
        FALLBACK_LOG.write_text("")
        log.info("Drained %d lines from fallback log.", len(lines))
    except OSError as exc:
        log.warning("Could not drain fallback log: %s", exc)


# ---------------------------------------------------------------------------
# UNIX socket server
# ---------------------------------------------------------------------------

class SudoLoggerServer:
    def __init__(self, verbose: bool = False) -> None:
        global log
        log = _setup_logging(verbose)
        self._stop = threading.Event()
        self._sock: socket.socket | None = None

    def _handle_client(self, conn: socket.socket, addr: object) -> None:
        try:
            buf = b""
            conn.settimeout(5.0)
            while True:
                chunk = conn.recv(4096)
                if not chunk:
                    break
                buf += chunk
            for line in buf.decode(errors="replace").splitlines():
                _process_payload(line)
        except OSError:
            pass
        finally:
            conn.close()

    def _signal_handler(self, signum: int, _frame: object) -> None:
        log.info("Signal %d received — stopping.", signum)
        self._stop.set()

    def run(self) -> None:
        signal.signal(signal.SIGTERM, self._signal_handler)
        signal.signal(signal.SIGINT, self._signal_handler)

        SOCKET_PATH.parent.mkdir(parents=True, exist_ok=True)
        if SOCKET_PATH.exists():
            SOCKET_PATH.unlink()

        self._sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self._sock.bind(str(SOCKET_PATH))
        os.chmod(str(SOCKET_PATH), 0o660)
        self._sock.listen(16)
        self._sock.settimeout(1.0)

        log.info("sudo_logger listening on %s", SOCKET_PATH)

        # Drain any events logged while we were offline
        _drain_fallback_log()

        # Periodic fallback drain thread
        def _periodic_drain() -> None:
            while not self._stop.is_set():
                time.sleep(60)
                _drain_fallback_log()

        drain_thread = threading.Thread(target=_periodic_drain, daemon=True)
        drain_thread.start()

        while not self._stop.is_set():
            try:
                conn, addr = self._sock.accept()
                t = threading.Thread(
                    target=self._handle_client,
                    args=(conn, addr),
                    daemon=True
                )
                t.start()
            except socket.timeout:
                continue
            except OSError as exc:
                if not self._stop.is_set():
                    log.error("Accept error: %s", exc)

        if SOCKET_PATH.exists():
            SOCKET_PATH.unlink()
        log.info("sudo_logger stopped.")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description="LinuxAuthGuard sudo event logger"
    )
    parser.add_argument("--verbose", "-v", action="store_true")
    args = parser.parse_args()
    SudoLoggerServer(verbose=args.verbose).run()


if __name__ == "__main__":
    main()
