#!/usr/bin/env python3
"""
ml_service.py — Background ML watcher service for LinuxAuthGuard.

Watches inotify events, logs file access patterns, periodically retrains
the sensitivity classifier, and emits desktop notifications for flagged files.
"""

from __future__ import annotations

import argparse
import logging
import os
import signal
import sqlite3
import sys
import threading
import time
from pathlib import Path
from typing import Optional

# ---------------------------------------------------------------------------
# Paths and constants
# ---------------------------------------------------------------------------

DB_PATH = Path("/var/lib/linuxauthguard/sudo_log.db")
MODEL_PATH = Path("/var/lib/linuxauthguard/model.pkl")
LOG_PATH = Path("/var/log/linuxauthguard/ml_service.log")
WATCH_ROOTS: list[str] = ["/home", "/root", "/etc", "/var"]
RETRAIN_INTERVAL: int = 86400          # 24 hours in seconds
NOTIFICATION_CONFIDENCE: float = 0.80  # threshold for flagging
POLL_INTERVAL: float = 0.5             # inotify read timeout (seconds)

# ---------------------------------------------------------------------------
# Logging setup
# ---------------------------------------------------------------------------

def _setup_logging(verbose: bool = False) -> logging.Logger:
    LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
    level = logging.DEBUG if verbose else logging.INFO
    logger = logging.getLogger("ml_service")
    logger.setLevel(level)

    fh = logging.FileHandler(LOG_PATH)
    fh.setLevel(level)
    fmt = logging.Formatter("[%(asctime)s] %(levelname)s %(message)s",
                            datefmt="%Y-%m-%dT%H:%M:%S")
    fh.setFormatter(fmt)
    logger.addHandler(fh)

    sh = logging.StreamHandler(sys.stdout)
    sh.setLevel(logging.WARNING)
    sh.setFormatter(fmt)
    logger.addHandler(sh)

    return logger


log: logging.Logger = logging.getLogger("ml_service")

# ---------------------------------------------------------------------------
# Database helpers
# ---------------------------------------------------------------------------

def _get_db(path: Path = DB_PATH) -> sqlite3.Connection:
    path.parent.mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(str(path), check_same_thread=False)
    con.execute("PRAGMA journal_mode=WAL")
    con.execute("PRAGMA synchronous=NORMAL")
    con.execute("""
        CREATE TABLE IF NOT EXISTS access_log (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            path        TEXT    NOT NULL,
            is_sudo     INTEGER NOT NULL DEFAULT 0,
            uid         INTEGER NOT NULL DEFAULT 0,
            accessed_at TEXT    NOT NULL
        )
    """)
    con.execute("""
        CREATE TABLE IF NOT EXISTS ml_flags (
            path        TEXT    PRIMARY KEY,
            confidence  REAL    NOT NULL,
            accepted    INTEGER,          -- NULL=pending, 1=accepted, 0=rejected
            flagged_at  TEXT    NOT NULL
        )
    """)
    con.commit()
    return con


def _log_access(con: sqlite3.Connection, path: str,
                is_sudo: bool, uid: int) -> None:
    ts = time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime())
    con.execute(
        "INSERT INTO access_log (path, is_sudo, uid, accessed_at) VALUES (?,?,?,?)",
        (path, int(is_sudo), uid, ts)
    )
    con.commit()


def _upsert_flag(con: sqlite3.Connection, path: str,
                 confidence: float) -> None:
    ts = time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime())
    con.execute("""
        INSERT INTO ml_flags (path, confidence, flagged_at)
        VALUES (?, ?, ?)
        ON CONFLICT(path) DO UPDATE SET
            confidence  = excluded.confidence,
            flagged_at  = excluded.flagged_at
    """, (path, confidence, ts))
    con.commit()


# ---------------------------------------------------------------------------
# Inotify watcher
# ---------------------------------------------------------------------------

# We use the inotify_simple package when available, falling back to a pure
# ctypes implementation so the service can start even without the package.

try:
    import inotify_simple  # type: ignore
    _INOTIFY_SIMPLE = True
except ImportError:
    _INOTIFY_SIMPLE = False

import ctypes
import struct

_IN_ACCESS    = 0x00000001
_IN_OPEN      = 0x00000020
_IN_CLOSE_NOWRITE = 0x00000010
_IN_CLOSE_WRITE   = 0x00000008
_WATCH_MASK   = _IN_ACCESS | _IN_OPEN | _IN_CLOSE_WRITE

_EVENT_STRUCT = struct.Struct("iIII")
_EVENT_SIZE   = _EVENT_STRUCT.size


class _InotifyFallback:
    """Minimal ctypes inotify wrapper (no dependency on inotify_simple)."""

    def __init__(self) -> None:
        self._libc = ctypes.CDLL("libc.so.6", use_errno=True)
        self._fd: int = self._libc.inotify_init1(os.O_NONBLOCK)
        if self._fd < 0:
            raise OSError(ctypes.get_errno(), "inotify_init1 failed")
        self._wd_to_path: dict[int, str] = {}

    def add_watch(self, path: str, mask: int) -> int:
        wd = self._libc.inotify_add_watch(
            self._fd,
            path.encode(),
            ctypes.c_uint32(mask)
        )
        if wd >= 0:
            self._wd_to_path[wd] = path
        return wd

    def read_events(self, timeout_s: float = 0.5) -> list[tuple[str, int]]:
        """Return list of (path, mask) tuples."""
        import select
        r, _, _ = select.select([self._fd], [], [], timeout_s)
        if not r:
            return []
        raw = os.read(self._fd, 4096)
        events: list[tuple[str, int]] = []
        offset = 0
        while offset + _EVENT_SIZE <= len(raw):
            wd, mask, _cookie, name_len = _EVENT_STRUCT.unpack_from(raw, offset)
            offset += _EVENT_SIZE
            name = b""
            if name_len:
                name = raw[offset: offset + name_len].rstrip(b"\x00")
                offset += name_len
            base = self._wd_to_path.get(wd, "")
            if base:
                full = os.path.join(base, name.decode(errors="replace")) if name else base
                events.append((full, mask))
        return events

    def close(self) -> None:
        os.close(self._fd)


class InotifyWatcher:
    """High-level watcher that adds watches for a list of root directories."""

    def __init__(self, roots: list[str]) -> None:
        self._roots = roots
        if _INOTIFY_SIMPLE:
            self._inotify = inotify_simple.INotify()
        else:
            self._inotify = _InotifyFallback()   # type: ignore[assignment]
        self._wd_map: dict[int, str] = {}
        self._add_roots()

    def _add_roots(self) -> None:
        mask = _WATCH_MASK
        for root in self._roots:
            if not os.path.isdir(root):
                continue
            try:
                if _INOTIFY_SIMPLE:
                    wd = self._inotify.add_watch(root, mask)
                else:
                    wd = self._inotify.add_watch(root, mask)
                self._wd_map[wd] = root
                log.debug("Watching %s (wd=%d)", root, wd)
            except OSError as exc:
                log.warning("Cannot watch %s: %s", root, exc)

    def read_events(self) -> list[tuple[str, int]]:
        if _INOTIFY_SIMPLE:
            evs = self._inotify.read(timeout=int(POLL_INTERVAL * 1000))
            out: list[tuple[str, int]] = []
            for ev in evs:
                base = self._wd_map.get(ev.wd, "")
                name = ev.name if ev.name else ""
                path = os.path.join(base, name) if name else base
                out.append((path, ev.mask))
            return out
        else:
            return self._inotify.read_events(POLL_INTERVAL)  # type: ignore[attr-defined]

    def close(self) -> None:
        self._inotify.close()


# ---------------------------------------------------------------------------
# ML integration (lazy imports)
# ---------------------------------------------------------------------------

def _load_classifier():  # type: ignore[return]
    """Lazy-load the SensitivityClassifier only when needed."""
    sys.path.insert(0, str(Path(__file__).parent))
    from classifier import SensitivityClassifier  # noqa: PLC0415
    clf = SensitivityClassifier(model_path=str(MODEL_PATH))
    clf.load()
    return clf


def _retrain(con: sqlite3.Connection) -> None:
    """Trigger model retraining in a subprocess to avoid memory bloat."""
    import subprocess  # noqa: PLC0415
    trainer = Path(__file__).parent / "trainer.py"
    try:
        subprocess.run(
            [sys.executable, str(trainer), "--once"],
            timeout=300,
            check=True
        )
        log.info("Model retrained successfully.")
    except subprocess.CalledProcessError as exc:
        log.error("Retraining failed: %s", exc)
    except subprocess.TimeoutExpired:
        log.error("Retraining timed out.")


# ---------------------------------------------------------------------------
# Classification worker
# ---------------------------------------------------------------------------

class ClassificationWorker(threading.Thread):
    """Pulls paths from a queue, classifies them, emits notifications."""

    def __init__(self, con: sqlite3.Connection,
                 queue: "threading.Queue[Optional[str]]") -> None:
        super().__init__(name="ClassificationWorker", daemon=True)
        self._con = con
        self._queue = queue
        self._clf: Optional[object] = None
        self._clf_loaded_at: float = 0.0
        self._recently_notified: set[str] = set()

    def _get_clf(self):  # type: ignore[return]
        now = time.monotonic()
        # Reload model every hour to pick up retrained version
        if self._clf is None or (now - self._clf_loaded_at) > 3600:
            try:
                self._clf = _load_classifier()
                self._clf_loaded_at = now
                log.info("Classifier (re)loaded.")
            except Exception as exc:
                log.warning("Could not load classifier: %s", exc)
                self._clf = None
        return self._clf

    def run(self) -> None:
        from notifier import notify_sensitive_file  # noqa: PLC0415
        while True:
            path = self._queue.get()
            if path is None:
                break
            if path in self._recently_notified:
                continue
            clf = self._get_clf()
            if clf is None:
                continue
            try:
                confidence = clf.predict([path])[0]
                if confidence >= NOTIFICATION_CONFIDENCE:
                    log.info("Flagged %s (conf=%.2f)", path, confidence)
                    _upsert_flag(self._con, path, confidence)
                    if path not in self._recently_notified:
                        notify_sensitive_file(path, confidence)
                        self._recently_notified.add(path)
                        # Limit cache size
                        if len(self._recently_notified) > 500:
                            self._recently_notified.pop()
            except Exception as exc:
                log.debug("Classification error for %s: %s", path, exc)


# ---------------------------------------------------------------------------
# Main service loop
# ---------------------------------------------------------------------------

class MLService:
    def __init__(self, verbose: bool = False) -> None:
        global log
        log = _setup_logging(verbose)
        self._con = _get_db()
        self._watcher: Optional[InotifyWatcher] = None
        self._stop_event = threading.Event()
        self._queue: "threading.Queue[Optional[str]]" = __import__("queue").Queue(maxsize=2000)
        self._worker = ClassificationWorker(self._con, self._queue)
        self._last_retrain = time.monotonic()

    def _handle_signal(self, signum: int, _frame: object) -> None:
        log.info("Received signal %d — shutting down.", signum)
        self._stop_event.set()

    def run(self) -> None:
        signal.signal(signal.SIGTERM, self._handle_signal)
        signal.signal(signal.SIGINT, self._handle_signal)

        log.info("ML service starting. Watching: %s", WATCH_ROOTS)
        self._worker.start()

        try:
            self._watcher = InotifyWatcher(WATCH_ROOTS)
        except Exception as exc:
            log.error("Failed to initialise inotify watcher: %s", exc)
            return

        while not self._stop_event.is_set():
            try:
                events = self._watcher.read_events()
            except Exception as exc:
                log.error("inotify read error: %s", exc)
                time.sleep(1.0)
                continue

            for path, mask in events:
                if not path or not os.path.isfile(path):
                    continue
                is_sudo = os.environ.get("SUDO_USER") is not None
                uid = os.getuid()
                _log_access(self._con, path, is_sudo, uid)
                try:
                    self._queue.put_nowait(path)
                except Exception:
                    pass  # queue full — drop silently

            # Periodic retraining
            now = time.monotonic()
            if (now - self._last_retrain) >= RETRAIN_INTERVAL:
                log.info("Triggering scheduled retraining.")
                t = threading.Thread(target=_retrain, args=(self._con,),
                                     daemon=True)
                t.start()
                self._last_retrain = now

        # Shutdown
        self._queue.put(None)
        self._worker.join(timeout=5)
        if self._watcher:
            self._watcher.close()
        self._con.close()
        log.info("ML service stopped.")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(description="LinuxAuthGuard ML watcher service")
    parser.add_argument("--verbose", "-v", action="store_true",
                        help="Enable debug logging")
    parser.add_argument("--retrain-now", action="store_true",
                        help="Retrain model immediately and exit")
    args = parser.parse_args()

    if args.retrain_now:
        con = _get_db()
        _retrain(con)
        con.close()
        return

    svc = MLService(verbose=args.verbose)
    svc.run()


if __name__ == "__main__":
    main()
