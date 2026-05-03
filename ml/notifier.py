#!/usr/bin/env python3
"""
LinuxAuthGuard - Desktop Notification Sender
Sends libnotify desktop notifications about ML sensitivity findings
and security events.
"""

from __future__ import annotations

import logging
import subprocess
from typing import Optional

logger = logging.getLogger("linuxauthguard.ml.notifier")

APP_NAME    = "LinuxAuthGuard"
APP_ICON    = "security-high"
URGENCY_LOW    = "low"
URGENCY_NORMAL = "normal"
URGENCY_HIGH   = "critical"


def notify(
    summary: str,
    body: str,
    urgency: str = URGENCY_NORMAL,
    timeout_ms: int = 8000,
    icon: str = APP_ICON,
) -> bool:
    """
    Send a desktop notification using notify-send (libnotify).
    Returns True on success.
    """
    try:
        cmd = [
            "notify-send",
            "--app-name", APP_NAME,
            "--icon", icon,
            f"--urgency={urgency}",
            f"--expire-time={timeout_ms}",
            summary,
            body,
        ]
        result = subprocess.run(
            cmd,
            capture_output=True,
            timeout=10,
            check=False,
        )
        if result.returncode != 0:
            logger.debug(
                "notify-send returned %d: %s",
                result.returncode,
                result.stderr.decode(errors="replace"),
            )
            # Try fallback via GNotification / gi.repository.Notify
            return _notify_via_gi(summary, body, urgency)
        return True
    except FileNotFoundError:
        logger.warning("notify-send not found; trying gi.repository.Notify")
        return _notify_via_gi(summary, body, urgency)
    except subprocess.TimeoutExpired:
        logger.warning("notify-send timed out")
        return False
    except Exception as e:
        logger.warning("Notification failed: %s", e)
        return False


def _notify_via_gi(summary: str, body: str, urgency: str) -> bool:
    """Fallback: use gi.repository.Notify (libnotify via GI)."""
    try:
        import gi
        gi.require_version("Notify", "0.7")
        from gi.repository import Notify
        if not Notify.is_initted():
            Notify.init(APP_NAME)
        n = Notify.Notification.new(summary, body, APP_ICON)
        urgency_map = {
            URGENCY_LOW:    Notify.Urgency.LOW,
            URGENCY_NORMAL: Notify.Urgency.NORMAL,
            URGENCY_HIGH:   Notify.Urgency.CRITICAL,
        }
        n.set_urgency(urgency_map.get(urgency, Notify.Urgency.NORMAL))
        n.show()
        return True
    except Exception as e:
        logger.debug("GI notify fallback failed: %s", e)
        return False


# ── Specific notification types ───────────────────────────────────────────────

def notify_ml_sensitive_file(
    file_path: str,
    confidence: float,
) -> None:
    """Notify user that ML flagged a file as sensitive."""
    short_path = file_path
    if len(short_path) > 60:
        short_path = "…" + short_path[-59:]

    summary = "LinuxAuthGuard is learning"
    body = (
        f"<b>{short_path}</b> appears to be accessed with elevated privileges often.\n"
        f"Confidence: {confidence:.0%}. "
        "Consider adding file protection."
    )
    notify(summary, body, urgency=URGENCY_NORMAL, timeout_ms=12000)


def notify_ml_sensitive_folder(
    folder_path: str,
    sensitive_file_count: int,
) -> None:
    """Notify user that ML flagged a folder as a sensitive zone."""
    short_path = folder_path
    if len(short_path) > 60:
        short_path = "…" + short_path[-59:]

    summary = "LinuxAuthGuard: Sensitive Zone Detected"
    body = (
        f"<b>{short_path}</b> contains {sensitive_file_count} file(s) "
        "frequently accessed with elevated privileges. "
        "Consider protecting this folder."
    )
    notify(summary, body, urgency=URGENCY_NORMAL, timeout_ms=15000)


def notify_sudo_anomaly(
    username: str,
    file_path: str,
    command: str,
) -> None:
    """Notify that an anomalous sudo access was detected."""
    short_path = file_path if len(file_path) <= 50 else "…" + file_path[-49:]
    summary = "⚠ LinuxAuthGuard: Sudo Anomaly Detected"
    body = (
        f"User <b>{username}</b> used sudo on a path that has never been "
        f"accessed this way before:\n<tt>{short_path}</tt>\n"
        f"Command: <tt>{command[:80]}</tt>"
    )
    notify(summary, body, urgency=URGENCY_HIGH, timeout_ms=20000)


def notify_auth_lockout(username: str, minutes: int) -> None:
    """Notify that an account has been locked out."""
    summary = "🔒 LinuxAuthGuard: Account Locked"
    body = (
        f"Too many failed login attempts for <b>{username}</b>.\n"
        f"Account locked for {minutes} minute(s)."
    )
    notify(summary, body, urgency=URGENCY_HIGH, timeout_ms=15000)


def notify_file_protected(path: str) -> None:
    """Notify that a file has been successfully protected."""
    short_path = path if len(path) <= 60 else "…" + path[-59:]
    summary = "✓ LinuxAuthGuard: Protection Added"
    body = f"<tt>{short_path}</tt> is now password-protected."
    notify(summary, body, urgency=URGENCY_LOW, timeout_ms=6000)
