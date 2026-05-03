#!/usr/bin/env python3
"""
LinuxAuthGuard - File Feature Extractor
Extracts numeric features from a file path and access history
for use by the ML sensitivity classifier.
"""

from __future__ import annotations

import logging
import math
import mimetypes
import os
import re
import time
from pathlib import Path
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger("linuxauthguard.ml.features")

# ── Feature names (must match order of extract() output) ────────────────────

FEATURE_NAMES: List[str] = [
    # Path/filename features
    "path_depth",
    "filename_length",
    "extension_sensitivity",
    "has_sensitive_keyword",
    "is_hidden",
    "in_home_dir",
    "in_etc_dir",
    "in_var_dir",
    "in_tmp_dir",
    # File attribute features
    "file_size_log",
    "days_since_modified",
    "days_since_accessed",
    "is_executable",
    "is_setuid",
    "is_world_readable",
    "is_world_writable",
    # MIME type features
    "mime_is_text",
    "mime_is_binary",
    "mime_is_archive",
    "mime_is_database",
    "mime_is_cert",
    # Access pattern features (from sudo_log.db)
    "sudo_access_count",
    "normal_access_count",
    "sudo_ratio",
    "unique_sudo_users",
    "last_sudo_days_ago",
]


# Sensitive file extensions (score 0.0–1.0)
_SENSITIVE_EXTENSIONS: Dict[str, float] = {
    # Credentials / secrets
    ".pem": 1.0, ".key": 1.0, ".pfx": 1.0, ".p12": 1.0,
    ".crt": 0.9, ".cer": 0.9, ".der": 0.9,
    ".gpg": 0.9, ".asc": 0.8, ".sig": 0.7,
    ".kdbx": 1.0, ".keepass": 1.0,
    ".passwd": 1.0, ".shadow": 1.0, ".htpasswd": 0.9,
    # Databases
    ".db": 0.8, ".sqlite": 0.8, ".sqlite3": 0.8,
    ".mdb": 0.7, ".accdb": 0.7,
    # Private keys and configs
    ".env": 0.9, ".secret": 1.0,
    ".conf": 0.5, ".config": 0.5, ".cfg": 0.5, ".ini": 0.4,
    ".yaml": 0.4, ".yml": 0.4, ".toml": 0.4,
    # Logs (may contain sensitive data)
    ".log": 0.5, ".audit": 0.8,
    # Archives (opaque)
    ".tar": 0.3, ".gz": 0.3, ".zip": 0.3, ".7z": 0.4, ".rar": 0.4,
    # Office (may contain sensitive business data)
    ".pdf": 0.4, ".doc": 0.4, ".docx": 0.4,
    ".xls": 0.5, ".xlsx": 0.5, ".csv": 0.5,
    # Binaries (less sensitive per se)
    ".so": 0.2, ".bin": 0.2, ".exe": 0.1,
}

_SENSITIVE_KEYWORDS: List[str] = [
    "password", "passwd", "secret", "token", "key", "cred",
    "auth", "cert", "private", "priv", "ssh", "id_rsa", "id_ed25519",
    "wallet", "vault", "master", "admin", "root", "backup",
    "shadow", "sudoers", "ssl", "tls", "pgp", "gpg",
    "api_key", "apikey", "access_key", "secret_key",
]


def extract(
    file_path: str,
    access_stats: Optional[Dict[str, int]] = None,
) -> Tuple[List[float], List[str]]:
    """
    Extract feature vector for a file.

    Args:
        file_path:    Absolute path to the file.
        access_stats: Dict with keys: sudo_count, normal_count,
                      unique_sudo_users, last_sudo_timestamp.

    Returns:
        (feature_vector, feature_names)
    """
    path = Path(file_path)
    stats = access_stats or {}

    features: List[float] = []

    # ── Path / filename features ─────────────────────────────────────────────

    # Path depth (relative to /)
    depth = len(path.parts) - 1
    features.append(float(min(depth, 20)))

    # Filename length
    features.append(float(min(len(path.name), 100)))

    # Extension sensitivity score
    ext = path.suffix.lower()
    features.append(_SENSITIVE_EXTENSIONS.get(ext, 0.1))

    # Has sensitive keyword in filename or path
    combined = file_path.lower()
    kw_hit = any(kw in combined for kw in _SENSITIVE_KEYWORDS)
    features.append(1.0 if kw_hit else 0.0)

    # Is hidden file (starts with .)
    features.append(1.0 if path.name.startswith(".") else 0.0)

    # Directory context
    path_str = str(path)
    features.append(1.0 if "/home/" in path_str else 0.0)
    features.append(1.0 if path_str.startswith("/etc/") else 0.0)
    features.append(1.0 if path_str.startswith("/var/") else 0.0)
    features.append(1.0 if path_str.startswith("/tmp/") else 0.0)

    # ── File attributes ──────────────────────────────────────────────────────

    try:
        stat = os.stat(file_path)
        size_bytes = stat.st_size
        mode = stat.st_mode

        # File size (log-scaled to [0, 1] roughly)
        features.append(math.log1p(size_bytes) / math.log1p(1e12))

        now = time.time()
        features.append((now - stat.st_mtime) / 86400.0)    # Days since modified
        features.append((now - stat.st_atime) / 86400.0)    # Days since accessed

        features.append(1.0 if (mode & 0o111) else 0.0)     # Executable
        features.append(1.0 if (mode & 0o4000) else 0.0)    # SUID
        features.append(1.0 if (mode & 0o004) else 0.0)     # World-readable
        features.append(1.0 if (mode & 0o002) else 0.0)     # World-writable

    except (FileNotFoundError, PermissionError, OSError):
        # File inaccessible — use neutral defaults
        features.extend([0.0, 30.0, 30.0, 0.0, 0.0, 0.0, 0.0])

    # ── MIME type ────────────────────────────────────────────────────────────

    mime_type, _ = mimetypes.guess_type(file_path)
    mime = mime_type or ""

    features.append(1.0 if mime.startswith("text/") else 0.0)
    features.append(1.0 if mime.startswith("application/octet") else 0.0)
    features.append(
        1.0 if any(a in mime for a in ["zip", "tar", "gzip", "rar", "7z"]) else 0.0
    )
    features.append(
        1.0 if any(d in mime for d in ["sqlite", "sql", "database"]) else 0.0
    )
    features.append(
        1.0 if any(c in mime for c in ["pkcs", "x509", "pem", "certificate"]) else 0.0
    )

    # ── Access pattern features ───────────────────────────────────────────────

    sudo_count    = float(stats.get("sudo_count", 0))
    normal_count  = float(stats.get("normal_count", 0))
    total_count   = sudo_count + normal_count

    features.append(min(sudo_count, 1000.0) / 100.0)    # sudo_access_count (scaled)
    features.append(min(normal_count, 1000.0) / 100.0)  # normal_access_count (scaled)
    features.append(sudo_count / max(total_count, 1.0))  # sudo_ratio

    unique_sudo = float(stats.get("unique_sudo_users", 0))
    features.append(min(unique_sudo, 10.0))

    last_sudo_ts = stats.get("last_sudo_timestamp", 0)
    if last_sudo_ts:
        days_ago = (time.time() - last_sudo_ts) / 86400.0
        features.append(min(days_ago, 365.0))
    else:
        features.append(365.0)  # Never sudo-accessed

    assert len(features) == len(FEATURE_NAMES), (
        f"Feature length mismatch: {len(features)} != {len(FEATURE_NAMES)}"
    )
    return features, FEATURE_NAMES


def extract_from_row(row: Dict[str, object]) -> List[float]:
    """
    Extract features from a pre-fetched database row.
    Useful for batch extraction without filesystem access.
    """
    file_path = str(row.get("path", ""))
    stats = {
        "sudo_count":        int(row.get("sudo_count", 0)),
        "normal_count":      int(row.get("normal_count", 0)),
        "unique_sudo_users": int(row.get("unique_sudo_users", 0)),
        "last_sudo_timestamp": float(row.get("last_sudo_timestamp", 0)),
    }
    features, _ = extract(file_path, access_stats=stats)
    return features
