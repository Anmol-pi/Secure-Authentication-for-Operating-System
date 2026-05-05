# LinuxAuthGuard

A production-grade Linux Secure Authentication System providing a GTK4 display greeter, per-file vault authentication, ML-based sensitivity classification, and sudo activity tracking — all integrated via PAM.

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────┐
│                     LinuxAuthGuard                          │
│                                                             │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────────┐  │
│  │   Greeter    │  │  File Auth   │  │   ML Service     │  │
│  │  (GTK4/PAM)  │  │ (FUSE+SQLite)│  │ (inotify+sklearn)│  │
│  └──────┬───────┘  └──────┬───────┘  └────────┬─────────┘  │
│         │                 │                   │             │
│         └────────┬────────┘                   │             │
│                  │                            │             │
│         ┌────────▼───────┐          ┌─────────▼──────────┐  │
│         │  PAM Module    │          │   Sudo Tracker     │  │
│         │ (C .so + TOTP) │          │ (pam_exec + Flask) │  │
│         └────────────────┘          └────────────────────┘  │
└─────────────────────────────────────────────────────────────┘
```

### Components

| Component | Path | Language | Description |
|-----------|------|----------|-------------|
| Greeter | `greeter/` | Python/GTK4 | Touch-first display manager login screen |
| File Auth | `file_auth/` | C/Python | FUSE overlay + GUI vault manager |
| ML Service | `ml/` | Python | inotify file watcher + RandomForest classifier |
| Sudo Tracker | `sudo_tracker/` | Python | PAM exec hook + anomaly detection + Flask dashboard |
| PAM Module | `core/` | C | PAM .so with TOTP, lockout, session tokens, audit log |

---

## Quick Start

### Prerequisites

Ubuntu/Debian:
```bash
sudo apt-get install gcc make libpam0g-dev libsqlite3-dev \
    libsodium-dev libfuse3-dev fuse3 \
    python3 python3-pip python3-gi gir1.2-gtk-4.0 gir1.2-notify-0.7
```

### Install

```bash
git clone https://github.com/yourorg/linuxauthguard
cd linuxauthguard
sudo ./install.sh
```

The installer will:
1. Install system and Python dependencies
2. Compile the PAM module and FUSE daemon
3. Install all files under `/usr/lib/linuxauthguard/`
4. Train the initial ML model from `ml/seed_dataset.csv`
5. Enable and start three systemd services
6. Add the sudo PAM exec hook

### Uninstall

```bash
sudo ./install.sh --uninstall
```

---

## Components in Detail

### Greeter (`greeter/`)

A GTK4 display greeter for use with a display manager (e.g. greetd). Features:

- Frosted-glass login card with animated clock
- Touch-first gesture navigation (swipe to switch users)
- Shake animation on failed auth
- TOTP MFA second-factor stage
- Lockout countdown display

**Files:**
- `greeter_main.py` — entry point, arg parsing
- `greeter_ui.py` — GTK4 window, login card, MFA stage
- `touch_handler.py` — GestureClick/GestureSwipe/GestureDrag controllers
- `pam_bridge.py` — PAM authentication bridge with TOTP detection
- `assets/style.css` — GTK4 CSS with frosted glass + animations

**Usage:**
```bash
# Configure as greetd command:
# /etc/greetd/config.toml:
#   [terminal]
#   vt = 1
#   [default_session]
#   command = "python3 /usr/lib/linuxauthguard/greeter/greeter_main.py"

python3 greeter/greeter_main.py --test
```

### File Auth (`file_auth/`)

A FUSE overlay filesystem that intercepts access to protected files and folders, requiring per-file password authentication.

- Argon2id password hashing
- 5-minute session cache (no re-auth within window)
- GTK4 manager GUI for add/remove/list/log
- CLI tool for scripting

**Files:**
- `fuse_vault.c` — FUSE daemon (C), inotify, SQLite, UNIX socket IPC
- `vault_gui.py` — GTK4 vault manager + IPC auth server
- `vault_cli.py` — CLI: `add`, `remove`, `list`, `passwd`, `status`, `log`
- `vault_db.py` — SQLite WAL database interface
- `prompt_dialog.py` — GTK4 password prompt dialog

**Usage:**
```bash
# Add a protected file
python3 file_auth/vault_cli.py add /home/alice/secret.txt

# List protected items
python3 file_auth/vault_cli.py list

# View access log
python3 file_auth/vault_cli.py log

# Launch GUI
python3 file_auth/vault_gui.py
```

### ML Service (`ml/`)

Background inotify-based watcher that classifies accessed files for sensitivity using a RandomForest model trained on 25 features.

- **Features:** path depth, extension score, sensitive keywords, directory context, file stat attrs, MIME flags, sudo/normal access counts
- **Threshold:** confidence > 0.80 triggers desktop notification
- **Retraining:** every 24 hours, merging seed CSV with observed access logs
- **Model persistence:** `/var/lib/linuxauthguard/model.pkl`

**Files:**
- `ml_service.py` — inotify watcher daemon
- `classifier.py` — SensitivityClassifier (RandomForest, lazy sklearn import)
- `feature_extractor.py` — 25-feature vector extractor
- `trainer.py` — training pipeline + periodic retraining loop
- `notifier.py` — notify-send + gi.repository.Notify notifications
- `seed_dataset.csv` — 200+ row synthetic labelled training set

**Usage:**
```bash
# Run service
python3 ml/ml_service.py

# Retrain immediately
python3 ml/ml_service.py --retrain-now

# Classify a file manually
python3 -c "
from ml.classifier import SensitivityClassifier
clf = SensitivityClassifier(); clf.load()
print(clf.predict(['/etc/passwd']))
"
```

### Sudo Tracker (`sudo_tracker/`)

Tracks all `sudo` invocations via a PAM exec hook, persists events to SQLite, and detects anomalies.

**Anomaly detection:**
- `NEW_PATH` — binary never previously run with sudo
- `UNUSUAL_HOUR` — outside user's historical usage window (±2.5σ)
- `BURST` — >10 sudo invocations within 60 seconds

**Dashboard:** Flask read-only web UI on `http://localhost:7474`

**Files:**
- `pam_exec_hook.sh` — PAM exec hook (bash), sends JSON to UNIX socket
- `sudo_logger.py` — UNIX socket server, persists events, drains fallback log
- `sudo_db.py` — SQLite interface: events, path_stats, user_summary
- `anomaly_detector.py` — Anomaly checks + notification dispatch
- `dashboard.py` — Flask dashboard (stats, anomalies, events, hourly chart)

**Setup:**
Add to `/etc/pam.d/sudo`:
```
session optional pam_exec.so seteuid /usr/lib/linuxauthguard/pam_exec_hook.sh
```

**Usage:**
```bash
# Start logger service
python3 sudo_tracker/sudo_logger.py

# Start dashboard
python3 sudo_tracker/dashboard.py
# Then open: http://localhost:7474
```

### PAM Module (`core/`)

A C PAM module providing:

- Password authentication (delegates to pam_unix; adds lockout + TOTP on top)
- TOTP MFA (RFC 6238, HMAC-SHA1, ±1-step tolerance, no OpenSSL dependency)
- Account lockout (5 fails → 30-minute lockout, stored in SQLite)
- Session token issuance (256-bit random, SHA-256 hashed in SQLite)
- Thread-safe audit log (ISO-8601 timestamped, append-only)

**Files:**
- `pam_linuxauthguard.c` — PAM module (sm_authenticate, sm_acct_mgmt, sm_open/close_session)
- `totp.c` — RFC 6238 TOTP (SHA-1 + HMAC-SHA1 inline, no libssl)
- `buffer_safe.c` — strlcpy/strlcat/secure_zero/validate_username
- `audit_log.c` — thread-safe file audit logger
- `session.c` — session token lifecycle (SHA-256 inline, SQLite backend)
- `include/` — header files for all of the above

**Build:**
```bash
make
# Produces: pam_linuxauthguard.so, fuse_vault
```

**PAM service file** (`/etc/pam.d/linuxauthguard`):
```
auth    required   pam_linuxauthguard.so
account required   pam_linuxauthguard.so
session optional   pam_linuxauthguard.so
```

---

## Configuration

All settings live in `/etc/linuxauthguard/linuxauthguard.conf` (JSON).

Key settings:

| Key | Default | Description |
|-----|---------|-------------|
| `pam_module.max_fail_attempts` | 5 | Fails before lockout |
| `pam_module.lockout_duration_seconds` | 1800 | Lockout duration (30 min) |
| `file_auth.session_timeout_seconds` | 300 | File auth session TTL |
| `ml.sensitivity_threshold` | 0.80 | Min confidence for notification |
| `ml.retrain_interval_hours` | 24 | Model retraining period |
| `sudo_tracker.burst_threshold` | 10 | Sudo/minute anomaly trigger |
| `sudo_tracker.dashboard_port` | 7474 | Flask dashboard port |

---

## Systemd Services

| Service | Description |
|---------|-------------|
| `linuxauthguard-file-auth` | FUSE vault daemon |
| `linuxauthguard-ml` | ML inotify watcher |
| `linuxauthguard-sudo-tracker` | Sudo event logger |

```bash
systemctl status linuxauthguard-*
journalctl -u linuxauthguard-ml -f
```

---

## Security Notes

- All C code compiled with `-fstack-protector-strong -D_FORTIFY_SOURCE=2`
- Passwords hashed with Argon2id (time=3, mem=64MB, parallel=2)
- Session tokens are 256-bit random from `/dev/urandom`
- All databases use SQLite WAL mode
- FUSE daemon drops privileges after mount where possible
- Audit log is append-only (`O_APPEND`)
- `lag_secure_zero()` used for all sensitive in-memory data

---

## Development

```bash
# Run tests
make test

# Build only
make

# Install to custom prefix
make install PREFIX=/usr/local

# Clean artefacts
make clean
```

---

## Paths Reference

| Path | Purpose |
|------|---------|
| `/etc/linuxauthguard/linuxauthguard.conf` | Master config |
| `/var/lib/linuxauthguard/vault.db` | File vault + TOTP secrets |
| `/var/lib/linuxauthguard/lockout.db` | PAM lockout + session tokens |
| `/var/lib/linuxauthguard/sudo_log.db` | Sudo event log |
| `/var/lib/linuxauthguard/model.pkl` | ML model |
| `/var/log/linuxauthguard/auth.log` | PAM audit log |
| `/var/log/linuxauthguard/greeter.log` | Greeter log |
| `/var/log/linuxauthguard/ml_service.log` | ML service log |
| `/run/linuxauthguard/vault_auth.sock` | FUSE ↔ GUI IPC socket |
| `/run/linuxauthguard/sudo_events.sock` | PAM hook → sudo_logger socket |

---

## License

MIT — see LICENSE file.
