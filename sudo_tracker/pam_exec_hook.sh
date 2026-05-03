#!/usr/bin/env bash
# pam_exec_hook.sh — PAM exec hook for LinuxAuthGuard sudo tracker.
#
# Installed via /etc/pam.d/sudo:
#   session optional pam_exec.so seteuid /usr/lib/linuxauthguard/pam_exec_hook.sh
#
# PAM sets the following environment variables before invoking this script:
#   PAM_TYPE       — open_session | close_session | auth | account | ...
#   PAM_USER       — the user who ran sudo
#   PAM_RUSER      — the invoking (real) user
#   PAM_TTY        — terminal
#   PAM_SERVICE    — pam service name (usually "sudo")
#   SUDO_COMMAND   — full command string (set by sudo itself)
#   SUDO_USER      — original user
#   SUDO_UID / SUDO_GID
#
# This hook logs to the sudo_logger.py daemon via a simple UNIX socket.
# If the socket is unavailable it falls back to appending to a flat log file.

set -euo pipefail

SOCKET_PATH="/run/linuxauthguard/sudo_events.sock"
FALLBACK_LOG="/var/log/linuxauthguard/sudo_fallback.log"
LOGGER_BIN="/usr/lib/linuxauthguard/sudo_logger.py"

# Only act on session open events from the sudo PAM service
if [[ "${PAM_TYPE:-}" != "open_session" ]]; then
    exit 0
fi

if [[ "${PAM_SERVICE:-}" != "sudo" && "${PAM_SERVICE:-}" != "su" ]]; then
    exit 0
fi

# Collect fields
TIMESTAMP="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
SUDO_USER_VAL="${PAM_RUSER:-${SUDO_USER:-unknown}}"
TARGET_USER="${PAM_USER:-root}"
COMMAND="${SUDO_COMMAND:-unknown}"
TTY="${PAM_TTY:-unknown}"
# Try to extract the first real path argument from the command
CMD_PATH="$(echo "${COMMAND}" | awk '{print $1}')"

# Build a compact JSON payload (no external dependencies — pure bash)
PAYLOAD="{\"ts\":\"${TIMESTAMP}\",\"user\":\"${SUDO_USER_VAL}\",\"target\":\"${TARGET_USER}\",\"cmd\":\"${COMMAND}\",\"cmd_path\":\"${CMD_PATH}\",\"tty\":\"${TTY}\"}"

# Try sending via UNIX socket using Python (always available) to avoid
# netcat dependency variance across distributions.
if [[ -S "${SOCKET_PATH}" ]]; then
    python3 - <<EOF 2>/dev/null && exit 0
import socket, sys
data = b'${PAYLOAD}\n'
try:
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(2)
    s.connect("${SOCKET_PATH}")
    s.sendall(data)
    s.close()
except Exception as e:
    sys.exit(1)
EOF
fi

# Fallback: write to flat log file
mkdir -p "$(dirname "${FALLBACK_LOG}")"
printf '%s\n' "${PAYLOAD}" >> "${FALLBACK_LOG}"

exit 0
