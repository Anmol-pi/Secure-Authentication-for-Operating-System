#!/usr/bin/env bash
# vault_gui_launcher.sh — Launch LinuxAuthGuard Vault GUI as normal user
# Installed to: /usr/lib/linuxauthguard/file_auth/vault_gui_launcher.sh
#
# Opens the vault in VIEW-ONLY mode (no add/remove/change-password).
# For full admin access, use vault_gui_sudo_launcher.sh (right-click
# "Open as Administrator" in the app menu).

VAULT_GUI="/usr/lib/linuxauthguard/file_auth/vault_gui.py"
PYTHON="$(command -v python3 || echo /usr/bin/python3)"

exec "$PYTHON" "$VAULT_GUI" "$@"
