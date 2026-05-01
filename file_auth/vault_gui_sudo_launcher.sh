#!/usr/bin/env bash
# vault_gui_sudo_launcher.sh — Open Vault GUI as Administrator
# Installed to: /usr/lib/linuxauthguard/file_auth/vault_gui_sudo_launcher.sh
#
# pkexec cannot run shell scripts directly, so it targets the compiled
# binary lag-vault-admin (registered in the polkit policy).
# We pass DISPLAY, XAUTHORITY, and DBUS as arguments so the binary
# can restore the GUI environment after pkexec clears it.

ADMIN_BIN="/usr/lib/linuxauthguard/file_auth/lag-vault-admin"

exec pkexec "$ADMIN_BIN" \
    "${DISPLAY:-:0}" \
    "${XAUTHORITY:-$HOME/.Xauthority}" \
    "${DBUS_SESSION_BUS_ADDRESS:-}"
