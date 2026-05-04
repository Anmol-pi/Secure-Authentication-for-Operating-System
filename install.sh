#!/usr/bin/env bash
# install.sh — LinuxAuthGuard installer
#
# Usage:
#   sudo ./install.sh            — full install
#   sudo ./install.sh --uninstall
#   sudo ./install.sh --deps-only
#   sudo ./install.sh --no-build  (skip C compilation; Python/config only)
#
# Greeter component has been REMOVED — LinuxAuthGuard no longer replaces
# your display manager (GDM/SDDM/LightDM). It installs only:
#   • PAM module   (authentication hardening)
#   • FUSE vault   (per-file encryption)
#   • ML service   (anomaly detection)
#   • Sudo tracker (privilege audit)
#   • Nautilus encryption extension (right-click encrypt/decrypt in Files)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG="/tmp/linuxauthguard_install.log"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
info()  { echo -e "${GREEN}[INFO]${NC}  $*" | tee -a "$LOG"; }
warn()  { echo -e "${YELLOW}[WARN]${NC}  $*" | tee -a "$LOG"; }
error() { echo -e "${RED}[ERROR]${NC} $*" | tee -a "$LOG"; exit 1; }

# -------------------------------------------------------------------------
# Argument parsing
# -------------------------------------------------------------------------
OPT_UNINSTALL=0
OPT_DEPS_ONLY=0
OPT_NO_BUILD=0

for arg in "$@"; do
    case "$arg" in
        --uninstall)  OPT_UNINSTALL=1 ;;
        --deps-only)  OPT_DEPS_ONLY=1 ;;
        --no-build)   OPT_NO_BUILD=1  ;;
        --help|-h)
            echo "Usage: sudo $0 [--uninstall|--deps-only|--no-build]"
            exit 0
            ;;
        *) warn "Unknown argument: $arg" ;;
    esac
done

# -------------------------------------------------------------------------
# Root check
# -------------------------------------------------------------------------
if [[ $EUID -ne 0 ]]; then
    error "This script must be run as root (sudo $0)"
fi

# -------------------------------------------------------------------------
# Uninstall
# -------------------------------------------------------------------------
if [[ $OPT_UNINSTALL -eq 1 ]]; then
    info "Uninstalling LinuxAuthGuard..."
    systemctl stop linuxauthguard-file-auth linuxauthguard-ml \
        linuxauthguard-sudo-tracker 2>/dev/null || true
    systemctl disable linuxauthguard-file-auth linuxauthguard-ml \
        linuxauthguard-sudo-tracker 2>/dev/null || true

    PAM_LIB="$(dpkg-architecture -qDEB_HOST_MULTIARCH 2>/dev/null || echo x86_64-linux-gnu)"
    rm -f "/lib/${PAM_LIB}/security/pam_linuxauthguard.so"
    rm -f /etc/pam.d/linuxauthguard
    rm -rf /usr/lib/linuxauthguard

    # Remove Nautilus encryption extension
    rm -f /usr/share/nautilus-python/extensions/lag_encrypt_extension.py
    info "Nautilus encryption extension removed."

    # Remove desktop launcher, icon, and polkit policy
    rm -f /usr/share/applications/linuxauthguard-vault.desktop
    rm -f /usr/share/applications/linuxauthguard-vault-admin.desktop
    rm -f /usr/lib/linuxauthguard/file_auth/lag-vault-admin
    rm -f /usr/share/icons/hicolor/scalable/apps/linuxauthguard.svg
    rm -f /usr/share/icons/hicolor/48x48/apps/linuxauthguard.png
    rm -f /usr/share/icons/hicolor/128x128/apps/linuxauthguard.png
    rm -f /usr/share/polkit-1/actions/com.linuxauthguard.vault.policy
    rm -f /usr/lib/linuxauthguard/file_auth/vault_gui_sudo_launcher.sh
    gtk-update-icon-cache -f -t /usr/share/icons/hicolor 2>/dev/null || true
    update-desktop-database /usr/share/applications 2>/dev/null || true
    info "Desktop launcher removed."

    rm -f /etc/systemd/system/linuxauthguard-*.service
    systemctl daemon-reload 2>/dev/null || true

    info "Uninstall complete."
    info "Config/data dirs preserved:"
    info "  /etc/linuxauthguard  /var/lib/linuxauthguard  /var/log/linuxauthguard"
    exit 0
fi

# -------------------------------------------------------------------------
# System dependency installation
# -------------------------------------------------------------------------
install_deps() {
    info "Installing system dependencies..."

    if command -v apt-get &>/dev/null; then
        apt-get update -qq
        apt-get install -y --no-install-recommends \
            gcc make pkg-config \
            libpam0g-dev \
            libsqlite3-dev \
            libsodium-dev \
            libfuse3-dev \
            fuse3 \
            python3 python3-pip python3-gi \
            gir1.2-gtk-4.0 gir1.2-notify-0.7 \
            libargon2-dev \
            python3-nautilus \
            >> "$LOG" 2>&1
    elif command -v dnf &>/dev/null; then
        dnf install -y \
            gcc make pkg-config \
            pam-devel \
            sqlite-devel \
            libsodium-devel \
            fuse3-devel \
            python3 python3-pip python3-gobject \
            gtk4 libnotify \
            libargon2-devel \
            nautilus-python \
            >> "$LOG" 2>&1
    elif command -v pacman &>/dev/null; then
        pacman -Sy --noconfirm \
            gcc make pkg-config \
            pam \
            sqlite \
            libsodium \
            fuse3 \
            python python-pip python-gobject \
            gtk4 libnotify \
            argon2 \
            python-nautilus \
            >> "$LOG" 2>&1
    else
        warn "Unknown package manager. Install manually: libpam-dev libsqlite3-dev libsodium-dev libfuse3-dev python3-gi gtk4 python3-nautilus"
    fi

    info "Installing Python packages..."
    pip3 install --break-system-packages --ignore-installed --quiet \
        argon2-cffi python-pam pyotp fusepy inotify-simple \
        scikit-learn numpy flask notify2 cryptography \
        >> "$LOG" 2>&1 || warn "Some pip packages failed — check $LOG"
}

if [[ $OPT_DEPS_ONLY -eq 1 ]]; then
    install_deps
    info "Dependencies installed."
    exit 0
fi

install_deps

# -------------------------------------------------------------------------
# Build C components
# -------------------------------------------------------------------------
if [[ $OPT_NO_BUILD -eq 0 ]]; then
    info "Building C components..."
    cd "$SCRIPT_DIR"
    make clean >> "$LOG" 2>&1
    make       >> "$LOG" 2>&1 || error "Build failed — see $LOG"
    info "Build succeeded."
fi

# -------------------------------------------------------------------------
# Create directories
# -------------------------------------------------------------------------
info "Creating directories..."
install -d /etc/linuxauthguard
install -d /var/lib/linuxauthguard
install -d /var/log/linuxauthguard
install -d /run/linuxauthguard
install -d /usr/lib/linuxauthguard/{ml,sudo_tracker,file_auth}

# -------------------------------------------------------------------------
# Install via Makefile
# -------------------------------------------------------------------------
info "Installing files..."
cd "$SCRIPT_DIR"
make install >> "$LOG" 2>&1 || error "make install failed — see $LOG"

# -------------------------------------------------------------------------
# Install Nautilus encryption extension
# -------------------------------------------------------------------------
info "Installing Nautilus encryption extension..."
NAUTILUS_EXT_DIR="/usr/share/nautilus-python/extensions"
install -d "$NAUTILUS_EXT_DIR"
install -m 644 file_auth/lag_encrypt_extension.py "$NAUTILUS_EXT_DIR/"
info "Nautilus extension installed. Restart Nautilus with: nautilus -q && nautilus"

# -------------------------------------------------------------------------
# Train initial ML model
# -------------------------------------------------------------------------
info "Training initial ML model from seed data..."
python3 /usr/lib/linuxauthguard/ml/trainer.py --once >> "$LOG" 2>&1 \
    || warn "Initial ML training failed — model will be trained on first run"

# -------------------------------------------------------------------------
# Enable systemd services (NO greeter — display manager untouched)
# -------------------------------------------------------------------------
info "Enabling systemd services..."
systemctl daemon-reload
systemctl enable --now \
    linuxauthguard-file-auth \
    linuxauthguard-ml \
    linuxauthguard-sudo-tracker \
    >> "$LOG" 2>&1 || warn "systemctl enable failed — start services manually"

# -------------------------------------------------------------------------
# PAM sudo hook
# -------------------------------------------------------------------------
info "Configuring sudo PAM hook..."
SUDO_PAM=/etc/pam.d/sudo
PAM_HOOK_LINE="session optional pam_exec.so seteuid /usr/lib/linuxauthguard/pam_exec_hook.sh"
if ! grep -qF "pam_exec_hook.sh" "$SUDO_PAM" 2>/dev/null; then
    echo "$PAM_HOOK_LINE" >> "$SUDO_PAM"
    info "Added pam_exec hook to $SUDO_PAM"
else
    info "pam_exec hook already present in $SUDO_PAM"
fi

# -------------------------------------------------------------------------
# Install desktop app launcher (Linux Mint / XFCE / GNOME app menu)
# -------------------------------------------------------------------------
info "Installing Vault GUI app launcher..."

# Install polkit policy (enables pkexec password prompt)
install -m 644 "$SCRIPT_DIR/linuxauthguard-vault.policy" \
    /usr/share/polkit-1/actions/com.linuxauthguard.vault.policy

# Compile the pkexec-target binary (lag-vault-admin)
info "Compiling admin launcher binary..."
gcc -Wall -Wextra \
    -o /usr/lib/linuxauthguard/file_auth/lag-vault-admin \
    "$SCRIPT_DIR/file_auth/lag_vault_admin.c" >> "$LOG" 2>&1 \
    || error "Failed to compile lag_vault_admin.c — is gcc installed?"
chmod 755 /usr/lib/linuxauthguard/file_auth/lag-vault-admin

# Install launcher scripts
install -m 755 "$SCRIPT_DIR/file_auth/vault_gui_launcher.sh" \
    /usr/lib/linuxauthguard/file_auth/vault_gui_launcher.sh
install -m 755 "$SCRIPT_DIR/file_auth/vault_gui_sudo_launcher.sh" \
    /usr/lib/linuxauthguard/file_auth/vault_gui_sudo_launcher.sh

# Install icon (SVG → hicolor theme, multiple sizes via rsvg-convert if available)
ICON_SRC="$SCRIPT_DIR/linuxauthguard.svg"
install -d /usr/share/icons/hicolor/scalable/apps
install -m 644 "$ICON_SRC" /usr/share/icons/hicolor/scalable/apps/linuxauthguard.svg

# Render to 48x48 PNG for app menus that don't support SVG
if command -v rsvg-convert &>/dev/null; then
    install -d /usr/share/icons/hicolor/48x48/apps
    rsvg-convert -w 48 -h 48 "$ICON_SRC" \
        -o /usr/share/icons/hicolor/48x48/apps/linuxauthguard.png 2>>"$LOG" || true
    install -d /usr/share/icons/hicolor/128x128/apps
    rsvg-convert -w 128 -h 128 "$ICON_SRC" \
        -o /usr/share/icons/hicolor/128x128/apps/linuxauthguard.png 2>>"$LOG" || true
elif command -v convert &>/dev/null; then
    install -d /usr/share/icons/hicolor/48x48/apps
    convert -background none -resize 48x48 "$ICON_SRC" \
        /usr/share/icons/hicolor/48x48/apps/linuxauthguard.png 2>>"$LOG" || true
fi

# Update icon cache
gtk-update-icon-cache -f -t /usr/share/icons/hicolor 2>>"$LOG" || true

# Install both .desktop files (user + admin)
install -m 644 "$SCRIPT_DIR/linuxauthguard-vault.desktop" \
    /usr/share/applications/linuxauthguard-vault.desktop
install -m 644 "$SCRIPT_DIR/linuxauthguard-vault-admin.desktop" \
    /usr/share/applications/linuxauthguard-vault-admin.desktop

# Refresh the application database so Mint menu picks it up immediately
update-desktop-database /usr/share/applications 2>>"$LOG" || true

info "App launcher installed. 'LinuxAuthGuard Vault' will appear in your app menu."

# -------------------------------------------------------------------------
# Done
# -------------------------------------------------------------------------
echo ""
info "======================================================"
info "  LinuxAuthGuard installed successfully!"
info "======================================================"
info ""
info "  App Menu:  Search 'LinuxAuthGuard Vault' in your app menu"
info "             (or find it under System / Security)"
info "  Services:  systemctl status linuxauthguard-*"
info "  Dashboard: http://127.0.0.1:7474  (start with:"
info "             python3 /usr/lib/linuxauthguard/sudo_tracker/dashboard.py)"
info "  Vault CLI: /usr/lib/linuxauthguard/file_auth/vault_cli.py --help"
info "  Encryption: Right-click any file in Nautilus → 'LAG Encrypt/Decrypt'"
info "  Log:       $LOG"
info ""
info "  NOTE: Your display manager (GDM/SDDM/LightDM) is untouched."
info "        The broken greeter component has been removed."
info ""
