#!/usr/bin/env python3
"""
lag_encrypt_extension.py — LinuxAuthGuard Nautilus Encryption Extension

Adds right-click context menu items to GNOME Files (Nautilus):
  • "LAG Encrypt File(s)"   — AES-256-GCM encrypt using a passphrase
  • "LAG Decrypt File(s)"   — Decrypt .lag files

Install:
    sudo cp lag_encrypt_extension.py /usr/share/nautilus-python/extensions/
    nautilus -q && nautilus   # restart Nautilus

Dependencies:
    python3-nautilus  (apt install python3-nautilus)
    cryptography      (pip install cryptography)
    python3-gi        (apt install python3-gi)
"""

import os
import struct
import secrets
import hashlib
import getpass
import threading
from pathlib import Path

# ── gi / Nautilus imports ────────────────────────────────────────────────────
import gi
gi.require_version("Gtk", "4.0")
gi.require_version("Nautilus", "4.0")
from gi.repository import Nautilus, GObject, Gtk, GLib

# ── cryptography ─────────────────────────────────────────────────────────────
try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
    from cryptography.hazmat.backends import default_backend
    _CRYPTO_OK = True
except ImportError:
    _CRYPTO_OK = False


# ── Constants ─────────────────────────────────────────────────────────────────
LAG_MAGIC   = b"LAG1"          # 4-byte file header
SALT_LEN    = 32               # scrypt salt bytes
NONCE_LEN   = 12               # AES-GCM nonce bytes
EXT         = ".lag"

# scrypt parameters — tuned for interactive speed on modest hardware
SCRYPT_N    = 2**17            # CPU/memory cost  (128 KiB * N)
SCRYPT_R    = 8
SCRYPT_P    = 1
KEY_LEN     = 32               # AES-256


# ── Key derivation ────────────────────────────────────────────────────────────

def _derive_key(passphrase: str, salt: bytes) -> bytes:
    """Derive a 256-bit key from *passphrase* + *salt* using scrypt."""
    kdf = Scrypt(
        salt=salt,
        length=KEY_LEN,
        n=SCRYPT_N,
        r=SCRYPT_R,
        p=SCRYPT_P,
        backend=default_backend(),
    )
    return kdf.derive(passphrase.encode("utf-8"))


# ── Encrypt / Decrypt ─────────────────────────────────────────────────────────

def encrypt_file(src_path: Path, passphrase: str) -> Path:
    """
    Encrypt *src_path* → *src_path*.lag

    File format:
        [4]  magic  LAG1
        [32] salt
        [12] nonce
        [N]  ciphertext + 16-byte GCM tag
    """
    salt  = secrets.token_bytes(SALT_LEN)
    nonce = secrets.token_bytes(NONCE_LEN)
    key   = _derive_key(passphrase, salt)
    aesgcm = AESGCM(key)

    plaintext = src_path.read_bytes()
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)

    dst_path = src_path.with_suffix(src_path.suffix + EXT)
    with dst_path.open("wb") as f:
        f.write(LAG_MAGIC)
        f.write(salt)
        f.write(nonce)
        f.write(ciphertext)

    # Wipe the key from memory as best we can
    key = b"\x00" * KEY_LEN
    return dst_path


def decrypt_file(src_path: Path, passphrase: str) -> Path:
    """
    Decrypt *src_path* (.lag) → original filename (suffix stripped).

    Raises ValueError on bad magic or wrong passphrase (auth tag mismatch).
    """
    data = src_path.read_bytes()
    if len(data) < len(LAG_MAGIC) + SALT_LEN + NONCE_LEN + 16:
        raise ValueError("File too short — not a valid .lag file.")

    offset = 0
    magic = data[offset:offset + 4]; offset += 4
    if magic != LAG_MAGIC:
        raise ValueError("Not a LAG-encrypted file (bad magic bytes).")

    salt       = data[offset:offset + SALT_LEN];  offset += SALT_LEN
    nonce      = data[offset:offset + NONCE_LEN]; offset += NONCE_LEN
    ciphertext = data[offset:]

    key    = _derive_key(passphrase, salt)
    aesgcm = AESGCM(key)

    try:
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)
    except Exception:
        raise ValueError("Decryption failed — wrong passphrase or file is corrupted.")

    # Strip .lag suffix to recover original name
    stem = src_path.name[:-len(EXT)] if src_path.name.endswith(EXT) else src_path.name + ".decrypted"
    dst_path = src_path.parent / stem
    dst_path.write_bytes(plaintext)

    key = b"\x00" * KEY_LEN
    return dst_path


# ── GTK Passphrase Dialog ─────────────────────────────────────────────────────

class PassphraseDialog(Gtk.Dialog):
    """Modal dialog that prompts for a passphrase (with optional confirm field)."""

    def __init__(self, parent, title: str, confirm: bool = False):
        super().__init__(title=title, transient_for=parent, modal=True)
        self.set_default_size(380, -1)

        box = self.get_content_area()
        box.set_spacing(12)
        box.set_margin_top(16)
        box.set_margin_bottom(16)
        box.set_margin_start(16)
        box.set_margin_end(16)

        # Icon + label
        header = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        icon = Gtk.Image.new_from_icon_name("dialog-password")
        icon.set_pixel_size(32)
        header.append(icon)
        lbl = Gtk.Label(label=f"<b>{title}</b>", use_markup=True, xalign=0)
        header.append(lbl)
        box.append(header)

        # Passphrase entry
        self._entry = Gtk.Entry()
        self._entry.set_visibility(False)
        self._entry.set_placeholder_text("Passphrase")
        self._entry.set_input_purpose(Gtk.InputPurpose.PASSWORD)
        box.append(self._entry)

        # Confirm entry (encrypt only)
        self._confirm = None
        if confirm:
            self._confirm = Gtk.Entry()
            self._confirm.set_visibility(False)
            self._confirm.set_placeholder_text("Confirm passphrase")
            self._confirm.set_input_purpose(Gtk.InputPurpose.PASSWORD)
            box.append(self._confirm)

        # Strength indicator (encrypt only)
        self._strength_bar = None
        if confirm:
            self._strength_bar = Gtk.LevelBar()
            self._strength_bar.set_min_value(0)
            self._strength_bar.set_max_value(4)
            box.append(self._strength_bar)
            self._entry.connect("changed", self._on_passphrase_changed)

        # Error label
        self._error_label = Gtk.Label(label="", xalign=0)
        self._error_label.add_css_class("error")
        box.append(self._error_label)

        # Buttons
        self.add_button("Cancel", Gtk.ResponseType.CANCEL)
        ok_btn = self.add_button("OK", Gtk.ResponseType.OK)
        ok_btn.add_css_class("suggested-action")
        self.set_default_response(Gtk.ResponseType.OK)
        self._entry.connect("activate", lambda _: self.response(Gtk.ResponseType.OK))
        if self._confirm:
            self._confirm.connect("activate", lambda _: self.response(Gtk.ResponseType.OK))

    def _on_passphrase_changed(self, entry):
        pw = entry.get_text()
        score = 0
        if len(pw) >= 8:  score += 1
        if len(pw) >= 14: score += 1
        if any(c.isdigit() for c in pw): score += 1
        if any(not c.isalnum() for c in pw): score += 1
        if self._strength_bar:
            self._strength_bar.set_value(score)

    def get_passphrase(self) -> str:
        return self._entry.get_text()

    def get_confirm(self) -> str:
        return self._confirm.get_text() if self._confirm else ""

    def show_error(self, msg: str):
        self._error_label.set_text(msg)


# ── Progress dialog ───────────────────────────────────────────────────────────

class ProgressDialog(Gtk.Dialog):
    def __init__(self, parent, title: str):
        super().__init__(title=title, transient_for=parent, modal=True)
        self.set_default_size(340, -1)
        box = self.get_content_area()
        box.set_spacing(12)
        box.set_margin_top(16); box.set_margin_bottom(16)
        box.set_margin_start(16); box.set_margin_end(16)

        self._label = Gtk.Label(label="Working…", xalign=0)
        box.append(self._label)

        self._bar = Gtk.ProgressBar()
        self._bar.set_pulse_step(0.1)
        box.append(self._bar)

        self._pulse_id = GLib.timeout_add(120, self._pulse)
        self.present()

    def _pulse(self):
        self._bar.pulse()
        return True

    def set_text(self, text: str):
        self._label.set_text(text)

    def finish(self):
        if self._pulse_id:
            GLib.source_remove(self._pulse_id)
            self._pulse_id = None
        self._bar.set_fraction(1.0)
        self.close()


# ── Result notification ───────────────────────────────────────────────────────

def _show_result(parent, title: str, message: str, error: bool = False):
    dialog = Gtk.MessageDialog(
        transient_for=parent,
        modal=True,
        message_type=Gtk.MessageType.ERROR if error else Gtk.MessageType.INFO,
        buttons=Gtk.ButtonsType.OK,
        text=title,
    )
    dialog.format_secondary_text(message)
    dialog.connect("response", lambda d, _: d.close())
    dialog.present()


# ── Extension class ───────────────────────────────────────────────────────────

class LAGEncryptExtension(GObject.GObject, Nautilus.MenuProvider):
    """
    LinuxAuthGuard Nautilus extension.
    Adds encrypt/decrypt options to the right-click context menu in GNOME Files.
    """

    def __init__(self):
        super().__init__()

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _paths_from_files(self, files) -> list[Path]:
        return [Path(f.get_location().get_path()) for f in files
                if f.get_location() is not None]

    def _all_encrypted(self, paths: list[Path]) -> bool:
        return all(p.suffix == EXT for p in paths)

    # ── Menu builder ──────────────────────────────────────────────────────────

    def get_file_items(self, files):
        if not _CRYPTO_OK:
            return []

        paths = self._paths_from_files(files)
        if not paths:
            return []

        items = []

        # Show "Encrypt" only if none of the selected files are already .lag
        if not self._all_encrypted(paths):
            item_enc = Nautilus.MenuItem(
                name="LAGEncryptExtension::Encrypt",
                label="🔒 LAG Encrypt",
                tip="Encrypt selected file(s) with AES-256-GCM (LinuxAuthGuard)",
            )
            item_enc.connect("activate", self._on_encrypt, files)
            items.append(item_enc)

        # Show "Decrypt" only if all selected files are .lag
        if self._all_encrypted(paths):
            item_dec = Nautilus.MenuItem(
                name="LAGEncryptExtension::Decrypt",
                label="🔓 LAG Decrypt",
                tip="Decrypt selected .lag file(s) (LinuxAuthGuard)",
            )
            item_dec.connect("activate", self._on_decrypt, files)
            items.append(item_dec)

        return items

    # ── Encrypt flow ──────────────────────────────────────────────────────────

    def _on_encrypt(self, menu_item, files):
        paths = self._paths_from_files(files)
        parent_win = None  # Nautilus doesn't give us a parent window handle

        dialog = PassphraseDialog(parent_win, "Encrypt with LAG", confirm=True)
        while True:
            response = dialog.run()
            if response != Gtk.ResponseType.OK:
                dialog.close()
                return
            pw  = dialog.get_passphrase()
            cpw = dialog.get_confirm()
            if not pw:
                dialog.show_error("Passphrase cannot be empty.")
                continue
            if pw != cpw:
                dialog.show_error("Passphrases do not match.")
                continue
            break
        dialog.close()

        prog = ProgressDialog(parent_win, "Encrypting…")
        results = []

        def _worker():
            for p in paths:
                try:
                    prog.set_text(f"Encrypting: {p.name}")
                    out = encrypt_file(p, pw)
                    results.append((True, p.name, out.name))
                except Exception as exc:
                    results.append((False, p.name, str(exc)))
            GLib.idle_add(_done)

        def _done():
            prog.finish()
            ok  = [r for r in results if r[0]]
            bad = [r for r in results if not r[0]]
            msg_parts = []
            if ok:
                msg_parts.append(f"✅ Encrypted {len(ok)} file(s).")
            if bad:
                msg_parts.append("❌ Errors:\n" + "\n".join(f"  {r[1]}: {r[2]}" for r in bad))
            _show_result(None, "LAG Encrypt", "\n".join(msg_parts), error=bool(bad))

        threading.Thread(target=_worker, daemon=True).start()

    # ── Decrypt flow ──────────────────────────────────────────────────────────

    def _on_decrypt(self, menu_item, files):
        paths = self._paths_from_files(files)
        parent_win = None

        dialog = PassphraseDialog(parent_win, "Decrypt with LAG", confirm=False)
        response = dialog.run()
        if response != Gtk.ResponseType.OK:
            dialog.close()
            return
        pw = dialog.get_passphrase()
        dialog.close()

        if not pw:
            _show_result(None, "LAG Decrypt", "No passphrase entered.", error=True)
            return

        prog = ProgressDialog(parent_win, "Decrypting…")
        results = []

        def _worker():
            for p in paths:
                try:
                    prog.set_text(f"Decrypting: {p.name}")
                    out = decrypt_file(p, pw)
                    results.append((True, p.name, out.name))
                except ValueError as exc:
                    results.append((False, p.name, str(exc)))
                except Exception as exc:
                    results.append((False, p.name, f"Unexpected error: {exc}"))
            GLib.idle_add(_done)

        def _done():
            prog.finish()
            ok  = [r for r in results if r[0]]
            bad = [r for r in results if not r[0]]
            msg_parts = []
            if ok:
                msg_parts.append(f"✅ Decrypted {len(ok)} file(s).")
            if bad:
                msg_parts.append("❌ Errors:\n" + "\n".join(f"  {r[1]}: {r[2]}" for r in bad))
            _show_result(None, "LAG Decrypt", "\n".join(msg_parts), error=bool(bad))

        threading.Thread(target=_worker, daemon=True).start()
