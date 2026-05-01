#!/usr/bin/env python3
"""
LinuxAuthGuard - Touch-responsive Password Prompt Dialog (GTK4)
Used by vault_gui.py when the FUSE daemon requests authentication.
"""

from __future__ import annotations

import gi
gi.require_version("Gtk", "4.0")

from gi.repository import Gtk, GLib
from pathlib import Path
from typing import Optional


class PromptDialog(Gtk.Dialog):
    """
    A modal dialog that prompts for a protection password.
    Responds to touch tap events to activate the entry field.
    Optionally shows a confirm field for new password entry.
    """

    def __init__(
        self,
        path: str,
        title: str = "Authentication Required",
        confirm: bool = False,
        transient_for: Optional[Gtk.Window] = None,
    ) -> None:
        super().__init__()
        self.set_title(title)
        self.set_modal(True)
        self.set_resizable(False)
        self.add_css_class("prompt-dialog")
        if transient_for:
            self.set_transient_for(transient_for)

        self._confirm = confirm
        self._path = path

        self._build_ui(path)
        self._install_touch_handlers()

        self.add_button("Cancel", Gtk.ResponseType.CANCEL)
        ok_btn = self.add_button("Unlock", Gtk.ResponseType.OK)
        ok_btn.add_css_class("suggested-action")
        ok_btn.add_css_class("signin-button")

        self._password_entry.grab_focus()

    # ── UI ──────────────────────────────────────────────────────────────────

    def _build_ui(self, path: str) -> None:
        content = self.get_content_area()
        content.set_spacing(0)
        content.set_margin_top(24)
        content.set_margin_bottom(8)
        content.set_margin_start(32)
        content.set_margin_end(32)

        # Lock icon
        icon = Gtk.Label(label="🔐")
        icon.add_css_class("prompt-icon")
        content.append(icon)

        # Path description
        short_path = str(path)
        if len(short_path) > 60:
            short_path = "…" + short_path[-59:]

        path_label = Gtk.Label(label=short_path)
        path_label.add_css_class("prompt-path")
        path_label.set_wrap(True)
        path_label.set_max_width_chars(40)
        path_label.set_justify(Gtk.Justification.CENTER)
        content.append(path_label)

        subtitle = Gtk.Label(label="Enter the protection password to unlock this item.")
        subtitle.add_css_class("prompt-subtitle")
        subtitle.set_wrap(True)
        subtitle.set_max_width_chars(40)
        subtitle.set_justify(Gtk.Justification.CENTER)
        content.append(subtitle)

        # Separator
        sep = Gtk.Separator()
        sep.set_margin_top(16)
        sep.set_margin_bottom(16)
        content.append(sep)

        # Password field
        pw_label = Gtk.Label(label="Password")
        pw_label.add_css_class("field-label")
        pw_label.set_halign(Gtk.Align.START)
        content.append(pw_label)

        self._password_entry = Gtk.Entry()
        self._password_entry.set_visibility(False)
        self._password_entry.set_input_purpose(Gtk.InputPurpose.PASSWORD)
        self._password_entry.add_css_class("auth-entry")
        self._password_entry.set_placeholder_text("Password…")
        self._password_entry.set_size_request(320, -1)
        self._password_entry.connect("activate", self._on_enter)
        content.append(self._password_entry)

        # Confirm field (only for new passwords)
        if self._confirm:
            confirm_label = Gtk.Label(label="Confirm Password")
            confirm_label.add_css_class("field-label")
            confirm_label.set_halign(Gtk.Align.START)
            confirm_label.set_margin_top(8)
            content.append(confirm_label)

            self._confirm_entry = Gtk.Entry()
            self._confirm_entry.set_visibility(False)
            self._confirm_entry.set_input_purpose(Gtk.InputPurpose.PASSWORD)
            self._confirm_entry.add_css_class("auth-entry")
            self._confirm_entry.set_placeholder_text("Confirm password…")
            self._confirm_entry.set_size_request(320, -1)
            self._confirm_entry.connect("activate", self._on_enter)
            content.append(self._confirm_entry)
        else:
            self._confirm_entry = None

        # Error label
        self._error_label = Gtk.Label(label="")
        self._error_label.add_css_class("status-label")
        self._error_label.add_css_class("error")
        self._error_label.set_margin_top(6)
        content.append(self._error_label)

    def _install_touch_handlers(self) -> None:
        """Make entry fields activate on first touch without requiring a tap."""
        for entry in [self._password_entry, self._confirm_entry]:
            if entry is None:
                continue
            gc = Gtk.GestureClick()
            gc.set_touch_only(False)
            gc.set_button(0)
            entry_ref = entry

            def _on_press(gesture, n, x, y, e=entry_ref):
                if not e.has_focus():
                    e.grab_focus()

            gc.connect("pressed", _on_press)
            entry.add_controller(gc)

    # ── Validation & response ────────────────────────────────────────────────

    def _on_enter(self, entry: Gtk.Entry) -> None:
        if self._confirm and entry == self._password_entry and self._confirm_entry:
            self._confirm_entry.grab_focus()
        else:
            self.response(Gtk.ResponseType.OK)

    def get_password(self) -> str:
        """Return the entered password. Validates if in confirm mode."""
        password = self._password_entry.get_text()
        if self._confirm and self._confirm_entry:
            confirm = self._confirm_entry.get_text()
            if password != confirm:
                self._error_label.set_text("Passwords do not match.")
                return ""
            if not password:
                self._error_label.set_text("Password cannot be empty.")
                return ""
        return password

    def do_response(self, response_id: int) -> None:
        """Intercept OK to validate before closing."""
        if response_id == Gtk.ResponseType.OK:
            if not self.get_password():
                # Validation failed — keep dialog open
                return
        super().do_response(response_id)
