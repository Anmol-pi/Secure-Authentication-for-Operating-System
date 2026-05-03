#!/usr/bin/env python3
"""
LinuxAuthGuard - Vault GUI (GTK4)
Full multi-pane application: Dashboard, Vault Explorer, Activity Logs, Settings.
Serves the IPC socket that fuse_vault.c uses to request passwords.
"""

from __future__ import annotations

import gi
gi.require_version("Gtk", "4.0")
gi.require_version("Gdk", "4.0")

import logging
import os
import socket
import sys
import threading
import time
from datetime import datetime
from pathlib import Path
from typing import Optional, List, Dict, Any
import pwd

from gi.repository import Gtk, Gdk, GLib, Gio, Pango

sys.path.insert(0, str(Path(__file__).parent))
from vault_db import VaultDB, ProtectedItem
from prompt_dialog import PromptDialog

logger = logging.getLogger("linuxauthguard.vault_gui")
IPC_SOCKET_PATH = "/run/linuxauthguard/vault_auth.sock"

ADMIN_MODE: bool = os.environ.get("LAG_ADMIN_MODE") == "1" or os.geteuid() == 0

# ── Nav pages ────────────────────────────────────────────────────────────────
NAV_DASHBOARD   = 0
NAV_VAULT       = 1
NAV_LOGS        = 2
NAV_SETTINGS    = 3


# ─────────────────────────────────────────────────────────────────────────────
# Application
# ─────────────────────────────────────────────────────────────────────────────

class VaultApplication(Gtk.Application):
    def __init__(self) -> None:
        super().__init__(
            application_id="com.linuxauthguard.vault",
            flags=Gio.ApplicationFlags.FLAGS_NONE,
        )
        self.db = VaultDB()
        self._ipc_thread: Optional[threading.Thread] = None
        self.connect("activate", self._on_activate)
        self.connect("shutdown", self._on_shutdown)

    def _on_activate(self, _app: Gtk.Application) -> None:
        _load_css()
        self._start_ipc_server()
        window = MainWindow(application=self, db=self.db)
        window.present()

    def _on_shutdown(self, _app: Gtk.Application) -> None:
        self._stop_ipc_server()

    # ── IPC ──────────────────────────────────────────────────────────────────

    def _start_ipc_server(self) -> None:
        Path(IPC_SOCKET_PATH).parent.mkdir(parents=True, exist_ok=True)
        try:
            os.unlink(IPC_SOCKET_PATH)
        except FileNotFoundError:
            pass
        self._ipc_running = True
        self._ipc_server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self._ipc_server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._ipc_server.bind(IPC_SOCKET_PATH)
        os.chmod(IPC_SOCKET_PATH, 0o600)
        self._ipc_server.listen(8)
        self._ipc_server.settimeout(1.0)
        self._ipc_thread = threading.Thread(
            target=self._ipc_loop, daemon=True, name="vault-ipc"
        )
        self._ipc_thread.start()

    def _stop_ipc_server(self) -> None:
        self._ipc_running = False
        try:
            self._ipc_server.close()
        except Exception:
            pass

    def _ipc_loop(self) -> None:
        while self._ipc_running:
            try:
                conn, _ = self._ipc_server.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            threading.Thread(
                target=self._handle_ipc_client, args=(conn,), daemon=True
            ).start()

    def _handle_ipc_client(self, conn: socket.socket) -> None:
        try:
            data = conn.recv(4096).decode(errors="replace").strip()
            if data.startswith("AUTH_REQUEST:"):
                path = data[13:]
                result: dict = {}
                event = threading.Event()

                def _show() -> bool:
                    d = PromptDialog(path=path)
                    d.connect("response", lambda dlg, r: _resp(dlg, r))
                    d.present()
                    return False

                def _resp(dlg: PromptDialog, r: int) -> None:
                    result["password"] = dlg.get_password() if r == Gtk.ResponseType.OK else None
                    dlg.destroy()
                    event.set()

                GLib.idle_add(_show)
                event.wait(timeout=120)
                pw = result.get("password")
                conn.send((f"PASSWORD:{pw}\n" if pw else b"DENIED\n").encode() if pw else b"DENIED\n")
            else:
                conn.send(b"ERROR:unknown_command\n")
        except Exception as e:
            logger.warning("IPC error: %s", e)
        finally:
            conn.close()


# ─────────────────────────────────────────────────────────────────────────────
# Main window — sidebar + stack
# ─────────────────────────────────────────────────────────────────────────────

class MainWindow(Gtk.ApplicationWindow):
    def __init__(self, application: VaultApplication, db: VaultDB) -> None:
        super().__init__(application=application)
        self.db = db
        self.is_admin = ADMIN_MODE
        self.set_title("LinuxAuthGuard")
        self.set_default_size(1100, 680)
        self.set_decorated(True)
        self._toast_timeout_id: Optional[int] = None
        self._build_ui()
        # Navigate to dashboard on startup
        self._nav_to(NAV_DASHBOARD)

    # ── Build ─────────────────────────────────────────────────────────────────

    def _build_ui(self) -> None:
        # ── Titlebar ──────────────────────────────────────────────────────────
        header = Gtk.HeaderBar()
        header.add_css_class("lag-header")

        brand = Gtk.Box(spacing=8)
        brand.set_halign(Gtk.Align.CENTER)
        shield = Gtk.Label(label="🛡")
        shield.add_css_class("brand-icon")
        brand_lbl = Gtk.Label(label="LinuxAuthGuard")
        brand_lbl.add_css_class("brand-title")
        brand.append(shield)
        brand.append(brand_lbl)
        header.set_title_widget(brand)

        # Mode badge
        badge_lbl = "🔑  Admin" if self.is_admin else "👁  View Only"
        badge = Gtk.Label(label=badge_lbl)
        badge.add_css_class("badge-admin" if self.is_admin else "badge-user")
        header.pack_start(badge)

        # Refresh
        refresh_btn = Gtk.Button()
        refresh_btn.set_icon_name("view-refresh-symbolic")
        refresh_btn.add_css_class("lag-icon-btn")
        refresh_btn.set_tooltip_text("Refresh")
        refresh_btn.connect("clicked", lambda _: self._refresh_current())
        header.pack_end(refresh_btn)

        self.set_titlebar(header)

        # ── Root layout: sidebar + content + toast overlay ─────────────────────
        overlay = Gtk.Overlay()
        self.set_child(overlay)

        root_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=0)
        overlay.set_child(root_box)

        # Sidebar
        sidebar = self._build_sidebar()
        root_box.append(sidebar)

        # Vertical divider
        div = Gtk.Separator(orientation=Gtk.Orientation.VERTICAL)
        div.add_css_class("lag-divider")
        root_box.append(div)

        # Page stack
        self._stack = Gtk.Stack()
        self._stack.set_transition_type(Gtk.StackTransitionType.SLIDE_LEFT_RIGHT)
        self._stack.set_transition_duration(220)
        self._stack.set_hexpand(True)
        self._stack.set_vexpand(True)
        root_box.append(self._stack)

        # Pages
        self._dashboard_page = DashboardPage(window=self, db=self.db)
        self._vault_page     = VaultPage(window=self, db=self.db)
        self._logs_page      = LogsPage(window=self, db=self.db)
        self._settings_page  = SettingsPage(window=self, db=self.db)

        self._stack.add_named(self._dashboard_page, "dashboard")
        self._stack.add_named(self._vault_page,     "vault")
        self._stack.add_named(self._logs_page,      "logs")
        self._stack.add_named(self._settings_page,  "settings")

        # Toast overlay widget
        self._toast_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=0)
        self._toast_box.set_halign(Gtk.Align.CENTER)
        self._toast_box.set_valign(Gtk.Align.END)
        self._toast_box.set_margin_bottom(24)
        self._toast_box.set_visible(False)
        overlay.add_overlay(self._toast_box)

        self._toast_label = Gtk.Label(label="")
        self._toast_label.add_css_class("toast-label")
        self._toast_box.append(self._toast_label)

        # Keyboard shortcut: Ctrl+L → lock all (placeholder)
        key_ctrl = Gtk.EventControllerKey()
        key_ctrl.connect("key-pressed", self._on_key_pressed)
        self.add_controller(key_ctrl)

    def _build_sidebar(self) -> Gtk.Box:
        sidebar = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=0)
        sidebar.add_css_class("lag-sidebar")
        sidebar.set_size_request(210, -1)

        # Nav entries: (icon, label, page_index)
        nav_items = [
            ("🏠", "Dashboard",      NAV_DASHBOARD),
            ("🔒", "Vault Explorer", NAV_VAULT),
            ("📋", "Activity Logs",  NAV_LOGS),
            ("⚙️",  "Settings",       NAV_SETTINGS),
        ]

        self._nav_btns: List[Gtk.Button] = []
        nav_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=4)
        nav_box.set_margin_top(20)
        nav_box.set_margin_start(12)
        nav_box.set_margin_end(12)
        nav_box.set_vexpand(True)
        sidebar.append(nav_box)

        for icon, label, page_idx in nav_items:
            btn = Gtk.Button()
            btn.add_css_class("nav-btn")
            inner = Gtk.Box(spacing=12)
            inner.set_margin_start(8)
            ic = Gtk.Label(label=icon)
            ic.add_css_class("nav-icon")
            lbl = Gtk.Label(label=label)
            lbl.add_css_class("nav-label")
            lbl.set_halign(Gtk.Align.START)
            lbl.set_hexpand(True)
            inner.append(ic)
            inner.append(lbl)
            btn.set_child(inner)
            btn.connect("clicked", lambda _, p=page_idx: self._nav_to(p))
            nav_box.append(btn)
            self._nav_btns.append(btn)

        # Bottom: user info
        bottom = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=6)
        bottom.add_css_class("sidebar-bottom")
        bottom.set_margin_start(16)
        bottom.set_margin_end(16)
        bottom.set_margin_bottom(20)

        sep = Gtk.Separator()
        sep.add_css_class("lag-divider")
        sep.set_margin_bottom(12)
        bottom.append(sep)

        try:
            uname = pwd.getpwuid(os.getuid()).pw_name
        except Exception:
            uname = str(os.getuid())
        user_lbl = Gtk.Label(label=f"👤  {uname}")
        user_lbl.add_css_class("sidebar-user")
        user_lbl.set_halign(Gtk.Align.START)
        bottom.append(user_lbl)

        sidebar.append(bottom)
        return sidebar

    # ── Navigation ────────────────────────────────────────────────────────────

    def _nav_to(self, page: int) -> None:
        self._current_page = page
        names = ["dashboard", "vault", "logs", "settings"]
        self._stack.set_visible_child_name(names[page])

        for i, btn in enumerate(self._nav_btns):
            if i == page:
                btn.add_css_class("nav-btn-active")
            else:
                btn.remove_css_class("nav-btn-active")

        # Refresh the target page
        self._refresh_current()

    def _refresh_current(self) -> None:
        pages = [
            self._dashboard_page,
            self._vault_page,
            self._logs_page,
            self._settings_page,
        ]
        pages[self._current_page].refresh()

    # ── Toast notification ────────────────────────────────────────────────────

    def show_toast(self, message: str, kind: str = "info") -> None:
        """kind: 'success' | 'error' | 'info'"""
        self._toast_label.set_text(message)
        self._toast_box.remove_css_class("toast-success")
        self._toast_box.remove_css_class("toast-error")
        self._toast_box.remove_css_class("toast-info")
        self._toast_box.add_css_class(f"toast-{kind}")
        self._toast_box.set_visible(True)
        self._toast_box.add_css_class("toast-in")

        if self._toast_timeout_id:
            GLib.source_remove(self._toast_timeout_id)
        self._toast_timeout_id = GLib.timeout_add(3000, self._hide_toast)

    def _hide_toast(self) -> bool:
        self._toast_box.set_visible(False)
        self._toast_box.remove_css_class("toast-in")
        self._toast_timeout_id = None
        return False

    def show_error(self, message: str) -> None:
        self.show_toast(f"✗  {message}", "error")

    def show_success(self, message: str) -> None:
        self.show_toast(f"✓  {message}", "success")

    # ── Keyboard shortcuts ────────────────────────────────────────────────────

    def _on_key_pressed(self, ctrl, keyval, keycode, state) -> bool:
        if state & Gdk.ModifierType.CONTROL_MASK:
            if keyval == Gdk.KEY_l:
                self.show_toast("🔒  Vault locked (Ctrl+L)", "info")
                return True
            if keyval == ord("1"):
                self._nav_to(NAV_DASHBOARD); return True
            if keyval == ord("2"):
                self._nav_to(NAV_VAULT); return True
            if keyval == ord("3"):
                self._nav_to(NAV_LOGS); return True
            if keyval == ord("4"):
                self._nav_to(NAV_SETTINGS); return True
        return False


# ─────────────────────────────────────────────────────────────────────────────
# Dashboard page
# ─────────────────────────────────────────────────────────────────────────────

class DashboardPage(Gtk.Box):
    def __init__(self, window: MainWindow, db: VaultDB) -> None:
        super().__init__(orientation=Gtk.Orientation.VERTICAL, spacing=0)
        self.window = window
        self.db = db
        self._build()

    def _build(self) -> None:
        scroll = Gtk.ScrolledWindow()
        scroll.set_policy(Gtk.PolicyType.NEVER, Gtk.PolicyType.AUTOMATIC)
        scroll.set_vexpand(True)
        self.append(scroll)

        content = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=0)
        content.set_margin_top(32)
        content.set_margin_bottom(32)
        content.set_margin_start(40)
        content.set_margin_end(40)
        scroll.set_child(content)

        # Page heading
        heading = Gtk.Label(label="Dashboard")
        heading.add_css_class("page-heading")
        heading.set_halign(Gtk.Align.START)
        content.append(heading)

        sub = Gtk.Label(label="Security overview and quick actions")
        sub.add_css_class("page-subheading")
        sub.set_halign(Gtk.Align.START)
        sub.set_margin_bottom(28)
        content.append(sub)

        # ── Stat cards row ─────────────────────────────────────────────────────
        cards_row = Gtk.Box(spacing=16)
        cards_row.set_margin_bottom(32)
        content.append(cards_row)

        self._card_files   = self._stat_card("🔒", "0", "Protected Items",  "card-blue")
        self._card_events  = self._stat_card("📋", "0", "Total Events",      "card-violet")
        self._card_denied  = self._stat_card("⚠",  "0", "Denied Accesses",   "card-red")
        self._card_mode    = self._stat_card(
            "🔑" if self.window.is_admin else "👁",
            "Admin" if self.window.is_admin else "View",
            "Current Mode", "card-gold"
        )
        for card in [self._card_files, self._card_events, self._card_denied, self._card_mode]:
            card.set_hexpand(True)
            cards_row.append(card)

        # ── Quick actions ──────────────────────────────────────────────────────
        qa_heading = Gtk.Label(label="Quick Actions")
        qa_heading.add_css_class("section-heading")
        qa_heading.set_halign(Gtk.Align.START)
        qa_heading.set_margin_bottom(12)
        content.append(qa_heading)

        qa_row = Gtk.Box(spacing=12)
        qa_row.set_margin_bottom(32)
        content.append(qa_row)

        def _quick_btn(icon, label, page, css):
            btn = Gtk.Button()
            btn.add_css_class("quick-action-btn")
            btn.add_css_class(css)
            inner = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=6)
            inner.set_margin_top(16)
            inner.set_margin_bottom(16)
            inner.set_halign(Gtk.Align.CENTER)
            ic = Gtk.Label(label=icon)
            ic.add_css_class("quick-action-icon")
            lbl = Gtk.Label(label=label)
            lbl.add_css_class("quick-action-label")
            inner.append(ic)
            inner.append(lbl)
            btn.set_child(inner)
            btn.connect("clicked", lambda _, p=page: self.window._nav_to(p))
            btn.set_hexpand(True)
            return btn

        qa_row.append(_quick_btn("🔒", "Vault Explorer",  NAV_VAULT,    "qa-blue"))
        qa_row.append(_quick_btn("📋", "Activity Logs",   NAV_LOGS,     "qa-violet"))
        qa_row.append(_quick_btn("⚙️",  "Settings",        NAV_SETTINGS, "qa-slate"))

        # ── Recent activity ────────────────────────────────────────────────────
        ra_heading = Gtk.Label(label="Recent Activity")
        ra_heading.add_css_class("section-heading")
        ra_heading.set_halign(Gtk.Align.START)
        ra_heading.set_margin_bottom(12)
        content.append(ra_heading)

        self._recent_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=6)
        content.append(self._recent_box)

    def _stat_card(self, icon: str, value: str, label: str, css: str) -> Gtk.Box:
        card = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=6)
        card.add_css_class("stat-card")
        card.add_css_class(css)
        card.set_margin_top(0)

        top = Gtk.Box(spacing=8)
        top.set_margin_top(20)
        top.set_margin_start(20)
        top.set_margin_end(20)
        card.append(top)

        ic = Gtk.Label(label=icon)
        ic.add_css_class("stat-icon")
        top.append(ic)

        val = Gtk.Label(label=value)
        val.add_css_class("stat-value")
        val.set_hexpand(True)
        val.set_halign(Gtk.Align.END)
        top.append(val)

        lbl = Gtk.Label(label=label)
        lbl.add_css_class("stat-label")
        lbl.set_halign(Gtk.Align.START)
        lbl.set_margin_start(20)
        lbl.set_margin_bottom(16)
        card.append(lbl)

        # Store value label ref on card for update
        card._value_label = val  # type: ignore[attr-defined]
        return card

    def refresh(self) -> None:
        items = self.db.list_items()
        total_events = 0
        total_denied = 0
        all_logs: List[Dict[str, Any]] = []

        for item in items:
            stats = self.db.get_access_stats(item.path)
            total_events += stats.get("total", 0)
            total_denied += stats.get("denied", 0)
            logs = self.db.get_access_log(item.path, limit=5)
            all_logs.extend(logs)

        self._card_files._value_label.set_text(str(len(items)))   # type: ignore
        self._card_events._value_label.set_text(str(total_events)) # type: ignore
        self._card_denied._value_label.set_text(str(total_denied)) # type: ignore

        # Recent activity — last 5 events across all items
        all_logs.sort(key=lambda e: e["timestamp"], reverse=True)
        recent = all_logs[:5]

        # Clear old rows
        child = self._recent_box.get_first_child()
        while child:
            nxt = child.get_next_sibling()
            self._recent_box.remove(child)
            child = nxt

        if not recent:
            empty = Gtk.Label(label="No activity recorded yet.")
            empty.add_css_class("empty-hint")
            empty.set_halign(Gtk.Align.START)
            self._recent_box.append(empty)
            return

        for entry in recent:
            row = self._activity_row(entry)
            self._recent_box.append(row)

    def _activity_row(self, entry: Dict[str, Any]) -> Gtk.Box:
        row = Gtk.Box(spacing=16)
        row.add_css_class("activity-row")

        # Result dot
        dot = Gtk.Label(label="●")
        dot.add_css_class("dot-granted" if entry["granted"] else "dot-denied")
        row.append(dot)

        # Event type
        atype = Gtk.Label(label=entry["access_type"].upper())
        atype.add_css_class("activity-type")
        atype.set_size_request(80, -1)
        atype.set_halign(Gtk.Align.START)
        row.append(atype)

        # Path (truncated)
        path_str = entry.get("item_path", "?")
        short = Path(path_str).name if path_str else "?"
        path_lbl = Gtk.Label(label=short)
        path_lbl.add_css_class("activity-path")
        path_lbl.set_tooltip_text(path_str)
        path_lbl.set_halign(Gtk.Align.START)
        path_lbl.set_hexpand(True)
        path_lbl.set_ellipsize(Pango.EllipsizeMode.END)
        row.append(path_lbl)

        # Timestamp
        ts = datetime.fromtimestamp(entry["timestamp"]).strftime("%b %d %H:%M")
        ts_lbl = Gtk.Label(label=ts)
        ts_lbl.add_css_class("activity-ts")
        row.append(ts_lbl)

        return row


# ─────────────────────────────────────────────────────────────────────────────
# Vault Explorer page
# ─────────────────────────────────────────────────────────────────────────────

class VaultPage(Gtk.Box):
    def __init__(self, window: MainWindow, db: VaultDB) -> None:
        super().__init__(orientation=Gtk.Orientation.VERTICAL, spacing=0)
        self.window = window
        self.db = db
        self._search_text = ""
        self._build()

    def _build(self) -> None:
        # Top toolbar
        toolbar = Gtk.Box(spacing=12)
        toolbar.add_css_class("page-toolbar")
        toolbar.set_margin_top(20)
        toolbar.set_margin_bottom(0)
        toolbar.set_margin_start(32)
        toolbar.set_margin_end(32)
        self.append(toolbar)

        heading = Gtk.Label(label="Vault Explorer")
        heading.add_css_class("page-heading")
        heading.set_hexpand(True)
        heading.set_halign(Gtk.Align.START)
        toolbar.append(heading)

        # Search box
        search = Gtk.SearchEntry()
        search.set_placeholder_text("Filter items…")
        search.add_css_class("lag-search")
        search.set_size_request(220, -1)
        search.connect("search-changed", self._on_search)
        toolbar.append(search)

        # Add button (admin only)
        if self.window.is_admin:
            add_btn = Gtk.Button(label="＋  Protect Item")
            add_btn.add_css_class("btn-primary")
            add_btn.connect("clicked", self._on_add_clicked)
            toolbar.append(add_btn)

        sub = Gtk.Label(label="Password-protected files and folders")
        sub.add_css_class("page-subheading")
        sub.set_halign(Gtk.Align.START)
        sub.set_margin_start(32)
        sub.set_margin_top(4)
        sub.set_margin_bottom(16)
        self.append(sub)

        # Separator
        sep = Gtk.Separator()
        sep.add_css_class("lag-divider")
        self.append(sep)

        # List
        scroll = Gtk.ScrolledWindow()
        scroll.set_policy(Gtk.PolicyType.NEVER, Gtk.PolicyType.AUTOMATIC)
        scroll.set_vexpand(True)
        self.append(scroll)

        self._list_box = Gtk.ListBox()
        self._list_box.add_css_class("vault-list")
        self._list_box.set_selection_mode(Gtk.SelectionMode.NONE)
        scroll.set_child(self._list_box)

        # Status bar
        self._status_bar = Gtk.Label(label="")
        self._status_bar.add_css_class("page-statusbar")
        self._status_bar.set_halign(Gtk.Align.START)
        self._status_bar.set_margin_start(32)
        self._status_bar.set_margin_top(8)
        self._status_bar.set_margin_bottom(8)
        self.append(self._status_bar)

    def _on_search(self, entry: Gtk.SearchEntry) -> None:
        self._search_text = entry.get_text().lower()
        self.refresh()

    def refresh(self) -> None:
        child = self._list_box.get_first_child()
        while child:
            nxt = child.get_next_sibling()
            self._list_box.remove(child)
            child = nxt

        items = self.db.list_items()
        if self._search_text:
            items = [i for i in items if self._search_text in i.path.lower()]

        for item in items:
            self._list_box.append(self._build_row(item))

        if not items:
            ph_row = Gtk.ListBoxRow()
            ph_row.set_activatable(False)
            ph_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=10)
            ph_box.set_margin_top(60)
            ph_box.set_margin_bottom(60)
            ph_box.set_halign(Gtk.Align.CENTER)
            icon = Gtk.Label(label="🔐")
            icon.set_markup('<span size="xx-large">🔐</span>')
            ph_box.append(icon)
            title = Gtk.Label(label="No protected items" if not self._search_text else "No results")
            title.add_css_class("page-heading-sm")
            ph_box.append(title)
            hint_text = ("Click  ＋ Protect Item  above to get started" if self.window.is_admin
                         else "Open as Administrator to add protected items")
            hint = Gtk.Label(label=hint_text)
            hint.add_css_class("empty-hint")
            ph_box.append(hint)
            ph_row.set_child(ph_box)
            self._list_box.append(ph_row)

        count = len(items)
        mode = "Administrator" if self.window.is_admin else "View Only"
        self._status_bar.set_text(f"{count} item(s)  ·  {mode}")

    def _build_row(self, item: ProtectedItem) -> Gtk.ListBoxRow:
        row = Gtk.ListBoxRow()
        row.set_activatable(False)
        row.add_css_class("vault-row")

        outer = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=14)
        outer.set_margin_top(14)
        outer.set_margin_bottom(14)
        outer.set_margin_start(20)
        outer.set_margin_end(20)
        row.set_child(outer)

        is_dir = Path(item.path).is_dir()

        # Lock indicator bar (left accent)
        accent = Gtk.Box()
        accent.add_css_class("row-accent")
        accent.set_size_request(3, -1)
        outer.append(accent)

        # Icon
        icon = Gtk.Label(label="📁" if is_dir else "📄")
        icon.add_css_class("vault-item-icon")
        outer.append(icon)

        # Info
        info = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=4)
        info.set_hexpand(True)
        outer.append(info)

        # Path label — basename bold, parent dimmed
        path_obj = Path(item.path)
        display = Gtk.Label()
        display.set_markup(
            f'<b>{GLib.markup_escape_text(path_obj.name)}</b>'
            f'<span foreground="#475569">  {GLib.markup_escape_text(str(path_obj.parent))}</span>'
        )
        display.set_halign(Gtk.Align.START)
        display.set_ellipsize(Pango.EllipsizeMode.MIDDLE)
        display.add_css_class("vault-item-path")
        display.set_tooltip_text(item.path)
        info.append(display)

        # Meta chips
        chips = Gtk.Box(spacing=8)
        info.append(chips)

        def _chip(txt: str, css: str) -> Gtk.Label:
            c = Gtk.Label(label=txt)
            c.add_css_class("chip")
            c.add_css_class(css)
            return c

        chips.append(_chip("📂 Dir" if is_dir else "📄 File", "chip-type"))
        if item.recursive and is_dir:
            chips.append(_chip("Recursive", "chip-meta"))
        if item.totp_required:
            chips.append(_chip("🔐 TOTP", "chip-totp"))
        created = datetime.fromtimestamp(item.created_at).strftime("%b %d, %Y")
        chips.append(_chip(f"Since {created}", "chip-date"))

        # Stats
        try:
            stats = self.db.get_access_stats(item.path)
            total = stats.get("total", 0)
            chips.append(_chip(f"{total} access{'es' if total != 1 else ''}", "chip-stats"))
        except Exception:
            pass

        # Actions
        actions = Gtk.Box(spacing=8)
        actions.set_valign(Gtk.Align.CENTER)
        outer.append(actions)

        log_btn = Gtk.Button(label="Logs")
        log_btn.add_css_class("btn-ghost")
        log_btn.connect("clicked", lambda _, p=item.path: self._view_log(p))
        actions.append(log_btn)

        if self.window.is_admin:
            pw_btn = Gtk.Button(label="Password")
            pw_btn.add_css_class("btn-ghost")
            pw_btn.connect("clicked", lambda _, p=item.path: self._change_password(p))
            actions.append(pw_btn)

            rm_btn = Gtk.Button(label="Remove")
            rm_btn.add_css_class("btn-danger")
            rm_btn.connect("clicked", lambda _, p=item.path: self._remove_item(p))
            actions.append(rm_btn)

        return row

    def _view_log(self, path: str) -> None:
        try:
            self.db.log_access(path, os.getuid(), "view_log", True)
        except Exception:
            pass
        entries = self.db.get_access_log(path, limit=100)
        LogDetailWindow(transient_for=self.window, path=path, entries=entries).present()

    def _on_add_clicked(self, _btn: Gtk.Button) -> None:
        dialog = Gtk.FileChooserDialog(
            title="Select File or Folder to Protect",
            transient_for=self.window,
            action=Gtk.FileChooserAction.OPEN,
        )
        dialog.add_button("Cancel", Gtk.ResponseType.CANCEL)
        dialog.add_button("Protect", Gtk.ResponseType.ACCEPT)
        dialog.connect("response", self._on_file_chosen)
        dialog.present()

    def _on_file_chosen(self, dialog: Gtk.FileChooserDialog, response: int) -> None:
        if response != Gtk.ResponseType.ACCEPT:
            dialog.destroy(); return
        gfile = dialog.get_file()
        dialog.destroy()
        if not gfile: return
        path = gfile.get_path()
        if not path: return
        if self.db.get_item(path):
            self.window.show_error(f"Already protected: {Path(path).name}")
            return
        prompt = PromptDialog(path=path, title="Set Protection Password",
                              confirm=True, transient_for=self.window)
        prompt.connect("response", lambda d, r, p=path: self._on_add_response(d, r, p))
        prompt.present()

    def _on_add_response(self, dialog: PromptDialog, response: int, path: str) -> None:
        if response != Gtk.ResponseType.OK:
            dialog.destroy(); return
        password = dialog.get_password()
        dialog.destroy()
        if not password:
            self.window.show_error("Password cannot be empty."); return
        try:
            uid = os.stat(path).st_uid
            self.db.add_item(path=path, password=password, owner_uid=uid,
                             recursive=True, totp_required=False)
            self.db.log_access(path, os.getuid(), "protect", True)
            self.window.show_success(f"Protected: {Path(path).name}")
            self.refresh()
        except Exception as e:
            self.window.show_error(str(e))
        finally:
            del password

    def _remove_item(self, path: str) -> None:
        confirm = Gtk.AlertDialog()
        confirm.set_message(f"Remove protection?")
        confirm.set_detail(f"{path}\n\nEnter the current password to confirm.")
        confirm.set_buttons(["Cancel", "Remove"])
        confirm.set_cancel_button(0)
        confirm.choose(self.window, None, lambda d, r: self._do_remove(d, r, path))

    def _do_remove(self, dialog: Gtk.AlertDialog, result: Gio.AsyncResult, path: str) -> None:
        try:
            if dialog.choose_finish(result) != 1: return
        except Exception: return
        prompt = PromptDialog(path=path, title="Confirm Removal", transient_for=self.window)
        prompt.connect("response", lambda d, r, p=path: self._on_remove_response(d, r, p))
        prompt.present()

    def _on_remove_response(self, dialog: PromptDialog, response: int, path: str) -> None:
        if response != Gtk.ResponseType.OK:
            dialog.destroy(); return
        pw = dialog.get_password()
        dialog.destroy()
        if not self.db.verify_password(path, pw):
            del pw
            self.window.show_error("Incorrect password."); return
        del pw
        self.db.remove_item(path)
        self.window.show_success(f"Removed: {Path(path).name}")
        self.refresh()

    def _change_password(self, path: str) -> None:
        prompt = PromptDialog(path=path, title="Change Password",
                              confirm=True, transient_for=self.window)
        prompt.connect("response", lambda d, r, p=path: self._on_change_pw(d, r, p))
        prompt.present()

    def _on_change_pw(self, dialog: PromptDialog, response: int, path: str) -> None:
        if response != Gtk.ResponseType.OK:
            dialog.destroy(); return
        pw = dialog.get_password()
        dialog.destroy()
        if not pw: return
        try:
            self.db.update_password(path, pw)
            self.window.show_success(f"Password updated: {Path(path).name}")
        except Exception as e:
            self.window.show_error(str(e))
        finally:
            del pw


# ─────────────────────────────────────────────────────────────────────────────
# Activity Logs page
# ─────────────────────────────────────────────────────────────────────────────

class LogsPage(Gtk.Box):
    def __init__(self, window: MainWindow, db: VaultDB) -> None:
        super().__init__(orientation=Gtk.Orientation.VERTICAL, spacing=0)
        self.window = window
        self.db = db
        self._filter_type = "ALL"
        self._build()

    def _build(self) -> None:
        # Toolbar
        toolbar = Gtk.Box(spacing=12)
        toolbar.add_css_class("page-toolbar")
        toolbar.set_margin_top(20)
        toolbar.set_margin_bottom(0)
        toolbar.set_margin_start(32)
        toolbar.set_margin_end(32)
        self.append(toolbar)

        heading = Gtk.Label(label="Activity Logs")
        heading.add_css_class("page-heading")
        heading.set_hexpand(True)
        heading.set_halign(Gtk.Align.START)
        toolbar.append(heading)

        # Filter dropdown
        filter_model = Gtk.StringList()
        for opt in ["ALL", "OPEN", "SESSION", "PROTECT", "VIEW_LOG", "STATUS"]:
            filter_model.append(opt)
        self._filter_combo = Gtk.DropDown(model=filter_model)
        self._filter_combo.add_css_class("lag-dropdown")
        self._filter_combo.connect("notify::selected", self._on_filter_changed)
        toolbar.append(self._filter_combo)

        sub = Gtk.Label(label="All access events across protected items")
        sub.add_css_class("page-subheading")
        sub.set_halign(Gtk.Align.START)
        sub.set_margin_start(32)
        sub.set_margin_top(4)
        sub.set_margin_bottom(16)
        self.append(sub)

        sep = Gtk.Separator()
        sep.add_css_class("lag-divider")
        self.append(sep)

        # Column headers
        hdr = Gtk.Box(spacing=0)
        hdr.add_css_class("log-table-header")
        hdr.set_margin_start(24)
        hdr.set_margin_end(24)
        hdr.set_margin_top(10)
        hdr.set_margin_bottom(6)
        self.append(hdr)

        for col, width in [("TIMESTAMP", 170), ("USER", 100), ("EVENT", 100), ("FILE", -1), ("RESULT", 90)]:
            h = Gtk.Label(label=col)
            h.add_css_class("log-col-header")
            h.set_halign(Gtk.Align.START)
            if width > 0:
                h.set_size_request(width, -1)
            else:
                h.set_hexpand(True)
            hdr.append(h)

        sep2 = Gtk.Separator()
        sep2.add_css_class("lag-divider")
        self.append(sep2)

        # Log list
        scroll = Gtk.ScrolledWindow()
        scroll.set_policy(Gtk.PolicyType.NEVER, Gtk.PolicyType.AUTOMATIC)
        scroll.set_vexpand(True)
        self.append(scroll)

        self._list_box = Gtk.ListBox()
        self._list_box.add_css_class("vault-list")
        self._list_box.set_selection_mode(Gtk.SelectionMode.NONE)
        scroll.set_child(self._list_box)

        # Status bar
        self._status_bar = Gtk.Label(label="")
        self._status_bar.add_css_class("page-statusbar")
        self._status_bar.set_halign(Gtk.Align.START)
        self._status_bar.set_margin_start(32)
        self._status_bar.set_margin_top(8)
        self._status_bar.set_margin_bottom(8)
        self.append(self._status_bar)

    def _on_filter_changed(self, combo: Gtk.DropDown, _param) -> None:
        model = combo.get_model()
        idx = combo.get_selected()
        item = model.get_item(idx)
        self._filter_type = item.get_string() if item else "ALL"
        self.refresh()

    def refresh(self) -> None:
        child = self._list_box.get_first_child()
        while child:
            nxt = child.get_next_sibling()
            self._list_box.remove(child)
            child = nxt

        # Gather all logs across all items
        items = self.db.list_items()
        all_logs: List[Dict[str, Any]] = []
        for item in items:
            logs = self.db.get_access_log(item.path, limit=200)
            all_logs.extend(logs)

        all_logs.sort(key=lambda e: e["timestamp"], reverse=True)

        # Apply filter
        if self._filter_type != "ALL":
            all_logs = [e for e in all_logs
                        if e["access_type"].upper() == self._filter_type]

        if not all_logs:
            ph_row = Gtk.ListBoxRow()
            ph_row.set_activatable(False)
            lbl = Gtk.Label(label="No log entries found.")
            lbl.add_css_class("empty-hint")
            lbl.set_margin_top(40)
            lbl.set_margin_bottom(40)
            ph_row.set_child(lbl)
            self._list_box.append(ph_row)
        else:
            for entry in all_logs[:200]:
                self._list_box.append(self._build_log_row(entry))

        self._status_bar.set_text(f"{len(all_logs)} event(s)")

    def _build_log_row(self, entry: Dict[str, Any]) -> Gtk.ListBoxRow:
        row = Gtk.ListBoxRow()
        row.set_activatable(False)
        row.add_css_class("log-row")

        box = Gtk.Box(spacing=0)
        box.set_margin_top(8)
        box.set_margin_bottom(8)
        box.set_margin_start(24)
        box.set_margin_end(24)
        row.set_child(box)

        granted = bool(entry["granted"])

        def _cell(text: str, width: int, css: str = "log-cell") -> Gtk.Label:
            lbl = Gtk.Label(label=text)
            lbl.add_css_class(css)
            lbl.set_halign(Gtk.Align.START)
            lbl.set_ellipsize(Pango.EllipsizeMode.END)
            if width > 0:
                lbl.set_size_request(width, -1)
            else:
                lbl.set_hexpand(True)
            return lbl

        ts = datetime.fromtimestamp(entry["timestamp"]).strftime("%Y-%m-%d %H:%M:%S")
        box.append(_cell(ts, 170))

        try:
            user = pwd.getpwuid(entry["accessed_by"]).pw_name
        except Exception:
            user = str(entry["accessed_by"])
        box.append(_cell(user, 100))

        atype = entry["access_type"].upper()
        type_lbl = Gtk.Label(label=atype)
        type_lbl.add_css_class("event-chip")
        type_css = {
            "OPEN": "chip-open", "SESSION": "chip-session",
            "PROTECT": "chip-protect", "VIEW_LOG": "chip-viewlog",
            "STATUS": "chip-status",
        }.get(atype, "chip-default")
        type_lbl.add_css_class(type_css)
        type_lbl.set_size_request(100, -1)
        type_lbl.set_halign(Gtk.Align.START)
        box.append(type_lbl)

        fname = Path(entry.get("item_path", "?")).name
        path_lbl = _cell(fname, -1)
        path_lbl.set_tooltip_text(entry.get("item_path", ""))
        box.append(path_lbl)

        result = Gtk.Label(label="✓ Granted" if granted else "✗ Denied")
        result.add_css_class("log-cell")
        result.add_css_class("result-granted" if granted else "result-denied")
        result.set_halign(Gtk.Align.START)
        result.set_size_request(90, -1)
        box.append(result)

        return row


# ─────────────────────────────────────────────────────────────────────────────
# Settings page
# ─────────────────────────────────────────────────────────────────────────────

class SettingsPage(Gtk.Box):
    def __init__(self, window: MainWindow, db: VaultDB) -> None:
        super().__init__(orientation=Gtk.Orientation.VERTICAL, spacing=0)
        self.window = window
        self.db = db
        # Simple in-memory settings (persist via GSettings in production)
        self._settings = {
            "auto_lock": False,
            "timeout_mins": 5,
            "root_only": False,
            "notifications": True,
        }
        self._build()

    def _build(self) -> None:
        scroll = Gtk.ScrolledWindow()
        scroll.set_policy(Gtk.PolicyType.NEVER, Gtk.PolicyType.AUTOMATIC)
        scroll.set_vexpand(True)
        self.append(scroll)

        content = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=0)
        content.set_margin_top(32)
        content.set_margin_bottom(32)
        content.set_margin_start(40)
        content.set_margin_end(40)
        scroll.set_child(content)

        heading = Gtk.Label(label="Settings")
        heading.add_css_class("page-heading")
        heading.set_halign(Gtk.Align.START)
        content.append(heading)

        sub = Gtk.Label(label="Configure vault behaviour and security preferences")
        sub.add_css_class("page-subheading")
        sub.set_halign(Gtk.Align.START)
        sub.set_margin_bottom(32)
        content.append(sub)

        def _section(title: str) -> Gtk.Box:
            grp = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=0)
            grp.add_css_class("settings-group")
            grp.set_margin_bottom(24)
            lbl = Gtk.Label(label=title)
            lbl.add_css_class("settings-group-title")
            lbl.set_halign(Gtk.Align.START)
            lbl.set_margin_bottom(8)
            content.append(lbl)
            content.append(grp)
            return grp

        def _toggle_row(grp: Gtk.Box, icon: str, title: str, desc: str, key: str) -> None:
            row = Gtk.Box(spacing=16)
            row.add_css_class("settings-row")
            grp.append(row)
            ic = Gtk.Label(label=icon)
            ic.add_css_class("settings-row-icon")
            row.append(ic)
            txt = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=2)
            txt.set_hexpand(True)
            row.append(txt)
            t = Gtk.Label(label=title)
            t.add_css_class("settings-row-title")
            t.set_halign(Gtk.Align.START)
            txt.append(t)
            d = Gtk.Label(label=desc)
            d.add_css_class("settings-row-desc")
            d.set_halign(Gtk.Align.START)
            txt.append(d)
            sw = Gtk.Switch()
            sw.set_active(self._settings[key])
            sw.set_valign(Gtk.Align.CENTER)
            sw.add_css_class("lag-switch")
            sw.connect("notify::active", lambda s, _p, k=key: self._on_toggle(k, s.get_active()))
            row.append(sw)

        sec1 = _section("Security")
        _toggle_row(sec1, "🔒", "Auto-Lock Vault",
                    "Automatically lock after inactivity", "auto_lock")
        _toggle_row(sec1, "🛡", "Root-Only Access",
                    "Require administrator for all operations", "root_only")

        sec2 = _section("Notifications")
        _toggle_row(sec2, "🔔", "Event Notifications",
                    "Show desktop notifications on access events", "notifications")

        # Timeout spinner
        sec3 = _section("Timeouts")
        timeout_row = Gtk.Box(spacing=16)
        timeout_row.add_css_class("settings-row")
        sec3.append(timeout_row)
        ic2 = Gtk.Label(label="⏱")
        ic2.add_css_class("settings-row-icon")
        timeout_row.append(ic2)
        txt2 = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=2)
        txt2.set_hexpand(True)
        timeout_row.append(txt2)
        t2 = Gtk.Label(label="Auto-Lock Timeout")
        t2.add_css_class("settings-row-title")
        t2.set_halign(Gtk.Align.START)
        txt2.append(t2)
        d2 = Gtk.Label(label="Minutes of inactivity before auto-lock")
        d2.add_css_class("settings-row-desc")
        d2.set_halign(Gtk.Align.START)
        txt2.append(d2)
        spin = Gtk.SpinButton()
        spin.set_adjustment(Gtk.Adjustment(
            value=self._settings["timeout_mins"],
            lower=1, upper=60, step_increment=1, page_increment=5
        ))
        spin.add_css_class("lag-spinbutton")
        spin.set_valign(Gtk.Align.CENTER)
        spin.connect("value-changed", self._on_timeout_changed)
        timeout_row.append(spin)

        # About section
        _section("About")
        about_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=6)
        about_box.add_css_class("settings-group")
        about_box.set_margin_bottom(0)

        for line in [
            ("LinuxAuthGuard", "page-heading-sm"),
            ("File vault protection for Linux Mint", "settings-row-desc"),
            (f"Mode: {'Administrator' if self.window.is_admin else 'View Only'}", "settings-row-desc"),
            (f"DB: /var/lib/linuxauthguard/vault.db", "settings-row-desc"),
        ]:
            lbl = Gtk.Label(label=line[0])
            lbl.add_css_class(line[1])
            lbl.set_halign(Gtk.Align.START)
            about_box.append(lbl)

        content.append(about_box)

    def _on_toggle(self, key: str, value: bool) -> None:
        self._settings[key] = value
        self.window.show_toast(
            f"{'Enabled' if value else 'Disabled'}: {key.replace('_', ' ').title()}", "info"
        )

    def _on_timeout_changed(self, spin: Gtk.SpinButton) -> None:
        self._settings["timeout_mins"] = int(spin.get_value())

    def refresh(self) -> None:
        pass  # Settings don't need DB refresh


# ─────────────────────────────────────────────────────────────────────────────
# Log detail window (modal)
# ─────────────────────────────────────────────────────────────────────────────

class LogDetailWindow(Gtk.Window):
    def __init__(self, transient_for: Gtk.Window, path: str, entries: list) -> None:
        super().__init__()
        self.set_transient_for(transient_for)
        self.set_modal(True)
        self.set_title("Access Log Detail")
        self.set_default_size(720, 500)

        outer = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=0)
        self.set_child(outer)

        # Header
        hdr = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=4)
        hdr.add_css_class("log-detail-header")
        hdr.set_margin_top(24)
        hdr.set_margin_bottom(16)
        hdr.set_margin_start(24)
        hdr.set_margin_end(24)
        outer.append(hdr)

        h = Gtk.Label(label="Access Log")
        h.add_css_class("page-heading")
        h.set_halign(Gtk.Align.START)
        hdr.append(h)

        p = Gtk.Label(label=path)
        p.add_css_class("page-subheading")
        p.set_halign(Gtk.Align.START)
        p.set_ellipsize(Pango.EllipsizeMode.MIDDLE)
        p.set_tooltip_text(path)
        hdr.append(p)

        sep = Gtk.Separator()
        sep.add_css_class("lag-divider")
        outer.append(sep)

        if not entries:
            empty = Gtk.Label(label="No access events recorded yet.")
            empty.add_css_class("empty-hint")
            empty.set_margin_top(60)
            empty.set_vexpand(True)
            outer.append(empty)
            return

        # Column header bar
        col_hdr = Gtk.Box(spacing=0)
        col_hdr.add_css_class("log-table-header")
        col_hdr.set_margin_start(24)
        col_hdr.set_margin_end(24)
        col_hdr.set_margin_top(10)
        col_hdr.set_margin_bottom(4)
        outer.append(col_hdr)

        for col, width in [("TIMESTAMP", 180), ("USER", 120), ("EVENT", 120), ("RESULT", -1)]:
            h2 = Gtk.Label(label=col)
            h2.add_css_class("log-col-header")
            h2.set_halign(Gtk.Align.START)
            if width > 0:
                h2.set_size_request(width, -1)
            else:
                h2.set_hexpand(True)
            col_hdr.append(h2)

        sep2 = Gtk.Separator()
        sep2.add_css_class("lag-divider")
        outer.append(sep2)

        scroll = Gtk.ScrolledWindow()
        scroll.set_vexpand(True)
        scroll.set_policy(Gtk.PolicyType.NEVER, Gtk.PolicyType.AUTOMATIC)
        outer.append(scroll)

        list_box = Gtk.ListBox()
        list_box.set_selection_mode(Gtk.SelectionMode.NONE)
        list_box.add_css_class("vault-list")
        scroll.set_child(list_box)

        for entry in entries:
            row = Gtk.ListBoxRow()
            row.set_activatable(False)
            row.add_css_class("log-row")
            box = Gtk.Box(spacing=0)
            box.set_margin_top(8)
            box.set_margin_bottom(8)
            box.set_margin_start(24)
            box.set_margin_end(24)
            row.set_child(box)

            granted = bool(entry["granted"])
            ts = datetime.fromtimestamp(entry["timestamp"]).strftime("%Y-%m-%d %H:%M:%S")
            try:
                user = pwd.getpwuid(entry["accessed_by"]).pw_name
            except Exception:
                user = str(entry["accessed_by"])
            atype = entry["access_type"].upper()

            def _c(text, width, css="log-cell"):
                lbl = Gtk.Label(label=text)
                lbl.add_css_class(css)
                lbl.set_halign(Gtk.Align.START)
                if width > 0:
                    lbl.set_size_request(width, -1)
                else:
                    lbl.set_hexpand(True)
                return lbl

            box.append(_c(ts, 180))
            box.append(_c(user, 120))

            et = Gtk.Label(label=atype)
            et.add_css_class("event-chip")
            et.add_css_class({"OPEN": "chip-open", "SESSION": "chip-session",
                              "PROTECT": "chip-protect", "VIEW_LOG": "chip-viewlog",
                              "STATUS": "chip-status"}.get(atype, "chip-default"))
            et.set_size_request(120, -1)
            et.set_halign(Gtk.Align.START)
            box.append(et)

            rl = Gtk.Label(label="✓ Granted" if granted else "✗ Denied")
            rl.add_css_class("log-cell")
            rl.add_css_class("result-granted" if granted else "result-denied")
            rl.set_hexpand(True)
            rl.set_halign(Gtk.Align.START)
            box.append(rl)

            list_box.append(row)

        footer = Gtk.Label(label=f"{len(entries)} event(s)")
        footer.add_css_class("page-statusbar")
        footer.set_halign(Gtk.Align.END)
        footer.set_margin_end(24)
        footer.set_margin_top(8)
        footer.set_margin_bottom(12)
        outer.append(footer)


# ─────────────────────────────────────────────────────────────────────────────
# CSS
# ─────────────────────────────────────────────────────────────────────────────

def _load_css() -> None:
    provider = Gtk.CssProvider()
    provider.load_from_data(VAULT_CSS.encode())
    display = Gdk.Display.get_default()
    if display:
        Gtk.StyleContext.add_provider_for_display(
            display, provider, Gtk.STYLE_PROVIDER_PRIORITY_APPLICATION
        )


VAULT_CSS = """
/* ═══════════════════════════════════════════════════════════════════════════
   LinuxAuthGuard — Design System
   Base: #0D1117  Accent: Indigo/Violet  Success: #4ade80  Error: #f87171
   ═══════════════════════════════════════════════════════════════════════════ */

/* ── Reset & base ─────────────────────────────────────────────────────────── */
* { box-sizing: border-box; }

window {
    background-color: #0D1117;
    color: #c9d1d9;
    font-family: "IBM Plex Sans", "Cantarell", "Segoe UI", sans-serif;
    font-size: 13px;
}

/* ── Header bar ───────────────────────────────────────────────────────────── */
headerbar {
    background-color: #161b22;
    border-bottom: 1px solid #30363d;
    min-height: 52px;
    padding: 0 12px;
    box-shadow: 0 1px 0 rgba(0,0,0,0.6);
}
.lag-header { background-color: #161b22; }
.brand-icon { font-size: 18px; margin-right: 2px; }
.brand-title {
    font-size: 15px;
    font-weight: 700;
    color: #f0f6fc;
    letter-spacing: -0.01em;
}

/* ── Mode badges ──────────────────────────────────────────────────────────── */
.badge-admin {
    font-size: 11px; font-weight: 700; letter-spacing: 0.03em;
    color: #0D1117;
    background: linear-gradient(135deg, #f0b429 0%, #d97706 100%);
    border-radius: 20px; padding: 3px 12px;
    margin-right: 4px;
}
.badge-user {
    font-size: 11px; font-weight: 600;
    color: #8b949e;
    background: #21262d;
    border: 1px solid #30363d;
    border-radius: 20px; padding: 3px 12px;
    margin-right: 4px;
}

/* ── Icon button ──────────────────────────────────────────────────────────── */
.lag-icon-btn {
    background: transparent;
    border: none;
    color: #8b949e;
    border-radius: 8px;
    padding: 6px;
    min-width: 32px; min-height: 32px;
}
.lag-icon-btn:hover { background: #21262d; color: #c9d1d9; }

/* ── Sidebar ──────────────────────────────────────────────────────────────── */
.lag-sidebar {
    background-color: #161b22;
    border-right: 1px solid #21262d;
}
.sidebar-bottom { margin-top: auto; }
.sidebar-user {
    font-size: 12px; color: #6e7681;
    letter-spacing: 0.01em;
}

/* ── Nav buttons ──────────────────────────────────────────────────────────── */
.nav-btn {
    background: transparent;
    border: none;
    border-radius: 10px;
    padding: 10px 12px;
    color: #8b949e;
    font-size: 13px;
    font-weight: 500;
    text-align: left;
    transition: background 150ms ease, color 150ms ease;
}
.nav-btn:hover {
    background: #21262d;
    color: #c9d1d9;
}
.nav-btn-active {
    background: rgba(88,166,255,0.1);
    color: #58a6ff;
    border-left: 3px solid #58a6ff;
}
.nav-btn-active:hover { background: rgba(88,166,255,0.15); }
.nav-icon { font-size: 16px; min-width: 24px; }
.nav-label { font-size: 13px; font-weight: 500; }

/* ── Dividers ─────────────────────────────────────────────────────────────── */
.lag-divider { background-color: #21262d; min-height: 1px; min-width: 1px; }

/* ── Page chrome ──────────────────────────────────────────────────────────── */
.page-heading {
    font-size: 22px; font-weight: 700;
    color: #f0f6fc; letter-spacing: -0.02em;
}
.page-heading-sm {
    font-size: 15px; font-weight: 600;
    color: #c9d1d9;
}
.page-subheading { font-size: 13px; color: #6e7681; margin-top: 2px; }
.section-heading {
    font-size: 13px; font-weight: 700;
    color: #8b949e; letter-spacing: 0.06em; text-transform: uppercase;
}
.page-toolbar { margin-bottom: 0; }
.page-statusbar {
    font-size: 11px; color: #6e7681;
    padding: 6px 0;
    border-top: 1px solid #21262d;
}
.empty-hint { font-size: 13px; color: #6e7681; }

/* ── Dashboard stat cards ─────────────────────────────────────────────────── */
.stat-card {
    background-color: #161b22;
    border: 1px solid #30363d;
    border-radius: 14px;
    transition: border-color 200ms ease;
}
.stat-card:hover { border-color: #58a6ff; }
.card-blue  { border-top: 3px solid #58a6ff; }
.card-violet{ border-top: 3px solid #a371f7; }
.card-red   { border-top: 3px solid #f85149; }
.card-gold  { border-top: 3px solid #f0b429; }
.stat-icon  { font-size: 22px; }
.stat-value {
    font-size: 28px; font-weight: 800;
    color: #f0f6fc; letter-spacing: -0.03em;
    font-variant-numeric: tabular-nums;
}
.stat-label { font-size: 12px; color: #6e7681; font-weight: 500; }

/* ── Quick actions ────────────────────────────────────────────────────────── */
.quick-action-btn {
    background: #161b22;
    border: 1px solid #30363d;
    border-radius: 14px;
    color: #c9d1d9;
    transition: all 180ms ease;
}
.quick-action-btn:hover { border-color: #58a6ff; background: #1c2128; }
.qa-blue:hover   { border-color: #58a6ff; }
.qa-violet:hover { border-color: #a371f7; }
.qa-slate:hover  { border-color: #6e7681; }
.quick-action-icon { font-size: 28px; }
.quick-action-label { font-size: 13px; font-weight: 600; color: #c9d1d9; }

/* ── Activity rows (dashboard) ────────────────────────────────────────────── */
.activity-row {
    background: #161b22;
    border: 1px solid #21262d;
    border-radius: 10px;
    padding: 10px 16px;
}
.dot-granted { color: #3fb950; font-size: 10px; }
.dot-denied  { color: #f85149; font-size: 10px; }
.activity-type {
    font-size: 11px; font-weight: 700; color: #8b949e;
    letter-spacing: 0.05em;
    font-family: "IBM Plex Mono", monospace;
}
.activity-path { font-size: 13px; color: #c9d1d9; }
.activity-ts   { font-size: 11px; color: #6e7681; font-family: "IBM Plex Mono", monospace; }

/* ── Vault list ───────────────────────────────────────────────────────────── */
.vault-list { background: transparent; }
.vault-row {
    background: #161b22;
    border: 1px solid #21262d;
    border-radius: 12px;
    margin: 3px 16px;
    transition: border-color 150ms ease, background 150ms ease;
}
.vault-row:hover {
    background: #1c2128;
    border-color: #388bfd;
}
.row-accent { background: #388bfd; border-radius: 2px; }
.vault-item-icon { font-size: 20px; min-width: 32px; }
.vault-item-path { font-size: 13px; color: #c9d1d9; }

/* ── Chips ────────────────────────────────────────────────────────────────── */
.chip {
    font-size: 10px; font-weight: 600;
    border-radius: 6px;
    padding: 2px 8px;
    letter-spacing: 0.02em;
}
.chip-type  { background: #21262d; color: #8b949e; border: 1px solid #30363d; }
.chip-meta  { background: rgba(56,139,253,0.1); color: #58a6ff; border: 1px solid rgba(56,139,253,0.2); }
.chip-totp  { background: rgba(163,113,247,0.1); color: #a371f7; border: 1px solid rgba(163,113,247,0.2); }
.chip-date  { background: transparent; color: #6e7681; }
.chip-stats { background: transparent; color: #6e7681; }

/* ── Buttons ──────────────────────────────────────────────────────────────── */
.btn-primary {
    background: linear-gradient(135deg, #388bfd 0%, #1f6feb 100%);
    color: #ffffff; font-weight: 600; font-size: 13px;
    border: none; border-radius: 10px; padding: 8px 18px;
    box-shadow: 0 2px 8px rgba(31,111,235,0.35);
    transition: all 150ms ease;
}
.btn-primary:hover {
    background: linear-gradient(135deg, #58a6ff 0%, #388bfd 100%);
    box-shadow: 0 4px 14px rgba(56,139,253,0.5);
}
.btn-ghost {
    background: transparent;
    color: #58a6ff; font-size: 12px; font-weight: 600;
    border: 1px solid rgba(56,139,253,0.3);
    border-radius: 8px; padding: 5px 12px;
    transition: all 130ms ease;
}
.btn-ghost:hover { background: rgba(56,139,253,0.1); border-color: #388bfd; }
.btn-danger {
    background: transparent;
    color: #f85149; font-size: 12px; font-weight: 600;
    border: 1px solid rgba(248,81,73,0.3);
    border-radius: 8px; padding: 5px 12px;
    transition: all 130ms ease;
}
.btn-danger:hover { background: rgba(248,81,73,0.1); border-color: #f85149; }

/* ── Search ───────────────────────────────────────────────────────────────── */
.lag-search {
    background: #21262d; color: #c9d1d9;
    border: 1px solid #30363d; border-radius: 10px;
    padding: 6px 12px; font-size: 13px;
    min-height: 36px;
}
.lag-search:focus { border-color: #388bfd; }

/* ── Log table ────────────────────────────────────────────────────────────── */
.log-table-header { background: transparent; }
.log-col-header {
    font-size: 10px; font-weight: 700; color: #6e7681;
    letter-spacing: 0.08em; text-transform: uppercase;
}
.log-row {
    border-bottom: 1px solid #21262d;
    transition: background 120ms ease;
}
.log-row:hover { background: rgba(255,255,255,0.02); }
.log-cell {
    font-family: "IBM Plex Mono", "Fira Code", monospace;
    font-size: 12px; color: #8b949e;
}
.result-granted { color: #3fb950; font-weight: 600; }
.result-denied  { color: #f85149; font-weight: 600; }

/* ── Event type chips ─────────────────────────────────────────────────────── */
.event-chip {
    font-size: 10px; font-weight: 700; letter-spacing: 0.04em;
    border-radius: 6px; padding: 2px 8px;
}
.chip-open    { background: rgba(56,139,253,0.12); color: #58a6ff; }
.chip-session { background: rgba(63,185,80,0.12);  color: #3fb950; }
.chip-protect { background: rgba(163,113,247,0.12);color: #a371f7; }
.chip-viewlog { background: rgba(240,180,41,0.12); color: #f0b429; }
.chip-status  { background: rgba(139,148,158,0.12);color: #8b949e; }
.chip-default { background: #21262d; color: #8b949e; }

/* ── Settings ─────────────────────────────────────────────────────────────── */
.settings-group {
    background: #161b22;
    border: 1px solid #30363d;
    border-radius: 14px;
    overflow: hidden;
}
.settings-group-title {
    font-size: 12px; font-weight: 700; color: #8b949e;
    letter-spacing: 0.06em; text-transform: uppercase;
    margin-bottom: 4px;
}
.settings-row {
    padding: 14px 20px;
    border-bottom: 1px solid #21262d;
    transition: background 120ms ease;
}
.settings-row:last-child { border-bottom: none; }
.settings-row:hover { background: #1c2128; }
.settings-row-icon { font-size: 18px; min-width: 32px; }
.settings-row-title { font-size: 14px; font-weight: 600; color: #c9d1d9; }
.settings-row-desc  { font-size: 12px; color: #6e7681; margin-top: 2px; }

/* ── Dropdown ─────────────────────────────────────────────────────────────── */
.lag-dropdown {
    background: #21262d; color: #c9d1d9;
    border: 1px solid #30363d; border-radius: 10px;
    min-height: 36px; padding: 4px 10px; font-size: 13px;
}

/* ── Spinbutton ───────────────────────────────────────────────────────────── */
.lag-spinbutton {
    background: #21262d; color: #c9d1d9;
    border: 1px solid #30363d; border-radius: 8px;
    font-size: 13px; min-width: 80px;
}

/* ── Switch ───────────────────────────────────────────────────────────────── */
switch { background: #30363d; border-radius: 12px; }
switch:checked { background: #1f6feb; }
switch slider { background: #f0f6fc; border-radius: 10px; }

/* ── Log detail header ────────────────────────────────────────────────────── */
.log-detail-header { background: transparent; }

/* ── Toast notifications ──────────────────────────────────────────────────── */
.toast-label {
    font-size: 13px; font-weight: 600;
    padding: 12px 24px;
    border-radius: 12px;
    box-shadow: 0 4px 20px rgba(0,0,0,0.5);
}
.toast-success .toast-label { background: #1a4a2e; color: #3fb950; border: 1px solid #2ea043; }
.toast-error   .toast-label { background: #4a1a1a; color: #f85149; border: 1px solid #da3633; }
.toast-info    .toast-label { background: #1c2a3e; color: #58a6ff; border: 1px solid #388bfd; }
"""


def main() -> int:
    logging.basicConfig(level=logging.INFO)
    app = VaultApplication()
    return app.run(sys.argv)


if __name__ == "__main__":
    sys.exit(main())
