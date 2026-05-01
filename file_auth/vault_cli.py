#!/usr/bin/env python3
"""
LinuxAuthGuard - Vault CLI
Add, remove, list, and manage password-protected files and folders.

Usage:
  vault_cli.py add    <path> [--recursive] [--totp]
  vault_cli.py remove <path>
  vault_cli.py list
  vault_cli.py passwd <path>
  vault_cli.py status <path>
  vault_cli.py log    <path> [--limit N]
"""

from __future__ import annotations

import argparse
import getpass
import os
import sys
import stat
from pathlib import Path
from typing import Optional

# Ensure we can import sibling modules
sys.path.insert(0, str(Path(__file__).parent))

from vault_db import VaultDB, ProtectedItem


def _require_root_or_owner(path: str) -> None:
    """Exit if caller is neither root nor owner of the path."""
    if os.geteuid() == 0:
        return
    try:
        item_stat = os.stat(path)
        if item_stat.st_uid != os.getuid():
            print(f"Error: you do not own '{path}' and are not root.", file=sys.stderr)
            sys.exit(1)
    except FileNotFoundError:
        pass  # File doesn't exist yet — that's OK for add


def _read_password(prompt: str = "Password: ", confirm: bool = False) -> str:
    """Read a password from the terminal with optional confirmation."""
    while True:
        pwd = getpass.getpass(prompt)
        if not pwd:
            print("Error: password cannot be empty.", file=sys.stderr)
            continue
        if len(pwd) > 512:
            print("Error: password too long (max 512 characters).", file=sys.stderr)
            continue
        if confirm:
            pwd2 = getpass.getpass("Confirm password: ")
            if pwd != pwd2:
                print("Passwords do not match. Try again.", file=sys.stderr)
                continue
        return pwd


def cmd_add(args: argparse.Namespace, db: VaultDB) -> int:
    """Add protection to a file or folder."""
    path = str(Path(args.path).resolve())

    if not Path(path).exists():
        print(f"Error: path does not exist: {path}", file=sys.stderr)
        return 1

    _require_root_or_owner(path)

    if db.get_item(path) is not None:
        print(f"Error: '{path}' is already protected.", file=sys.stderr)
        print("Use 'vault_cli.py passwd' to change its password.", file=sys.stderr)
        return 1

    is_dir = Path(path).is_dir()
    recursive = args.recursive if hasattr(args, "recursive") else True
    totp = args.totp if hasattr(args, "totp") else False

    print(f"Adding protection to: {path}")
    if is_dir:
        print(f"  Mode: {'recursive' if recursive else 'shallow'} directory protection")
    if totp:
        print("  TOTP: required")

    password = _read_password("New protection password: ", confirm=True)

    owner_uid = os.stat(path).st_uid

    try:
        db.add_item(
            path=path,
            password=password,
            owner_uid=owner_uid,
            recursive=recursive,
            totp_required=totp,
        )
    except Exception as e:
        print(f"Error: failed to add protection: {e}", file=sys.stderr)
        return 1
    finally:
        # Zero password from memory best-effort
        del password

    print(f"✓ Protection added to: {path}")
    if is_dir and recursive:
        print("  All files and subdirectories are now protected.")
    return 0


def cmd_remove(args: argparse.Namespace, db: VaultDB) -> int:
    """Remove protection from a file or folder."""
    path = str(Path(args.path).resolve())

    item = db.get_item(path)
    if item is None:
        print(f"Error: '{path}' is not protected.", file=sys.stderr)
        return 1

    _require_root_or_owner(path)

    print(f"Removing protection from: {path}")
    password = _read_password("Current protection password: ", confirm=False)

    if not db.verify_password(path, password):
        print("Error: incorrect password.", file=sys.stderr)
        del password
        return 1

    del password

    try:
        db.remove_item(path)
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1

    print(f"✓ Protection removed from: {path}")
    return 0


def cmd_list(args: argparse.Namespace, db: VaultDB) -> int:
    """List all protected items."""
    items = db.list_items()
    if not items:
        print("No protected items found.")
        return 0

    print(f"{'PATH':<55} {'TYPE':<6} {'TOTP':<5} {'OWNER':<8} {'PROTECTED SINCE'}")
    print("─" * 100)

    import pwd
    from datetime import datetime

    for item in items:
        try:
            owner_name = pwd.getpwuid(item.owner_uid).pw_name
        except KeyError:
            owner_name = str(item.owner_uid)

        path = Path(item.path)
        item_type = "dir" if path.is_dir() else "file"
        created = datetime.fromtimestamp(item.created_at).strftime("%Y-%m-%d %H:%M")
        totp = "yes" if item.totp_required else "no"
        mode = "R" if item.recursive else "S"  # Recursive / Shallow

        # Truncate long paths
        display_path = str(item.path)
        if len(display_path) > 54:
            display_path = "…" + display_path[-53:]

        print(f"{display_path:<55} {item_type+'/'+mode:<6} {totp:<5} {owner_name:<8} {created}")

    print(f"\nTotal: {len(items)} protected item(s)")
    return 0


def cmd_passwd(args: argparse.Namespace, db: VaultDB) -> int:
    """Change the password for a protected item."""
    path = str(Path(args.path).resolve())

    item = db.get_item(path)
    if item is None:
        print(f"Error: '{path}' is not protected.", file=sys.stderr)
        return 1

    _require_root_or_owner(path)

    old_password = _read_password("Current password: ", confirm=False)
    if not db.verify_password(path, old_password):
        print("Error: incorrect current password.", file=sys.stderr)
        del old_password
        return 1
    del old_password

    new_password = _read_password("New password: ", confirm=True)

    try:
        db.update_password(path, new_password)
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        del new_password
        return 1

    del new_password
    print(f"✓ Password updated for: {path}")
    return 0


def cmd_status(args: argparse.Namespace, db: VaultDB) -> int:
    """Show protection status of a path."""
    path = str(Path(args.path).resolve())

    item = db.get_item(path)
    if item is None:
        # Check if it falls under a protected parent
        parent = db.get_parent_item(path)
        if parent is None:
            print(f"Not protected: {path}")
            return 0
        print(f"Protected via parent: {parent.path}")
        item = parent

    from datetime import datetime
    import pwd

    try:
        owner_name = pwd.getpwuid(item.owner_uid).pw_name
    except KeyError:
        owner_name = str(item.owner_uid)

    print(f"Protected path:  {item.path}")
    print(f"Owner:           {owner_name} (uid={item.owner_uid})")
    print(f"Type:            {'Directory' if Path(item.path).is_dir() else 'File'}")
    print(f"Recursive:       {'Yes' if item.recursive else 'No (shallow)'}")
    print(f"TOTP required:   {'Yes' if item.totp_required else 'No'}")
    print(f"Protected since: {datetime.fromtimestamp(item.created_at)}")
    print(f"Last updated:    {datetime.fromtimestamp(item.updated_at)}")

    # Access stats
    stats = db.get_access_stats(item.path)
    print(f"Total accesses:  {stats.get('total', 0)}")
    print(f"Granted:         {stats.get('granted', 0)}")
    print(f"Denied:          {stats.get('denied', 0)}")
    # Record that this user queried the status (audit trail)
    db.log_access(item.path, os.getuid(), "status", True)
    return 0


def cmd_log(args: argparse.Namespace, db: VaultDB) -> int:
    """Show access log for a protected path."""
    path = str(Path(args.path).resolve())
    limit = getattr(args, "limit", 20) or 20

    entries = db.get_access_log(path, limit=limit)
    if not entries:
        print(f"No access log entries for: {path}")
        return 0

    from datetime import datetime
    import pwd

    print(f"Access log for: {path}  (last {limit} entries)")
    print(f"{'TIMESTAMP':<22} {'USER':<12} {'TYPE':<10} {'RESULT'}")
    print("─" * 60)

    for entry in entries:
        try:
            user = pwd.getpwuid(entry["accessed_by"]).pw_name
        except KeyError:
            user = str(entry["accessed_by"])
        ts = datetime.fromtimestamp(entry["timestamp"]).strftime("%Y-%m-%d %H:%M:%S")
        result = "✓ granted" if entry["granted"] else "✗ denied"
        print(f"{ts:<22} {user:<12} {entry['access_type']:<10} {result}")

    # Record that this user viewed the log
    db.log_access(path, os.getuid(), "view_log", True)
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(
        prog="vault_cli",
        description="LinuxAuthGuard file/folder protection manager",
    )
    parser.add_argument(
        "--db",
        default="/var/lib/linuxauthguard/vault.db",
        help="Path to vault database",
    )

    sub = parser.add_subparsers(dest="command", required=True)

    # add
    p_add = sub.add_parser("add", help="Protect a file or folder")
    p_add.add_argument("path", help="File or directory to protect")
    p_add.add_argument(
        "--no-recursive", dest="recursive", action="store_false", default=True,
        help="Shallow (non-recursive) folder protection"
    )
    p_add.add_argument(
        "--totp", action="store_true", default=False,
        help="Require TOTP in addition to password"
    )

    # remove
    p_remove = sub.add_parser("remove", help="Remove protection")
    p_remove.add_argument("path")

    # list
    sub.add_parser("list", help="List all protected items")

    # passwd
    p_passwd = sub.add_parser("passwd", help="Change protection password")
    p_passwd.add_argument("path")

    # status
    p_status = sub.add_parser("status", help="Show protection status")
    p_status.add_argument("path")

    # log
    p_log = sub.add_parser("log", help="Show access log")
    p_log.add_argument("path")
    p_log.add_argument("--limit", type=int, default=20, help="Max entries to show")

    args = parser.parse_args()

    # Ensure DB directory exists
    db_path = Path(args.db)
    db_path.parent.mkdir(parents=True, exist_ok=True)

    db = VaultDB(str(db_path))

    dispatch = {
        "add":    cmd_add,
        "remove": cmd_remove,
        "list":   cmd_list,
        "passwd": cmd_passwd,
        "status": cmd_status,
        "log":    cmd_log,
    }

    handler = dispatch.get(args.command)
    if handler is None:
        parser.print_help()
        return 1

    try:
        return handler(args, db)
    except KeyboardInterrupt:
        print("\nAborted.")
        return 130
    except PermissionError as e:
        print(f"Permission denied: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
