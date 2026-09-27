#!/usr/bin/env python3
"""
smbforge - SMB enumeration + structure-preserving collection tool.

Combines smbmap-style share/file listing with smbclient-style downloading,
but with a --recursive mode that mirrors the exact remote share/folder tree
locally, a JSONL manifest of what happened, and resume support.

Intended for AUTHORIZED security assessments / CTF / lab environments only.
You must have explicit permission to access the target system.
"""

import argparse
import fnmatch
import getpass
import json
import os
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

try:
    from impacket.smbconnection import SMBConnection, SessionError
    from impacket.smb3structs import FILE_DIRECTORY_FILE
except ImportError:
    print("[!] impacket is required: pip install impacket", file=sys.stderr)
    sys.exit(1)

TOOL_VERSION = "1.0"

# Share types we skip by default when doing --all (printer/IPC/admin-hidden noise).
# We still SHOW them when listing, we just don't try to walk/download them
# unless the user explicitly names them with --share.
NOISY_SHARES = {"IPC$"}


# --------------------------------------------------------------------------- #
# Manifest
# --------------------------------------------------------------------------- #

class Manifest:
    """Append-only JSONL log of every file we touched, plus a running summary."""

    def __init__(self, path):
        self.path = path
        self._fh = open(path, "a", buffering=1, encoding="utf-8")
        self.counts = {"downloaded": 0, "skipped": 0, "access_denied": 0, "error": 0, "listed_dir": 0}

    def log(self, status, share, remote_path, local_path=None, size=None, error=None):
        entry = {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%S"),
            "status": status,
            "share": share,
            "remote_path": remote_path,
            "local_path": local_path,
            "size": size,
            "error": error,
        }
        self._fh.write(json.dumps(entry) + "\n")
        if status in self.counts:
            self.counts[status] += 1

    def close(self):
        self._fh.close()

    def summary(self):
        return (
            f"downloaded={self.counts['downloaded']} "
            f"skipped(resume)={self.counts['skipped']} "
            f"access_denied={self.counts['access_denied']} "
            f"errors={self.counts['error']}"
        )


# --------------------------------------------------------------------------- #
# Connection helpers
# --------------------------------------------------------------------------- #

def parse_hash(hash_str):
    """Accept 'LMHASH:NTHASH' or a bare NTHASH."""
    if ":" in hash_str:
        lm, nt = hash_str.split(":", 1)
    else:
        lm, nt = "aad3b435b51404eeaad3b435b51404ee", hash_str
    return lm, nt


def connect(args):
    conn = SMBConnection(args.host, args.host, sess_port=args.port)

    lmhash = nthash = ""
    if args.hash:
        lmhash, nthash = parse_hash(args.hash)

    if args.kerberos:
        conn.kerberosLogin(
            args.username, args.password or "", args.domain,
            lmhash, nthash, aesKey=args.aes_key, kdcHost=args.dc_ip,
        )
    elif args.no_pass:
        conn.login("", "", args.domain)
    else:
        conn.login(args.username, args.password, args.domain, lmhash, nthash)

    return conn


# --------------------------------------------------------------------------- #
# Share / directory enumeration
# --------------------------------------------------------------------------- #

STYPE_BASE_MASK = 0x0FFFFFFF
STYPE_SPECIAL = 0x80000000
STYPE_NAMES = {0: "Disk", 1: "Printer", 2: "Device", 3: "IPC"}


def decode_share_type(raw):
    base = raw & STYPE_BASE_MASK
    hidden = bool(raw & STYPE_SPECIAL)
    name = STYPE_NAMES.get(base, f"Unknown({base})")
    return f"{name} (hidden)" if hidden else name


def list_shares(conn):
    shares = []
    for s in conn.listShares():
        name = s["shi1_netname"][:-1] if isinstance(s["shi1_netname"], str) else s["shi1_netname"].decode("utf-16-le", errors="ignore").rstrip("\x00")
        remark = s["shi1_remark"]
        if isinstance(remark, bytes):
            remark = remark.decode("utf-16-le", errors="ignore").rstrip("\x00")
        stype = s["shi1_type"]
        shares.append({"name": name, "remark": remark, "type": stype, "type_name": decode_share_type(stype)})
    return shares


def list_dir(conn, share, remote_path):
    """List one directory level. remote_path uses backslashes, '' = root."""
    search = (remote_path.rstrip("\\") + "\\*") if remote_path else "*"
    return conn.listPath(share, search)


def is_remote_dir(conn, share, remote_path):
    """Best-effort check: try listing it as a directory."""
    try:
        list_dir(conn, share, remote_path)
        return True
    except SessionError:
        return False


def walk_remote(conn, share, remote_path=""):
    """
    Yields (kind, path, size) for every entry under remote_path, recursively.
    kind is 'dir' or 'file'. path uses backslashes relative to share root.
    Raises SessionError up if the top-level path itself can't be listed
    (caller decides how to treat that - e.g. access denied vs single file).
    """
    entries = list_dir(conn, share, remote_path)
    for e in entries:
        name = e.get_longname()
        if name in (".", ".."):
            continue
        full = f"{remote_path}\\{name}" if remote_path else name
        if e.is_directory():
            yield ("dir", full, 0)
            try:
                yield from walk_remote(conn, share, full)
            except SessionError as exc:
                yield ("dir_error", full, str(exc))
        else:
            yield ("file", full, e.get_filesize())


# --------------------------------------------------------------------------- #
# Filtering
# --------------------------------------------------------------------------- #

def matches_filters(name, includes, excludes):
    if includes and not any(fnmatch.fnmatch(name, pat) for pat in includes):
        return False
    if excludes and any(fnmatch.fnmatch(name, pat) for pat in excludes):
        return False
    return True


# --------------------------------------------------------------------------- #
# Download
# --------------------------------------------------------------------------- #

def download_one_file(conn_factory, args, share, remote_path, local_path, expected_size, manifest, resume):
    """
    conn_factory: callable returning a *new* SMBConnection, used so threads
    each get their own connection (impacket connections aren't thread-safe).
    """
    if resume and os.path.exists(local_path):
        try:
            local_size = os.path.getsize(local_path)
        except OSError:
            local_size = -1
        if expected_size is not None and local_size == expected_size:
            manifest.log("skipped", share, remote_path, local_path, expected_size)
            return "skipped"

    if args.dry_run:
        manifest.log("downloaded", share, remote_path, local_path, expected_size, error="DRY_RUN")
        return "downloaded"

    os.makedirs(os.path.dirname(local_path), exist_ok=True)
    conn = conn_factory()
    try:
        with open(local_path, "wb") as fh:
            conn.getFile(share, remote_path, fh.write)
        manifest.log("downloaded", share, remote_path, local_path, os.path.getsize(local_path))
        return "downloaded"
    except SessionError as exc:
        msg = str(exc)
        if "ACCESS_DENIED" in msg or "STATUS_ACCESS_DENIED" in msg:
            manifest.log("access_denied", share, remote_path, local_path, error=msg)
            return "access_denied"
        manifest.log("error", share, remote_path, local_path, error=msg)
        return "error"
    except Exception as exc:  # noqa: BLE001 - want to log and keep going
        manifest.log("error", share, remote_path, local_path, error=str(exc))
        return "error"
    finally:
        try:
            conn.close()
        except Exception:
            pass


def collect_share(conn, conn_factory, args, share, remote_root, local_root, manifest, show_structure=False):
    """
    Recursively mirror remote_root (a directory in `share`) into local_root,
    preserving the exact remote structure. remote_root='' = whole share.
    show_structure=True also prints each dir/file as it's discovered (used
    when --list is combined with --download). Otherwise prints a live
    single-line progress counter so long collections don't look stalled.
    """
    print(f"[*] Collecting share '{share}' ({remote_root or '<root>'}) -> {local_root}")
    pool = ThreadPoolExecutor(max_workers=args.threads)
    interrupted = False
    dirs_seen = 0
    files_queued = 0
    counts = {"downloaded": 0, "skipped": 0, "access_denied": 0, "error": 0}

    def progress_line(done):
        total = files_queued
        sys.stdout.write(
            f"\r    [*] {done}/{total} processed "
            f"(downloaded={counts['downloaded']} skipped={counts['skipped']} "
            f"denied={counts['access_denied']} errors={counts['error']})   "
        )
        sys.stdout.flush()

    try:
        walker = walk_remote(conn, share, remote_root)
        futures = []
        for kind, path, size in walker:
            if kind == "dir_error":
                manifest.log("access_denied", share, path, error=str(size))
                print(f"    [!] ACCESS_DENIED (dir): {share}\\{path}")
                continue
            if kind == "dir":
                dirs_seen += 1
                if show_structure:
                    print(f"    DIR   {share}\\{path}")
                continue
            # kind == 'file'
            name = os.path.basename(path.replace("\\", "/"))
            if not matches_filters(name, args.include, args.exclude):
                continue
            if show_structure:
                print(f"    FILE  {share}\\{path}  ({size} bytes)")
            else:
                sys.stdout.write(f"\r    [*] scanning: {dirs_seen} dir(s), {files_queued} file(s) found...   ")
                sys.stdout.flush()
            rel = path.replace("\\", os.sep)
            # strip the remote_root prefix so local tree starts at share root
            local_path = os.path.join(local_root, rel)
            futures.append(pool.submit(
                download_one_file, conn_factory, args, share, path, local_path, size, manifest, args.resume
            ))
            files_queued += 1

        if not show_structure and files_queued:
            print()  # move off the scanning line

        done = 0
        for f in as_completed(futures):
            status = f.result()
            done += 1
            if status in counts:
                counts[status] += 1
            if not show_structure:
                progress_line(done)
        if not show_structure and files_queued:
            print()  # move off the progress line
    except KeyboardInterrupt:
        interrupted = True
        if not show_structure and files_queued:
            print()
        print(f"    [!] Interrupted — cancelling pending downloads in '{share}'...", file=sys.stderr)
        raise
    except SessionError as exc:
        msg = str(exc)
        if "ACCESS_DENIED" in msg:
            manifest.log("access_denied", share, remote_root, error=msg)
            print(f"    [!] ACCESS_DENIED: {share}\\{remote_root}")
        else:
            manifest.log("error", share, remote_root, error=msg)
            print(f"    [!] ERROR listing {share}\\{remote_root}: {msg}")
    finally:
        pool.shutdown(wait=not interrupted, cancel_futures=interrupted)


# --------------------------------------------------------------------------- #
# Listing (read-only, no download)
# --------------------------------------------------------------------------- #

def print_shares(shares):
    name_w = max(len("Share"), max((len(s["name"]) for s in shares), default=0)) + 2
    type_w = max(len("Type"), max((len(s["type_name"]) for s in shares), default=0)) + 2

    header = f"{'Share':<{name_w}}{'Type':<{type_w}}Remark"
    print(header)
    print("-" * (name_w + type_w + max(len("Remark"), 20)))
    for s in sorted(shares, key=lambda x: x["name"].lower()):
        remark = s["remark"] or "-"
        print(f"{s['name']:<{name_w}}{s['type_name']:<{type_w}}{remark}")
    print(f"\n{len(shares)} share(s) found.")


def print_dir_listing(conn, share, remote_path, recursive):
    if recursive:
        for kind, path, size in walk_remote(conn, share, remote_path):
            if kind == "dir":
                print(f"  DIR   {share}\\{path}")
            elif kind == "file":
                print(f"  FILE  {share}\\{path}  ({size} bytes)")
            elif kind == "dir_error":
                print(f"  !!!   {share}\\{path}  ACCESS_DENIED")
    else:
        try:
            entries = list_dir(conn, share, remote_path)
        except SessionError as exc:
            print(f"  !!! ACCESS_DENIED or error listing {share}\\{remote_path}: {exc}")
            return
        for e in entries:
            name = e.get_longname()
            if name in (".", ".."):
                continue
            tag = "DIR " if e.is_directory() else "FILE"
            size = "" if e.is_directory() else f"  ({e.get_filesize()} bytes)"
            print(f"  {tag}  {name}{size}")


# --------------------------------------------------------------------------- #
# Main
# --------------------------------------------------------------------------- #

def build_output_root(args):
    if args.output:
        return args.output
    target = args.host.replace("/", "_")
    user = args.username or "anonymous"
    return os.path.join(f"smbforge_{target}", user)


def validate_args(args):
    """
    Pure flag-combination checks that don't need a connection. Runs before
    anything touches disk or the network, so a bad combo fails with nothing
    created.
    """
    if not args.download and not args.list:
        return "Specify --list to browse, or --download (with --share/--path or --all) to fetch files."
    if args.download:
        if args.all and not args.recursive:
            return "--all requires --recursive (whole-share mirroring)."
        if not args.all and not args.share:
            return "--download requires --share (with optional --path) or --all --recursive."
    return None


def main():
    p = argparse.ArgumentParser(
        description="smbforge - SMB enumeration + structure-preserving collection tool. "
                    "Authorized security testing use only.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )

    conn_grp = p.add_argument_group("connection")
    conn_grp.add_argument("-H", "--host", required=True, help="Target host / IP")
    conn_grp.add_argument("-P", "--port", type=int, default=445)
    conn_grp.add_argument("-d", "--domain", default="", help="Domain / workgroup, e.g. CORP")
    conn_grp.add_argument("-u", "--username", default="")
    auth = conn_grp.add_mutually_exclusive_group()
    auth.add_argument("-p", "--password", default=None)
    auth.add_argument("--hash", help="Pass-the-hash: LMHASH:NTHASH or bare NTHASH")
    auth.add_argument("--no-pass", action="store_true", help="Null / anonymous session")
    conn_grp.add_argument("-k", "--kerberos", action="store_true", help="Use Kerberos (ccache)")
    conn_grp.add_argument("--dc-ip", help="Domain controller IP (for Kerberos)")
    conn_grp.add_argument("--aes-key", help="AES key for Kerberos")

    action_grp = p.add_argument_group("what to do")
    action_grp.add_argument("--list", action="store_true",
                             help="List shares (or contents of --share/--path) instead of downloading")
    action_grp.add_argument("-s", "--share", help="Target a specific share")
    action_grp.add_argument("--path", default="", help=r"Remote path within the share, e.g. IT\Logs")
    action_grp.add_argument("--all", action="store_true", help="Operate across every accessible share")
    action_grp.add_argument("--download", action="store_true", help="Download instead of just listing")
    action_grp.add_argument("-r", "--recursive", action="store_true",
                             help="Mirror the exact remote directory structure locally")
    action_grp.add_argument("--skip-print-shares", action="store_true",
                             help="With --all: skip printer-driver shares (e.g. print$) without asking")
    action_grp.add_argument("--include-print-shares", action="store_true",
                             help="With --all: include printer-driver shares without asking")

    out_grp = p.add_argument_group("output")
    out_grp.add_argument("-o", "--output", help="Override the auto-generated output directory")
    out_grp.add_argument("--resume", action="store_true", help="Skip files already downloaded (size match)")
    out_grp.add_argument("--dry-run", action="store_true", help="Show what would happen, download nothing")
    out_grp.add_argument("--include", action="append", default=[], help="Glob pattern to include (repeatable)")
    out_grp.add_argument("--exclude", action="append", default=[], help="Glob pattern to exclude (repeatable)")
    out_grp.add_argument("--threads", type=int, default=4)
    out_grp.add_argument("-v", "--verbose", action="store_true")

    args = p.parse_args()

    validation_error = validate_args(args)
    if validation_error:
        print(f"[!] {validation_error}", file=sys.stderr)
        sys.exit(2)

    if not args.password and not args.hash and not args.no_pass and not args.kerberos:
        args.password = getpass.getpass(f"Password for {args.domain + chr(92) if args.domain else ''}{args.username}: ")

    conn_factory = lambda: connect(args)

    try:
        conn = connect(args)
    except Exception as exc:
        print(f"[!] Connection/auth failed: {exc}", file=sys.stderr)
        sys.exit(1)

    print(f"[+] Authenticated to {args.host} as "
          f"{(args.domain + chr(92)) if args.domain else ''}{args.username or '(anonymous)'}")

    # ---- pure listing mode -------------------------------------------------
    if args.list and not args.download:
        if args.share:
            print(f"[*] Listing {'recursively ' if args.recursive else ''}{args.share}\\{args.path}")
            print_dir_listing(conn, args.share, args.path, args.recursive)
        else:
            try:
                shares = list_shares(conn)
            except SessionError:
                reason = "Anonymous" if args.no_pass else "This session's"
                print(f"[!] {reason} share enumeration denied — try with credentials "
                      "(-u/-p, --hash, or -k).", file=sys.stderr)
                conn.close()
                sys.exit(1)
            print_shares(shares)
        conn.close()
        return

    # ---- download mode ------------------------------------------------------
    # Pre-flight access check happens BEFORE anything is created on disk.
    # validate_args() already ruled out bad flag combos; this catches a
    # runtime failure (wrong creds, no access) for the combo actually given.
    if args.all:
        try:
            shares = list_shares(conn)
        except SessionError:
            reason = "Anonymous" if args.no_pass else "This session's"
            print(f"[!] {reason} share enumeration denied — try with credentials "
                  "(-u/-p, --hash, or -k).", file=sys.stderr)
            conn.close()
            sys.exit(1)

        skip_print = args.skip_print_shares
        printerish = [s["name"] for s in shares if s["name"].lower() == "print$"
                      or s.get("type_name", "").lower().startswith("printer")]
        if printerish and not args.skip_print_shares and not args.include_print_shares:
            try:
                resp = input(
                    f"[?] Skip printer-driver share(s) ({', '.join(printerish)})? "
                    "These are usually large with low intel value. [Y/n]: "
                ).strip().lower()
            except EOFError:
                resp = ""
            skip_print = resp in ("", "y", "yes")
    else:  # args.share is guaranteed here by validate_args
        try:
            list_dir(conn, args.share, "")
        except SessionError as exc:
            msg = str(exc)
            reason = "Access denied" if "ACCESS_DENIED" in msg else f"Error: {exc}"
            print(f"[!] {reason} accessing share '{args.share}' — try different credentials.",
                  file=sys.stderr)
            conn.close()
            sys.exit(1)

    output_root = build_output_root(args)
    os.makedirs(output_root, exist_ok=True)
    manifest_path = os.path.join(output_root, "manifest.jsonl")
    manifest = Manifest(manifest_path)
    print(f"[+] Output root : {output_root}")
    print(f"[+] Manifest    : {manifest_path}")
    if args.dry_run:
        print("[*] DRY RUN - no files will actually be written")

    try:
        if args.all:
            for s in shares:
                name = s["name"]
                if name in NOISY_SHARES or name.endswith("$") and name.upper() in ("ADMIN$", "IPC$"):
                    print(f"[*] Skipping administrative share {name}")
                    continue
                if skip_print and name in printerish:
                    print(f"[*] Skipping printer-driver share {name}")
                    continue
                local_root = os.path.join(output_root, name)
                collect_share(conn, conn_factory, args, name, "", local_root, manifest, show_structure=args.list)

        else:
            if args.path and not args.recursive:
                # try as a single file first
                if is_remote_dir(conn, args.share, args.path):
                    print("[!] That path is a directory. Add --recursive to mirror it, "
                          "or point --path at a specific file.", file=sys.stderr)
                    sys.exit(2)
                name = os.path.basename(args.path.replace("\\", "/"))
                local_path = os.path.join(output_root, args.share, args.path.replace("\\", os.sep))
                try:
                    size = None
                    for e in list_dir(conn, args.share, os.path.dirname(args.path)):
                        if e.get_longname() == name:
                            size = e.get_filesize()
                            break
                except SessionError:
                    size = None
                if args.list:
                    print(f"    FILE  {args.share}\\{args.path}" + (f"  ({size} bytes)" if size is not None else ""))
                status = download_one_file(conn_factory, args, args.share, args.path, local_path, size, manifest, args.resume)
                print(f"[{status}] {args.share}\\{args.path}")
            else:
                local_root = os.path.join(output_root, args.share)
                collect_share(conn, conn_factory, args, args.share, args.path, local_root, manifest, show_structure=args.list)
    finally:
        conn.close()
        manifest.close()
        print(f"[+] Done: {manifest.summary()}")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] Interrupted by user — partial results (if any) are in the manifest.", file=sys.stderr)
        sys.exit(130)
