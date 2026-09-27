# smbforge

A single Python tool that merges `smbmap`-style enumeration with
`smbclient`-style downloading — built for authorized penetration
tests, VAPT engagements, and lab/CTF work.

The one thing it does that neither tool does cleanly out of the box:
**`--recursive` mirrors the remote share/folder structure exactly**
into a local directory tree, instead of dumping everything flat.

> ⚠️ Use only against systems you are explicitly authorized to test.

## Install

No virtual environment needed — installs and runs like `smbmap` or
`smbclient` do, directly against your system Python.

```bash
pip install -r requirements.txt --break-system-packages
chmod +x smbforge.py
```

On distros that don't enforce PEP 668 (the "externally-managed-environment"
restriction), you can drop `--break-system-packages`:

```bash
pip install -r requirements.txt
```

If you'd rather isolate it anyway, a venv still works the normal way
(`python3 -m venv venv && source venv/bin/activate && pip install -r requirements.txt`),
but it isn't required.

## Auth options

Any one of:

```
-p / --password PASSWORD
--hash LMHASH:NTHASH        # or a bare NTHASH (pass-the-hash)
--no-pass                   # null / anonymous session
-k / --kerberos             # ccache (KRB5CCNAME), optionally with --dc-ip / --aes-key
```

If none are given and `--no-pass`/`--kerberos` aren't set, you're
prompted for a password (not echoed, not stored in shell history).

## Usage

### 1. List shares

```bash
python3 smbforge.py -H <target> -d <DOMAIN> -u <user> -p '<password>' --list
```

### 2. List contents of a share (optionally recursive, no download)

```bash
python3 smbforge.py -H <target> -d <DOMAIN> -u <user> -p '<password>' \
    --list -s <share> --path '<subfolder>' -r
```

### 3. Download a single file

```bash
python3 smbforge.py -H <target> -d <DOMAIN> -u <user> -p '<password>' \
    --download -s <share> --path '<folder>\<file>'
```

### 4. Download an entire share, preserving the exact remote structure

```bash
python3 smbforge.py -H <target> -d <DOMAIN> -u <user> -p '<password>' \
    --download -s <share> -r
```

### 5. Download every accessible share, all mirrored the same way

```bash
python3 smbforge.py -H <target> -d <DOMAIN> -u <user> -p '<password>' \
    --download --all -r
```

If any accessible share looks like a printer-driver deployment share
(e.g. `print$`), you'll be asked once whether to skip it — these are
often large with low intel value. Answer non-interactively with
`--skip-print-shares` or `--include-print-shares`.

### 6. Show the structure while downloading

Combine `--list` with `--download` to print each directory/file as
it's discovered, alongside the actual download:

```bash
python3 smbforge.py -H <target> -d <DOMAIN> -u <user> -p '<password>' \
    --list --download --all -r
```

## Output layout

Unless `-o/--output` is given, output goes to:

```
smbforge_<host>/<username>/
├── manifest.jsonl          # one JSON line per file: downloaded / skipped / access_denied / error
├── <share1>/
│   └── ...mirrored remote tree...
└── <share2>/
    └── ...
```

The local tree matches the remote one exactly — folder for folder,
file for file.

Directories you can't read show up in `manifest.jsonl` as
`access_denied` and printed to the terminal — the run keeps going.
Progress prints in place on one line so long collections don't look
stalled; pass `--list` alongside `--download` if you want every
directory/file printed individually instead of a running counter.

Ctrl+C at any point cancels pending downloads cleanly and exits —
whatever finished downloading (and the manifest recording it) stays
on disk, safe to resume later with `--resume`.

## All flags

**Connection**

| Flag | Purpose |
|---|---|
| `-H, --host` | Target IP/hostname (required) |
| `-P, --port` | SMB port, default 445 |
| `-d, --domain` | Domain / workgroup |
| `-u, --username` | Username |
| `-p, --password` | Password (prompted securely if omitted) |
| `--hash` | Pass-the-hash: `LMHASH:NTHASH` or a bare NTHASH |
| `--no-pass` | Null/anonymous session |
| `-k, --kerberos` | Kerberos auth via ccache |
| `--dc-ip` | Domain controller IP, used with `-k` |
| `--aes-key` | AES key for Kerberos |

**What to do**

| Flag | Purpose |
|---|---|
| `--list` | List shares, or contents of `--share`/`--path` — no download. Combine with `--download` to show structure while downloading |
| `-s, --share` | Target one specific share |
| `--path` | Remote path inside the share |
| `--all` | Operate across every accessible share (requires `-r`) |
| `--download` | Actually fetch files |
| `-r, --recursive` | Mirror the exact remote directory tree locally |
| `--skip-print-shares` | With `--all`: skip printer-driver shares without asking |
| `--include-print-shares` | With `--all`: include printer-driver shares without asking |

**Output**

| Flag | Purpose |
|---|---|
| `-o, --output` | Override the auto-generated output directory |
| `--resume` | Skip files already downloaded when local size matches remote |
| `--dry-run` | Walk and log what would download, write nothing |
| `--include` | Glob pattern to include, repeatable |
| `--exclude` | Glob pattern to exclude, repeatable |
| `--threads` | Concurrent download workers, default 4 |

## Notes

- Built on [impacket](https://github.com/fortra/impacket)'s
  `SMBConnection`, so it talks SMB1/2/3 directly — no shelling out to
  `smbclient`/`smbmap` binaries.
- `--all` always requires `-r/--recursive` — a flat "download
  everything from every share" without structure isn't offered on
  purpose, since that's the exact mess this tool exists to avoid.
- `ADMIN$` and `IPC$` are skipped automatically under `--all` (you can
  still target them explicitly with `-s`).
