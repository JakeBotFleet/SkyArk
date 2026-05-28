#!/usr/bin/env python3
"""
AWSHostRecon (Linux/Python port of SkyArk's AWSHostRecon.ps1)

Performs host reconnaissance for AWS-related artefacts on a Linux box:

  * AWS-related environment variables (AWS_*, BOTO_CONFIG, etc.)
  * AWS credentials / config files under every /home/* and /root
  * Parsed [profile] / aws_access_key_id / aws_secret_access_key from those files
  * AWS-fingerprint URLs in Firefox, Chrome, Chromium history & bookmarks
  * Directories and files whose name contains 'aws' under home dirs, /tmp, /opt

Outputs a structured JSON report alongside human-readable stdout.

Usage:
    python3 awshostrecon.py [--output ./recon.json] [--quick]
"""
from __future__ import annotations

import argparse
import configparser
import json
import os
import re
import sqlite3
import sys
import tempfile
import time
from pathlib import Path


BANNER = r"""
---------------------------------------------------------------------------
      __          _______ _    _           _   _____
     /\ \        / / ____| |  | |         | | |  __ \
    /  \ \  /\  / / (___ | |__| | ___  ___| |_| |__) |___  ___ ___  _ __
   / /\ \ \/  \/ / \___ \|  __  |/ _ \/ __| __|  _  // _ \/ __/ _ \| '_ \
  / ____ \  /\  /  ____) | |  | | (_) \__ \ |_| | \ \  __/ (_| (_) | | | |
 /_/    \_\/  \/  |_____/|_|  |_|\___/|___/\__|_|  \_\___|\___\___/|_| |_|
                       AWSHostRecon (Linux/Python)
---------------------------------------------------------------------------
"""

AWS_ENV_VARS = {
    "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN",
    "AWS_PROFILE", "AWS_DEFAULT_PROFILE", "AWS_REGION", "AWS_DEFAULT_REGION",
    "AWS_CONFIG_FILE", "AWS_SHARED_CREDENTIALS_FILE",
    "AWS_CREDENTIAL_FILE", "BOTO_CONFIG",
    "AWS_ROLE_ARN", "AWS_WEB_IDENTITY_TOKEN_FILE",
    "AWS_ENDPOINT_URL", "AWS_CONTAINER_CREDENTIALS_FULL_URI",
    "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI",
}

AWS_URL_RE = re.compile(
    rb"https?://[\w.\-]*(aws|amazonaws|amazon|s3|console\.aws)[\w./\-?=&%]*",
    re.IGNORECASE,
)


def scan_env_vars() -> dict:
    print("[+] Scanning environment variables")
    found = {}
    for k, v in os.environ.items():
        if k in AWS_ENV_VARS or k.startswith("AWS_"):
            # redact secret material in stdout but keep in JSON
            masked = v
            if any(s in k for s in ("SECRET", "TOKEN", "ACCESS_KEY")):
                masked = (v[:6] + "..." + v[-4:]) if len(v) > 12 else "***"
            print(f"    {k} = {masked}")
            found[k] = v
    if not found:
        print("    [-] no AWS-related env vars set")
    return found


def _home_dirs() -> list[Path]:
    homes = []
    for base in ("/root", "/home"):
        p = Path(base)
        try:
            if not p.exists():
                continue
        except PermissionError:
            continue
        if p == Path("/root"):
            homes.append(p)
        else:
            try:
                for child in p.iterdir():
                    try:
                        if child.is_dir():
                            homes.append(child)
                    except PermissionError:
                        continue
            except PermissionError:
                continue
    return homes


def scan_credentials_files() -> dict:
    print("\n[+] Scanning AWS credentials / config files")
    found: dict[str, dict] = {}

    candidates: list[Path] = []
    for home in _home_dirs():
        for sub in (".aws/credentials", ".aws/config"):
            candidates.append(home / sub)
    # plus any explicit env overrides
    for var in ("AWS_SHARED_CREDENTIALS_FILE", "AWS_CONFIG_FILE", "AWS_CREDENTIAL_FILE", "BOTO_CONFIG"):
        if os.environ.get(var):
            candidates.append(Path(os.environ[var]))

    for path in candidates:
        try:
            if not path.is_file():
                continue
        except PermissionError:
            print(f"    [!] {path}: permission denied")
            continue
        cp = configparser.ConfigParser()
        try:
            cp.read(path)
        except (configparser.Error, OSError) as e:
            print(f"    [!] {path}: {e}")
            continue
        profiles = {}
        for section in cp.sections():
            keys = {}
            for k in ("aws_access_key_id", "aws_secret_access_key", "aws_session_token", "region", "role_arn"):
                if cp.has_option(section, k):
                    val = cp.get(section, k)
                    if k in ("aws_secret_access_key", "aws_session_token") and len(val) > 12:
                        keys[k] = val[:6] + "..." + val[-4:]
                    else:
                        keys[k] = val
            profiles[section] = keys
        found[str(path)] = profiles
        print(f"    {path}  profiles={list(profiles.keys())}")

    if not found:
        print("    [-] no AWS credentials files found")
    return found


# --------------- Browser scanners --------------------------------------------
def _safe_copy_sqlite(src: Path) -> Path | None:
    """Browsers lock their DBs - copy to tmp before reading."""
    try:
        tf = tempfile.NamedTemporaryFile(prefix="recon-", suffix=".sqlite", delete=False)
        tf.close()
        tf_path = Path(tf.name)
        tf_path.write_bytes(src.read_bytes())
        return tf_path
    except OSError:
        return None


def _grep_urls(text: bytes) -> list[str]:
    return sorted({m.decode("utf-8", "ignore") for m in AWS_URL_RE.findall(text)})


def scan_browsers() -> dict:
    print("\n[+] Scanning browser data for AWS URLs")
    findings: dict[str, list[str]] = {}

    def _isdir(p: Path) -> bool:
        try:
            return p.is_dir()
        except PermissionError:
            return False

    def _isfile(p: Path) -> bool:
        try:
            return p.is_file()
        except PermissionError:
            return False

    for home in _home_dirs():
        # Firefox
        ff_root = home / ".mozilla/firefox"
        if _isdir(ff_root):
            try:
                ff_profs = list(ff_root.iterdir())
            except PermissionError:
                ff_profs = []
            for prof in ff_profs:
                places = prof / "places.sqlite"
                if not _isfile(places):
                    continue
                tmp = _safe_copy_sqlite(places)
                if tmp is None:
                    continue
                try:
                    con = sqlite3.connect(f"file:{tmp}?mode=ro", uri=True)
                    cur = con.cursor()
                    for row in cur.execute("SELECT url FROM moz_places"):
                        url = row[0] or ""
                        if "aws" in url.lower() or "amazonaws" in url.lower():
                            findings.setdefault(f"firefox:{home.name}", []).append(url)
                    con.close()
                except sqlite3.Error:
                    pass
                finally:
                    try:
                        tmp.unlink()
                    except OSError:
                        pass

        # Chrome / Chromium
        for browser, sub in (("chrome", ".config/google-chrome"),
                             ("chromium", ".config/chromium"),
                             ("edge", ".config/microsoft-edge")):
            root = home / sub
            if not _isdir(root):
                continue
            try:
                profs = list(root.iterdir())
            except PermissionError:
                continue
            for prof in profs:
                if not _isdir(prof):
                    continue
                for fname in ("History", "Bookmarks"):
                    f = prof / fname
                    if not _isfile(f):
                        continue
                    if fname == "Bookmarks":
                        # JSON, just regex it
                        urls = _grep_urls(f.read_bytes())
                        if urls:
                            findings.setdefault(f"{browser}:{home.name}", []).extend(urls)
                        continue
                    tmp = _safe_copy_sqlite(f)
                    if tmp is None:
                        continue
                    try:
                        con = sqlite3.connect(f"file:{tmp}?mode=ro", uri=True)
                        cur = con.cursor()
                        for row in cur.execute("SELECT url FROM urls"):
                            url = row[0] or ""
                            if "aws" in url.lower() or "amazonaws" in url.lower():
                                findings.setdefault(f"{browser}:{home.name}", []).append(url)
                        con.close()
                    except sqlite3.Error:
                        pass
                    finally:
                        try:
                            tmp.unlink()
                        except OSError:
                            pass

    for k, urls in findings.items():
        urls_unique = sorted(set(urls))
        findings[k] = urls_unique
        print(f"    {k}: {len(urls_unique)} unique AWS URLs")
        for u in urls_unique[:5]:
            print(f"        {u}")
    if not findings:
        print("    [-] no AWS URLs in browser data")
    return findings


def scan_aws_paths(quick: bool) -> dict:
    print("\n[+] Scanning for files/folders containing 'aws'")
    folders: list[str] = []
    files: list[str] = []
    bases = _home_dirs() + [Path("/tmp"), Path("/opt")]

    # cap walk depth so we don't explode on big trees in --quick
    max_depth = 4 if quick else 8

    for base in bases:
        if not base.is_dir():
            continue
        base_depth = len(base.parts)
        for root, dirs, fs in os.walk(base, followlinks=False):
            depth = len(Path(root).parts) - base_depth
            if depth > max_depth:
                dirs[:] = []
                continue
            # skip noisy or recursive trees
            dirs[:] = [d for d in dirs if d not in (".git", "node_modules", ".cache",
                                                     "site-packages", "__pycache__")]
            for d in dirs:
                if "aws" in d.lower():
                    folders.append(str(Path(root) / d))
            for f in fs:
                if "aws" in f.lower():
                    files.append(str(Path(root) / f))

    folders = sorted(set(folders))
    files = sorted(set(files))
    print(f"    folders: {len(folders)}")
    for x in folders[:10]:
        print(f"        {x}")
    if len(folders) > 10:
        print(f"        ... +{len(folders)-10} more")
    print(f"    files: {len(files)}")
    for x in files[:10]:
        print(f"        {x}")
    if len(files) > 10:
        print(f"        ... +{len(files)-10} more")
    return {"folders": folders, "files": files}


# ---------------------------------------------------------------------------
def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--output", default=None, help="Write JSON report to this path")
    p.add_argument("--quick", action="store_true", help="Limit filesystem-walk depth")
    p.add_argument("--skip-paths", action="store_true", help="Skip filesystem walk entirely")
    args = p.parse_args(argv)

    print(BANNER)
    start = time.time()
    report = {
        "scanned_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "env_vars": scan_env_vars(),
        "credential_files": scan_credentials_files(),
        "browser_urls": scan_browsers(),
    }
    if not args.skip_paths:
        report["paths"] = scan_aws_paths(args.quick)
    elapsed = time.time() - start

    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2)
        print(f"\n[+] JSON report written to {args.output}")
    print(f"[+] Scan finished in {elapsed:.1f}s")
    return 0


if __name__ == "__main__":
    sys.exit(main())
