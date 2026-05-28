#!/usr/bin/env python3
"""
AWStrace (Linux/Python port of SkyArk's AWStrace.ps1)

Downloads CloudTrail log files from S3, decompresses them, parses every
event, and emits:
  * Full Analyzed Logs.csv     - every event with normalized fields
  * Sensitive IAM Actions.csv  - prioritized subset (IAM admin actions)

Geolocation/WhoIs IP enrichment from the original PS module is intentionally
omitted (relied on free public endpoints that are flaky / privacy concerns).

Usage:
    python3 awstrace.py download \
        --bucket my-trail-bucket --prefix AWSLogs/123456789012/CloudTrail/us-west-2/2026/05/25 \
        --local-path ./logs
    python3 awstrace.py analyze --local-path ./logs

The two phases can also be chained:
    python3 awstrace.py run --bucket ... --prefix ... --local-path ./logs
"""
from __future__ import annotations

import argparse
import csv
import datetime as _dt
import gzip
import json
import os
import sys
from typing import Iterable

try:
    import boto3
    from botocore.exceptions import BotoCoreError, ClientError
except ImportError:
    sys.stderr.write("[!] boto3 required: pip install boto3\n")
    sys.exit(1)


BANNER = r"""
----------------------------------------------------
      __          _______ _
     /\ \        / / ____| |
    /  \ \  /\  / / (___ | |_ _ __ __ _  ___ ___
   / /\ \ \/  \/ / \___ \| __| '__/ _` |/ __/ _ \
  / ____ \  /\  /  ____) | |_| | | (_| | (_|  __/
 /_/    \_\/  \/  |_____/ \__|_|  \__,_|\___\___|
----------------------------------------------------
   AWStrace (Linux/Python) - CloudTrail analysis
----------------------------------------------------
"""


SENSITIVE_ACTIONS = {
    "AddUserToGroup",
    "CreateAccessKey",
    "CreateLoginProfile",
    "UpdateLoginProfile",
    "AttachUserPolicy", "AttachGroupPolicy", "AttachRolePolicy",
    "PutUserPolicy", "PutGroupPolicy", "PutRolePolicy",
    "CreatePolicy",
    "CreatePolicyVersion", "SetDefaultPolicyVersion",
    "PassRole", "CreateInstanceProfile", "AddRoleToInstanceProfile",
    "UpdateAssumeRolePolicy",
}


# ---------------------------------------------------------------------------
# S3 download
# ---------------------------------------------------------------------------
def download_trail(bucket: str, prefix: str, local_path: str, region: str,
                   profile: str | None) -> int:
    session_kw = {"region_name": region}
    if profile:
        session_kw["profile_name"] = profile
    s3 = boto3.session.Session(**session_kw).client("s3")

    zipped_dir = os.path.join(local_path, "ZippedLogs")
    os.makedirs(zipped_dir, exist_ok=True)

    print(f"[+] Listing s3://{bucket}/{prefix}")
    paginator = s3.get_paginator("list_objects_v2")
    keys: list[str] = []
    for page in paginator.paginate(Bucket=bucket, Prefix=prefix):
        for o in page.get("Contents", []):
            if o["Key"].endswith(".gz"):
                keys.append(o["Key"])

    if not keys:
        print("[-] No .gz CloudTrail objects found under that prefix")
        return 0

    print(f"[+] Downloading {len(keys)} objects -> {zipped_dir}")
    for i, key in enumerate(keys, 1):
        out = os.path.join(zipped_dir, os.path.basename(key))
        try:
            s3.download_file(bucket, key, out)
        except (BotoCoreError, ClientError) as e:
            print(f"    [!] {key}: {e}")
            continue
        if i % max(1, len(keys) // 10) == 0:
            pct = int(i / len(keys) * 100)
            print(f"    {i}/{len(keys)} ({pct}%)")
    return len(keys)


# ---------------------------------------------------------------------------
# Unzip
# ---------------------------------------------------------------------------
def unzip_files(local_path: str) -> int:
    zipped = os.path.join(local_path, "ZippedLogs")
    unzipped = os.path.join(local_path, "UnzippedLogs")
    os.makedirs(unzipped, exist_ok=True)

    files = [os.path.join(dp, f) for dp, _, fs in os.walk(zipped) for f in fs if f.endswith(".gz")]
    print(f"[+] Decompressing {len(files)} .gz files")
    for i, src in enumerate(files, 1):
        dst = os.path.join(unzipped, os.path.basename(src)[:-3])
        try:
            with gzip.open(src, "rb") as fin, open(dst, "wb") as fout:
                fout.write(fin.read())
        except OSError as e:
            print(f"    [!] {src}: {e}")
    return len(files)


# ---------------------------------------------------------------------------
# Analysis
# ---------------------------------------------------------------------------
def _action_category(event_name: str) -> str:
    """First UpperCase-delimited prefix - 'GetUser' -> 'Get', 'CreateAccessKey' -> 'Create'."""
    if not event_name:
        return ""
    for i, ch in enumerate(event_name):
        if i > 0 and ch.isupper():
            return event_name[:i]
    return event_name


def _read_records(path: str) -> Iterable[dict]:
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError) as e:
        print(f"    [!] cannot parse {path}: {e}")
        return
    for rec in data.get("Records", []):
        yield rec


def analyze(local_path: str) -> tuple[str, str]:
    unzipped = os.path.join(local_path, "UnzippedLogs")
    if not os.path.isdir(unzipped):
        raise SystemExit(f"[!] {unzipped} does not exist. Run 'download' or 'unzip' first.")

    full_csv = os.path.join(local_path, "Full Analyzed Logs.csv")
    sens_csv = os.path.join(local_path, "Sensitive IAM Actions.csv")

    fieldnames = [
        "EntityUserName", "EventName_TheAction", "ActionCategory", "ActionType",
        "GotError", "EntityType", "AccessKeyId", "CredentialsType", "EventType",
        "EventTimeUTC", "DayOfTheWeek", "Day", "Month", "Year", "InvokedBy",
        "EventSource", "SourceAccountID", "RecipientAccountId", "LoginMFA",
        "TempSessionMFA", "ResponsedTokenID", "ResponsedAccessKeyID",
        "ResponsedAccessKeyTarget", "PrincipleID", "ARN", "AWSresources",
        "AwsRegion", "UserAgent", "RequestParameters", "ResponseElements",
        "ErrorCode", "ErrorMessage", "RequestID", "EventID", "SharedEventID",
        "EventVersion", "SourceIP", "LogOriginalFilePath",
    ]

    total = 0
    sensitive_rows: list[dict] = []
    files = sorted(os.listdir(unzipped))
    print(f"[+] Analysing {len(files)} CloudTrail files")

    with open(full_csv, "w", newline="", encoding="utf-8") as full_f:
        full_w = csv.DictWriter(full_f, fieldnames=fieldnames)
        full_w.writeheader()

        for idx, fname in enumerate(files, 1):
            path = os.path.join(unzipped, fname)
            if not os.path.isfile(path):
                continue
            for rec in _read_records(path):
                row = _build_row(rec, path)
                if row is None:
                    continue
                full_w.writerow(row)
                total += 1
                if row["EventName_TheAction"] in SENSITIVE_ACTIONS:
                    sensitive_rows.append(row)
            if files and idx % max(1, len(files) // 10) == 0:
                pct = int(idx / len(files) * 100)
                print(f"    {idx}/{len(files)} ({pct}%)")

    with open(sens_csv, "w", newline="", encoding="utf-8") as sf:
        sw = csv.DictWriter(sf, fieldnames=fieldnames)
        sw.writeheader()
        for r in sensitive_rows:
            sw.writerow(r)

    print(f"\n[+] {total} events parsed")
    print(f"[+] {len(sensitive_rows)} sensitive IAM events")
    print(f"[+] Full CSV : {full_csv}")
    print(f"[+] Sensitive: {sens_csv}")
    return full_csv, sens_csv


def _build_row(rec: dict, path: str) -> dict | None:
    try:
        ui = rec.get("userIdentity", {}) or {}
        sc = ui.get("sessionContext", {}) or {}
        attrs = sc.get("attributes", {}) or {}
        event_name = rec.get("eventName", "")
        cat = _action_category(event_name)
        try:
            ts = _dt.datetime.fromisoformat(rec["eventTime"].replace("Z", "+00:00"))
            day, month, year, dow = ts.strftime("%d"), ts.strftime("%m"), ts.strftime("%Y"), ts.strftime("%A")
        except Exception:
            day = month = year = dow = ""

        action_type = "readAction" if cat in ("Describe", "Get", "List") else "activeAction"
        mfa = attrs.get("mfaAuthenticated")
        akid = ui.get("accessKeyId", "")
        cred_type = ""
        if akid:
            cred_type = "TempSessionToken" if mfa else "DirectAccessKey"

        resp = rec.get("responseElements") or {}
        if not isinstance(resp, dict):
            resp = {}
        req = rec.get("requestParameters") or {}
        if not isinstance(req, dict):
            req = {}
        creds = resp.get("credentials") or {}
        if not isinstance(creds, dict):
            creds = {}
        akey = resp.get("accessKey") or {}
        if not isinstance(akey, dict):
            akey = {}

        username = ui.get("userName") or ""
        if ui.get("type") == "Root":
            username = "RootAccount"

        return {
            "EntityUserName": username,
            "EventName_TheAction": event_name,
            "ActionCategory": cat,
            "ActionType": action_type,
            "GotError": "True" if rec.get("errorCode") else "-",
            "EntityType": ui.get("type", ""),
            "AccessKeyId": akid,
            "CredentialsType": cred_type,
            "EventType": rec.get("eventType", ""),
            "EventTimeUTC": rec.get("eventTime", ""),
            "DayOfTheWeek": dow,
            "Day": day, "Month": month, "Year": year,
            "InvokedBy": ui.get("invokedBy", ""),
            "EventSource": rec.get("eventSource", ""),
            "SourceAccountID": ui.get("accountId", ""),
            "RecipientAccountId": rec.get("recipientAccountId", ""),
            "LoginMFA": (rec.get("additionalEventData") or {}).get("MFAUsed", "") if isinstance(rec.get("additionalEventData"), dict) else "",
            "TempSessionMFA": str(mfa) if mfa is not None else "",
            "ResponsedTokenID": creds.get("accessKeyId", ""),
            "ResponsedAccessKeyID": akey.get("accessKeyId", ""),
            "ResponsedAccessKeyTarget": akey.get("userName", ""),
            "PrincipleID": ui.get("principalId", ""),
            "ARN": ui.get("arn", ""),
            "AWSresources": ",".join(r.get("ARN", "") for r in rec.get("resources", []) or []),
            "AwsRegion": rec.get("awsRegion", ""),
            "UserAgent": rec.get("userAgent", ""),
            "RequestParameters": ",".join(req.keys()),
            "ResponseElements": ",".join(resp.keys()),
            "ErrorCode": rec.get("errorCode", ""),
            "ErrorMessage": rec.get("errorMessage", ""),
            "RequestID": rec.get("requestID", ""),
            "EventID": rec.get("eventID", ""),
            "SharedEventID": rec.get("sharedEventID", ""),
            "EventVersion": rec.get("eventVersion", ""),
            "SourceIP": rec.get("sourceIPAddress", ""),
            "LogOriginalFilePath": path,
        }
    except Exception as e:
        print(f"    [!] bad record in {path}: {e}")
        return None


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def main(argv: list[str] | None = None) -> int:
    print(BANNER)
    p = argparse.ArgumentParser()
    sub = p.add_subparsers(dest="cmd", required=True)

    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--profile")
    common.add_argument("--region", default=os.environ.get("AWS_DEFAULT_REGION", "us-east-1"))

    pd = sub.add_parser("download", parents=[common])
    pd.add_argument("--bucket", required=True)
    pd.add_argument("--prefix", required=True)
    pd.add_argument("--local-path", required=True)

    pu = sub.add_parser("unzip")
    pu.add_argument("--local-path", required=True)

    pa = sub.add_parser("analyze")
    pa.add_argument("--local-path", required=True)

    pr = sub.add_parser("run", parents=[common])
    pr.add_argument("--bucket", required=True)
    pr.add_argument("--prefix", required=True)
    pr.add_argument("--local-path", required=True)

    args = p.parse_args(argv)

    if args.cmd in ("download", "run"):
        download_trail(args.bucket, args.prefix, args.local_path, args.region, args.profile)
        unzip_files(args.local_path)
        if args.cmd == "run":
            analyze(args.local_path)
    elif args.cmd == "unzip":
        unzip_files(args.local_path)
    elif args.cmd == "analyze":
        analyze(args.local_path)

    return 0


if __name__ == "__main__":
    sys.exit(main())
