#!/usr/bin/env python3
"""
AWStealth (Linux/Python port of SkyArk's AWStealth.ps1)

Discovers privileged AWS IAM entities (Users / Groups / Roles) and Shadow
Admins by analysing every attached managed policy and every inline policy
in the target account.

The detection logic mirrors the 32 privilege patterns from the original
PowerShell module written by Asaf Hecht (@Hechtov) - CyberArk Labs.

Credentials are taken from the standard boto3 chain - export AWS_ACCESS_KEY_ID,
AWS_SECRET_ACCESS_KEY and (optional) AWS_SESSION_TOKEN before invocation, or
pass --profile.

Usage examples:
    python3 awstealth.py
    python3 awstealth.py --region us-east-1 --output-dir ./out
    python3 awstealth.py --profile myprofile
"""
from __future__ import annotations

import argparse
import csv
import datetime as _dt
import json
import os
import sys
import time
import urllib.parse
from typing import Any

try:
    import boto3
    import botocore
    from botocore.exceptions import BotoCoreError, ClientError
except ImportError:
    sys.stderr.write("[!] boto3 is required. Install with: pip install boto3\n")
    sys.exit(1)


# ---------------------------------------------------------------------------
# Banner
# ---------------------------------------------------------------------------
VERSION = "py-1.0"
BANNER = r"""
------------------------------------------------------
      __          _______ _             _ _   _
     /\ \        / / ____| |           | | | | |
    /  \ \  /\  / / (___ | |_ ___  __ _| | |_| |__
   / /\ \ \/  \/ / \___ \| __/ _ \/ _` | | __| '_ \
  / ____ \  /\  /  ____) | ||  __/ (_| | | |_| | | |
 /_/    \_\/  \/  |_____/ \__\___|\__,_|_|\__|_| |_|
------------------------------------------------------
   AWStealth (Linux/Python {ver}) - Shadow-Admin scan
------------------------------------------------------
""".format(ver=VERSION)


# ---------------------------------------------------------------------------
# Privilege detection
# ---------------------------------------------------------------------------
BUILTIN_PRIVILEGED_POLICIES = {
    "AdministratorAccess":   "FullAWSAdmin",
    "Billing":               "BillingAdministrator",
    "NetworkAdministrator":  "NetworkAdministrator",
    "PowerUserAccess":       "PowerUserAccess",
    "SystemAdministrator":   "SystemAdministrator",
    "DatabaseAdministrator": "DatabaseAdministrator",
}

BROAD_RESOURCES = {
    "*",
    "arn:aws:iam::*:user/*",
    "arn:aws:iam::*:group/*",
    "arn:aws:iam::*:role/*",
    "arn:aws:iam::*:policy/*",
    "arn:aws:iam::*:instance-profile/*",
    "arn:aws:ec2:*:*:instance/*",
    "arn:aws:lambda:*:*:function:*",
    "arn:aws:glue:*:*:catalog/*",
    "arn:aws:cloudformation:*:*:stack/*/*",
    "arn:aws:codestar:*:*:project/*",
    "arn:aws:codestar:*:*:notebook-instance/*",
}


def _as_list(v: Any) -> list:
    """Policy fields can be a string OR a list - normalize to list."""
    if v is None:
        return []
    return v if isinstance(v, list) else [v]


def _has_resource(resources: list, allowed: set) -> bool:
    return any(r in allowed for r in resources)


def _has_action(actions: list, wanted: set) -> bool:
    return any(a in wanted for a in actions)


def _mark(out: list, label: str) -> None:
    if label not in out:
        out.append(label)


def check_privileged_policy(policy_doc: dict, policy_name: str = "") -> tuple[bool, str, str]:
    """
    Return (is_privileged, privilege_type, policy_condition).

    Faithful port of the Check-PrivilegedPolicy function in AWStealth.ps1.
    """
    if policy_name in BUILTIN_PRIVILEGED_POLICIES:
        return True, BUILTIN_PRIVILEGED_POLICIES[policy_name], "noCondition"

    if not policy_doc:
        return False, "", "noCondition"

    statements = _as_list(policy_doc.get("Statement"))
    matched: list[str] = []
    policy_condition = "noCondition"

    for stmt in statements:
        if not isinstance(stmt, dict):
            continue
        if stmt.get("Effect") != "Allow":
            continue

        # condition aggregation
        if stmt.get("Condition"):
            cond_val = ""
            for v in stmt["Condition"].values():
                cond_val += str(v)
            policy_condition = cond_val if policy_condition == "noCondition" else policy_condition + cond_val

        actions = _as_list(stmt.get("Action"))
        resources = _as_list(stmt.get("Resource"))
        if not _has_resource(resources, BROAD_RESOURCES):
            continue

        # (1) full cloud admin */*
        if "*" in actions and "*" in resources:
            _mark(matched, "FullAWSAdmin")
        # (2) CreateAccessKey -> other users
        if "iam:CreateAccessKey" in actions and _has_resource(resources, {"*", "arn:aws:iam::*:user/*"}):
            _mark(matched, "ShadowCreateAccessKeys")
        # (3) Attach*Policy
        if "iam:AttachUserPolicy" in actions and _has_resource(resources, {"*", "arn:aws:iam::*:user/*"}):
            _mark(matched, "ShadowAttachUserPolicy")
        if "iam:AttachGroupPolicy" in actions and _has_resource(resources, {"*", "arn:aws:iam::*:group/*"}):
            _mark(matched, "ShadowAttachGroupPolicy")
        if "iam:AttachRolePolicy" in actions and _has_resource(resources, {"*", "arn:aws:iam::*:role/*"}):
            _mark(matched, "ShadowAttachRolePolicy")
        # (4) Put*Policy
        if "iam:PutUserPolicy" in actions and _has_resource(resources, {"*", "arn:aws:iam::*:user/*"}):
            _mark(matched, "ShadowPutUserPolicy")
        if "iam:PutGroupPolicy" in actions and _has_resource(resources, {"*", "arn:aws:iam::*:group/*"}):
            _mark(matched, "ShadowPutGroupPolicy")
        if "iam:PutRolePolicy" in actions and _has_resource(resources, {"*", "arn:aws:iam::*:role/*"}):
            _mark(matched, "ShadowPutRolePolicy")
        # (5) CreatePolicy
        if "iam:CreatePolicy" in actions and _has_resource(resources, {"*", "arn:aws:iam::*:policy/*"}):
            _mark(matched, "ShadowCreatePolicy")
        # (6) UpdateLoginProfile
        if "iam:UpdateLoginProfile" in actions and _has_resource(resources, {"*", "arn:aws:iam::*:user/*"}):
            _mark(matched, "ShadowUpdateLoginProfiles")
        # (7) CreateLoginProfile
        if "iam:CreateLoginProfile" in actions and _has_resource(resources, {"*", "arn:aws:iam::*:user/*"}):
            _mark(matched, "ShadowCreateLoginProfiles")
        # (8) AddUserToGroup
        if "iam:AddUserToGroup" in actions and _has_resource(resources, {"*", "arn:aws:iam::*:group/*"}):
            _mark(matched, "ShadowAddUserToGroups")
        # (9) CreatePolicyVersion / SetDefaultPolicyVersion
        if _has_action(actions, {"iam:CreatePolicyVersion", "iam:SetDefaultPolicyVersion"}) \
                and _has_resource(resources, {"*", "arn:aws:iam::*:policy/*"}):
            _mark(matched, "ShadowSetPolicyVersions")
        # (10) modifyInstanceProfile combo
        ip_actions = {"iam:CreateInstanceProfile", "iam:AddRoleToInstanceProfile",
                      "iam:PassRole", "ec2:AssociateIamInstanceProfile"}
        ip_resources = {"*", "arn:aws:iam::*:role/*", "arn:aws:iam::*:instance-profile/*",
                        "arn:aws:ec2:*:*:instance/*"}
        if len([a for a in actions if a in ip_actions]) >= 3 and _has_resource(resources, ip_resources):
            _mark(matched, "ShadowModifyInstanceProfiles")
        # (11) UpdateAssumeRolePolicy
        if "iam:UpdateAssumeRolePolicy" in actions and _has_resource(resources, {"*", "arn:aws:iam::*:role/*"}):
            _mark(matched, "ShadowUpdateAssumeRolePolicy")
        # (12) iam:* full IAM admin
        iam_star_res = {"*", "arn:aws:iam::*:user/*", "arn:aws:iam::*:group/*",
                        "arn:aws:iam::*:role/*", "arn:aws:iam::*:policy/*",
                        "arn:aws:iam::*:instance-profile/*"}
        if "iam:*" in actions and _has_resource(resources, iam_star_res):
            _mark(matched, "FullIAMadmin")
        # (13)-(18) service-wide admins
        if "s3:*" in actions and "*" in resources:
            _mark(matched, "FullS3admin")
        if "ec2:*" in actions and "*" in resources:
            _mark(matched, "FullEC2admin")
        if "kms:*" in actions and "*" in resources:
            _mark(matched, "FullKMSadmin")
        if "sts:*" in actions and "*" in resources:
            _mark(matched, "FullSTSadmin")
        if "Cloudformation:*" in actions and "*" in resources:
            _mark(matched, "FullCloudformationAdmin")
        if "lambda:*" in actions and "*" in resources:
            _mark(matched, "FullLambdaAdmin")
        # (19) iam:attach*
        if "iam:attach*" in actions and _has_resource(resources, {"*", "arn:aws:iam::*:user/*",
                                                                  "arn:aws:iam::*:group/*",
                                                                  "arn:aws:iam::*:role/*"}):
            _mark(matched, "IAMattachAdmin")
        # (20) iam:put*
        if "iam:put*" in actions and _has_resource(resources, {"*", "arn:aws:iam::*:user/*",
                                                               "arn:aws:iam::*:group/*",
                                                               "arn:aws:iam::*:role/*"}):
            _mark(matched, "IAMputAdmin")
        # (21) iam:add*
        if "iam:add*" in actions and _has_resource(resources, {"*", "arn:aws:iam::*:group/*"}):
            _mark(matched, "IAMaddAdmin")
        # (22) iam:create*
        if "iam:create*" in actions and _has_resource(resources, {"*", "arn:aws:iam::*:policy/*"}):
            _mark(matched, "IAMcreateAdmin")
        # (23) CreatePolicyVersion alone
        if "iam:CreatePolicyVersion" in actions and _has_resource(resources, {"*", "arn:aws:iam::*:policy/*"}):
            _mark(matched, "ShadowCreatePolicyVersions")
        # (24) PassRole + RunInstances
        if {"iam:PassRole", "ec2:RunInstances"}.issubset(set(actions)) \
                and _has_resource(resources, {"*", "arn:aws:ec2:*:*:instance/*"}):
            _mark(matched, "ShadowRunNewInstancesWithRoles")

        # (25-32) Rhino Security Labs PrivEsc methods
        if "iam:PassRole" in actions:
            if "lambda:CreateFunction" in actions and _has_resource(resources, {"*", "arn:aws:lambda:*:*:function:*"}):
                if _has_action(actions, {"lambda:InvokeFunction",
                                         "lambda:AddPermission",
                                         "lambda:CreateEventSourceMapping"}):
                    _mark(matched, "ShadowRunLambda")
            if "glue:CreateDevEndpoint" in actions and _has_resource(resources, {"*", "arn:aws:glue:*:*:catalog/*"}):
                _mark(matched, "ShadowGlueDevEndpoint")
            if "cloudformation:CreateStack" in actions and _has_resource(resources, {"*", "arn:aws:cloudformation:*:*:stack/*/*"}):
                _mark(matched, "ShadowCloudFormation")
            if {"datapipeline:CreatePipeline", "datapipeline:PutPipelineDefinition"}.issubset(set(actions)) \
                    and "*" in resources:
                _mark(matched, "ShadowDataPipeline")
            if "codestar:CreateProject" in actions and _has_resource(resources, {"*", "arn:aws:codestar:*:*:project/*"}):
                _mark(matched, "ShadowCodeStar")
            if {"sagemaker:CreateNotebookInstance", "sagemaker:CreatePresignedNotebookInstanceUrl"}.issubset(set(actions)) \
                    and _has_resource(resources, {"*", "arn:aws:codestar:*:*:notebook-instance/*"}):
                _mark(matched, "ShadowSageMaker")

        if "lambda:UpdateFunctionCode" in actions and _has_resource(resources, {"*", "arn:aws:lambda:*:*:function:*"}):
            _mark(matched, "ShadowUpdateLambda")
        if "glue:UpdateDevEndpoint" in actions and _has_resource(resources, {"*", "arn:aws:glue:*:*:catalog/*"}):
            _mark(matched, "ShadowGlueUpdate")
        if "codestar:CreateProjectFromTemplate" in actions and _has_resource(resources, {"*", "arn:aws:codestar:*:*:project/*"}):
            _mark(matched, "ShadowCodeStar")
        if {"codestar:CreateProject", "codestar:AssociateTeamMember"}.issubset(set(actions)) \
                and _has_resource(resources, {"*", "arn:aws:codestar:*:*:project/*"}):
            _mark(matched, "ShadowCodeStar")
        if "lambda:UpdateFunctionConfiguration" in actions and _has_resource(resources, {"*", "arn:aws:codestar:*:*:function/*"}):
            _mark(matched, "ShadowAddLambda")
        if "sagemaker:CreatePresignedNotebookInstanceUrl" in actions and _has_resource(resources, {"*", "arn:aws:codestar:*:*:notebook-instance/*"}):
            _mark(matched, "ShadowSageMaker")

    is_priv = bool(matched)
    return is_priv, ",".join(matched), policy_condition


# ---------------------------------------------------------------------------
# AWS plumbing
# ---------------------------------------------------------------------------
def _decode_doc(raw: Any) -> dict:
    """get_policy_version / GetUserPolicy may return Document as dict or as URL-encoded string."""
    if isinstance(raw, dict):
        return raw
    if isinstance(raw, str):
        return json.loads(urllib.parse.unquote(raw))
    return {}


def build_clients(profile: str | None, region: str):
    session_kw = {"region_name": region}
    if profile:
        session_kw["profile_name"] = profile
    session = boto3.session.Session(**session_kw)
    iam = session.client("iam")
    sts = session.client("sts")
    return session, iam, sts


def paginate(client, op: str, key: str, **kwargs):
    paginator = client.get_paginator(op)
    for page in paginator.paginate(**kwargs):
        for item in page.get(key, []):
            yield item


# ---------------------------------------------------------------------------
# Scan orchestration
# ---------------------------------------------------------------------------
class Scanner:
    def __init__(self, iam, verbose: bool = False):
        self.iam = iam
        self.verbose = verbose
        self.entities: dict[str, dict] = {}
        self.counts: dict[str, int] = {}

    # -------- entity helpers ------------------------------------------------
    def _user_mfa(self, username: str) -> str:
        try:
            res = self.iam.list_mfa_devices(UserName=username)
            return "True" if res.get("MFADevices") else "NoMFA"
        except ClientError:
            return "Unknown"

    def _entity_line(self, *, entity_type: str, policy_type: str, entity_obj: dict,
                     policy_doc_str: str, policy_name: str, privilege_type: str,
                     policy_condition: str) -> dict:
        group_members = ""
        assume_role_doc = ""
        if entity_type == "User":
            name = entity_obj["UserName"]
            arn = entity_obj["Arn"]
            password_last_used = str(entity_obj.get("PasswordLastUsed", "")) or "Never"
            mfa = self._user_mfa(name)
        elif entity_type == "Group":
            name = entity_obj["Group"]["GroupName"]
            arn = entity_obj["Group"]["Arn"]
            users = entity_obj.get("Users") or []
            group_members = ",".join(u["UserName"] for u in users) or "EmptyGroup"
            mfa = "-"
            password_last_used = ""
        else:  # Role
            name = entity_obj["RoleName"]
            arn = entity_obj["Arn"]
            assume = entity_obj.get("AssumeRolePolicyDocument")
            assume_role_doc = json.dumps(assume) if isinstance(assume, dict) else str(assume or "")
            mfa = "-"
            password_last_used = ""

        return {
            "EntityName": name,
            "EntityType": entity_type,
            "PrivilegeType": privilege_type,
            "PolicyName": policy_name,
            "PolicyType": policy_type,
            "MFAenable": mfa,
            "policyCondition": policy_condition,
            "GroupMembers": group_members,
            "PasswordLastUsed": password_last_used,
            "AssumeRolePolicyDocument": assume_role_doc,
            "Arn": arn,
            "PrivilegedPermissionPolicy": policy_doc_str,
        }

    def _merge_or_add(self, arn: str, builder, *, policy_doc_str: str,
                      policy_name: str, privilege_type: str, policy_condition: str,
                      policy_type_suffix: str = ""):
        if arn in self.entities:
            line = self.entities[arn]
            line["PrivilegedPermissionPolicy"] += f"\n+\n{policy_doc_str}"
            if policy_type_suffix:
                line["PolicyType"] += policy_type_suffix
            line["PolicyName"] += f",{policy_name}"
            line["PrivilegeType"] += f",{privilege_type}"
            line["policyCondition"] += f",{policy_condition}"
        else:
            self.entities[arn] = builder()

    # -------- managed policies ---------------------------------------------
    def scan_managed_policies(self):
        print("[+] Scanning attached managed policies...")
        policies = list(paginate(self.iam, "list_policies", "Policies", OnlyAttached=True))
        self.counts["ManagedPolicies"] = len(policies)
        print(f"    Discovered {len(policies)} attached managed policies")

        for idx, pol in enumerate(policies, 1):
            arn = pol["Arn"]
            name = pol["PolicyName"]
            try:
                ver = self.iam.get_policy_version(PolicyArn=arn, VersionId=pol["DefaultVersionId"])
            except ClientError as e:
                if self.verbose:
                    print(f"    [!] Could not fetch policy version for {name}: {e}")
                continue
            doc = _decode_doc(ver["PolicyVersion"]["Document"])
            doc_str = json.dumps(doc, indent=2)
            is_priv, ptype, pcond = check_privileged_policy(doc, name)
            if not is_priv:
                continue

            # entities the policy is attached to
            try:
                entities = self.iam.list_entities_for_policy(
                    PolicyArn=arn, PolicyUsageFilter="PermissionsPolicy"
                )
            except ClientError:
                entities = self.iam.list_entities_for_policy(PolicyArn=arn)

            for u in entities.get("PolicyUsers", []):
                try:
                    info = self.iam.get_user(UserName=u["UserName"])["User"]
                except ClientError:
                    continue
                self._merge_or_add(
                    info["Arn"],
                    lambda info=info: self._entity_line(
                        entity_type="User", policy_type="ManagedPolicy",
                        entity_obj=info, policy_doc_str=doc_str,
                        policy_name=name, privilege_type=ptype, policy_condition=pcond,
                    ),
                    policy_doc_str=doc_str, policy_name=name,
                    privilege_type=ptype, policy_condition=pcond,
                )
            for g in entities.get("PolicyGroups", []):
                try:
                    info = self.iam.get_group(GroupName=g["GroupName"])
                except ClientError:
                    continue
                self._merge_or_add(
                    info["Group"]["Arn"],
                    lambda info=info: self._entity_line(
                        entity_type="Group", policy_type="ManagedPolicy",
                        entity_obj=info, policy_doc_str=doc_str,
                        policy_name=name, privilege_type=ptype, policy_condition=pcond,
                    ),
                    policy_doc_str=doc_str, policy_name=name,
                    privilege_type=ptype, policy_condition=pcond,
                )
                # propagate to users-in-group
                for member in info.get("Users", []):
                    try:
                        uinfo = self.iam.get_user(UserName=member["UserName"])["User"]
                    except ClientError:
                        continue
                    pname = f"{name}-Through\"{info['Group']['GroupName']}\"Group"
                    self._merge_or_add(
                        uinfo["Arn"],
                        lambda uinfo=uinfo, pname=pname: self._entity_line(
                            entity_type="User", policy_type="ManagedPolicy",
                            entity_obj=uinfo, policy_doc_str=doc_str,
                            policy_name=pname, privilege_type=ptype, policy_condition=pcond,
                        ),
                        policy_doc_str=doc_str, policy_name=pname,
                        privilege_type=ptype, policy_condition=pcond,
                    )
            for r in entities.get("PolicyRoles", []):
                try:
                    info = self.iam.get_role(RoleName=r["RoleName"])["Role"]
                except ClientError:
                    continue
                self._merge_or_add(
                    info["Arn"],
                    lambda info=info: self._entity_line(
                        entity_type="Role", policy_type="ManagedPolicy",
                        entity_obj=info, policy_doc_str=doc_str,
                        policy_name=name, privilege_type=ptype, policy_condition=pcond,
                    ),
                    policy_doc_str=doc_str, policy_name=name,
                    privilege_type=ptype, policy_condition=pcond,
                )

            if len(policies) >= 10 and idx % max(1, len(policies) // 10) == 0:
                pct = int(idx / len(policies) * 100)
                print(f"    Status: {idx}/{len(policies)} managed policies ({pct}%)")
        print("[+] Finished managed policies")

    # -------- inline policies ----------------------------------------------
    def scan_inline_policies(self):
        print("\n[+] Scanning inline policies...")
        users = list(paginate(self.iam, "list_users", "Users"))
        groups = list(paginate(self.iam, "list_groups", "Groups"))
        roles = list(paginate(self.iam, "list_roles", "Roles"))
        self.counts["Users"] = len(users)
        self.counts["Groups"] = len(groups)
        self.counts["Roles"] = len(roles)

        inline_count = 0

        # users
        print(f"    Analyzing {len(users)} users for inline policies")
        for u in users:
            uname = u["UserName"]
            for pname in self.iam.list_user_policies(UserName=uname).get("PolicyNames", []):
                inline_count += 1
                pol = self.iam.get_user_policy(UserName=uname, PolicyName=pname)
                doc = _decode_doc(pol["PolicyDocument"])
                doc_str = json.dumps(doc, indent=2)
                is_priv, ptype, pcond = check_privileged_policy(doc, pname)
                if not is_priv:
                    continue
                info = self.iam.get_user(UserName=uname)["User"]
                self._merge_or_add(
                    info["Arn"],
                    lambda info=info, pname=pname: self._entity_line(
                        entity_type="User", policy_type="InlinePolicy",
                        entity_obj=info, policy_doc_str=doc_str,
                        policy_name=pname, privilege_type=ptype, policy_condition=pcond,
                    ),
                    policy_doc_str=doc_str, policy_name=pname,
                    privilege_type=ptype, policy_condition=pcond,
                    policy_type_suffix="+InlinePolicy",
                )

        # groups
        print(f"    Analyzing {len(groups)} groups for inline policies")
        for g in groups:
            gname = g["GroupName"]
            for pname in self.iam.list_group_policies(GroupName=gname).get("PolicyNames", []):
                inline_count += 1
                pol = self.iam.get_group_policy(GroupName=gname, PolicyName=pname)
                doc = _decode_doc(pol["PolicyDocument"])
                doc_str = json.dumps(doc, indent=2)
                is_priv, ptype, pcond = check_privileged_policy(doc, pname)
                if not is_priv:
                    continue
                ginfo = self.iam.get_group(GroupName=gname)
                self._merge_or_add(
                    ginfo["Group"]["Arn"],
                    lambda ginfo=ginfo, pname=pname: self._entity_line(
                        entity_type="Group", policy_type="InlinePolicy",
                        entity_obj=ginfo, policy_doc_str=doc_str,
                        policy_name=pname, privilege_type=ptype, policy_condition=pcond,
                    ),
                    policy_doc_str=doc_str, policy_name=pname,
                    privilege_type=ptype, policy_condition=pcond,
                    policy_type_suffix="+InlinePolicy",
                )
                # propagate to group members
                for member in ginfo.get("Users", []):
                    try:
                        uinfo = self.iam.get_user(UserName=member["UserName"])["User"]
                    except ClientError:
                        continue
                    pname2 = f"{pname}-Through\"{gname}\"Group"
                    self._merge_or_add(
                        uinfo["Arn"],
                        lambda uinfo=uinfo, pname2=pname2: self._entity_line(
                            entity_type="User", policy_type="InlinePolicy",
                            entity_obj=uinfo, policy_doc_str=doc_str,
                            policy_name=pname2, privilege_type=ptype, policy_condition=pcond,
                        ),
                        policy_doc_str=doc_str, policy_name=pname2,
                        privilege_type=ptype, policy_condition=pcond,
                        policy_type_suffix="+InlinePolicy",
                    )

        # roles
        print(f"    Analyzing {len(roles)} roles for inline policies")
        for r in roles:
            rname = r["RoleName"]
            for pname in self.iam.list_role_policies(RoleName=rname).get("PolicyNames", []):
                inline_count += 1
                pol = self.iam.get_role_policy(RoleName=rname, PolicyName=pname)
                doc = _decode_doc(pol["PolicyDocument"])
                doc_str = json.dumps(doc, indent=2)
                is_priv, ptype, pcond = check_privileged_policy(doc, pname)
                if not is_priv:
                    continue
                rinfo = self.iam.get_role(RoleName=rname)["Role"]
                self._merge_or_add(
                    rinfo["Arn"],
                    lambda rinfo=rinfo, pname=pname: self._entity_line(
                        entity_type="Role", policy_type="InlinePolicy",
                        entity_obj=rinfo, policy_doc_str=doc_str,
                        policy_name=pname, privilege_type=ptype, policy_condition=pcond,
                    ),
                    policy_doc_str=doc_str, policy_name=pname,
                    privilege_type=ptype, policy_condition=pcond,
                    policy_type_suffix="+InlinePolicy",
                )

        self.counts["InlinePolicies"] = inline_count
        print(f"[+] Finished {inline_count} inline policies")


# ---------------------------------------------------------------------------
# Report writers
# ---------------------------------------------------------------------------
def write_csv(path: str, rows: list[dict]) -> None:
    if not rows:
        # write headers only
        rows = [{}]
    fieldnames = list(rows[0].keys()) or [
        "EntityName", "EntityType", "PrivilegeType", "PolicyName", "PolicyType",
        "MFAenable", "policyCondition", "GroupMembers", "PasswordLastUsed",
        "AssumeRolePolicyDocument", "Arn", "PrivilegedPermissionPolicy",
    ]
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        for r in rows:
            if r:
                w.writerow(r)


def write_report(path: str, rows: list[dict], counts: dict, csv_path: str, account: str) -> None:
    lines = []
    add = lines.append
    add("")
    add("######################################################")
    add(BANNER.strip())
    add(f"              AWStealth version: {VERSION}")
    add("")
    add(f"       The scanned AWS Account: {account}")
    add(f"        Date of the scan: {_dt.datetime.now().strftime('%Y-%m-%d %H:%M')}")
    add("")
    add("######################################################")
    add("                     SCAN SUMMARY")
    add("######################################################")
    add(f"Users:           {counts.get('Users', '?')}")
    add(f"Groups:          {counts.get('Groups', '?')}")
    add(f"Roles:           {counts.get('Roles', '?')}")
    add(f"Managed policies attached: {counts.get('ManagedPolicies', '?')}")
    add(f"Inline policies discovered: {counts.get('InlinePolicies', '?')}")
    add("")

    shadow = [r for r in rows if "shadow" in r["PrivilegeType"].lower()]
    no_mfa = [r for r in rows if r["MFAenable"] == "NoMFA"]
    no_cond = [r for r in rows if "noCon" in r["policyCondition"]]
    unsec = [r for r in rows if r["MFAenable"] == "NoMFA" and "noCon" in r["policyCondition"]]

    add(f"Total privileged entities: {len(rows)}")
    add(f"Shadow Admins: {len(shadow)}")
    add(f"Users without MFA: {len(no_mfa)}")
    add(f"Entities without permission conditions: {len(no_cond)}")
    add(f"Unsecured users (no MFA AND no condition): {len(unsec)}")
    add("")
    add("Full CSV: " + csv_path)
    add("######################################################")

    by_type = {"User": [], "Group": [], "Role": []}
    for r in rows:
        by_type.setdefault(r["EntityType"], []).append(r)

    for et in ("User", "Group", "Role"):
        add("")
        add(f"--- Privileged {et}s ({len(by_type[et])}) ---")
        for i, r in enumerate(by_type[et], 1):
            extra = f" members=[{r['GroupMembers']}]" if et == "Group" else ""
            add(f"{i}. {r['EntityName']}  privType={r['PrivilegeType']}  mfa={r['MFAenable']}{extra}")

    add("")
    add("######################################################")
    add("Detailed entity dumps:")
    add("######################################################")
    for i, r in enumerate(rows, 1):
        add("")
        add(f"{i}. {r['EntityName']} ({r['EntityType']})  arn={r['Arn']}")
        add(f"   Privilege types: {r['PrivilegeType']}")
        add(f"   Policy names:    {r['PolicyName']}")
        add(f"   Condition:       {r['policyCondition']}")
        add(f"   MFA:             {r['MFAenable']}")
        if r["GroupMembers"]:
            add(f"   GroupMembers:    {r['GroupMembers']}")
        if r["AssumeRolePolicyDocument"]:
            add(f"   AssumeRoleDoc:   {r['AssumeRolePolicyDocument']}")
        add("   PrivilegedPermissionPolicy:")
        for ln in r["PrivilegedPermissionPolicy"].splitlines():
            add(f"     {ln}")

    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------
def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="AWStealth (Linux/Python port)")
    parser.add_argument("--profile", help="boto3 profile name (default: env credentials)")
    parser.add_argument("--region", default=os.environ.get("AWS_DEFAULT_REGION", "us-east-1"))
    parser.add_argument("--output-dir", default=os.path.dirname(os.path.abspath(__file__)))
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args(argv)

    print(BANNER)

    try:
        session, iam, sts = build_clients(args.profile, args.region)
        ident = sts.get_caller_identity()
        print(f"[+] Caller identity: {ident['Arn']}  (account {ident['Account']})")
    except (BotoCoreError, ClientError) as e:
        print(f"[!] Failed to authenticate to AWS: {e}", file=sys.stderr)
        return 2

    scanner = Scanner(iam, verbose=args.verbose)
    start = time.time()
    try:
        scanner.scan_managed_policies()
        scanner.scan_inline_policies()
    except (BotoCoreError, ClientError) as e:
        print(f"[!] AWS error mid-scan: {e}", file=sys.stderr)

    rows = sorted(
        scanner.entities.values(),
        key=lambda r: (r["EntityType"], r["PrivilegeType"], r["PolicyName"]),
        reverse=True,
    )

    os.makedirs(args.output_dir, exist_ok=True)
    stamp = _dt.datetime.now().strftime("%Y%m%d-%H%M%S")
    csv_path = os.path.join(args.output_dir, f"AWStealth-Results-{stamp}.csv")
    txt_path = os.path.join(args.output_dir, f"AWStealth-Report-{stamp}.txt")
    write_csv(csv_path, rows)
    write_report(txt_path, rows, scanner.counts, csv_path, ident["Account"])

    elapsed = time.time() - start
    print(f"\n[+] Discovered {len(rows)} privileged entities in {elapsed:.1f}s")
    print(f"[+] CSV : {csv_path}")
    print(f"[+] TXT : {txt_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
