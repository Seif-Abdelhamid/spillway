"""Effective outside access to S3 buckets: bucket policy + ACLs + Block Public Access."""

from __future__ import annotations

import re

from spillway.conditions import ANONYMOUS, ANY_AWS_ACCOUNT, PROBES, Probe, attacker_controlled
from spillway.evaluate import decide
from spillway.findings import Finding, downgrade
from spillway.loader import Resource, Snapshot, strip_index
from spillway.policy import PolicyError, Statement, account_of, object_scope, parse_policy, resource_matches
from spillway.tri import Tri

# Representative actions per access level. A level is exposed if any of its actions is.
LEVELS: dict[str, tuple[str, ...]] = {
    "read": ("s3:GetObject", "s3:ListBucket"),
    "write": ("s3:PutObject", "s3:DeleteObject"),
    "admin": ("s3:PutBucketPolicy", "s3:DeleteBucketPolicy", "s3:PutBucketAcl", "s3:PutObjectAcl"),
}
OBJECT_ACTIONS = {"s3:GetObject", "s3:PutObject", "s3:DeleteObject", "s3:PutObjectAcl"}
BASE_SEVERITY = {"read": "high", "write": "critical", "admin": "critical"}
SOURCE_KEYS = {"aws:sourcearn", "aws:sourceaccount", "aws:sourceorgid"}
PAB_FLAGS = ("block_public_acls", "block_public_policy", "ignore_public_acls", "restrict_public_buckets")
ACCEPT_TAG = "spillway:accept-public-read"

_CANNED = {
    "public-read": {ANONYMOUS.name: ("read",), ANY_AWS_ACCOUNT.name: ("read",)},
    "public-read-write": {ANONYMOUS.name: ("read", "write"), ANY_AWS_ACCOUNT.name: ("read", "write")},
    "authenticated-read": {ANY_AWS_ACCOUNT.name: ("read",)},
}
_GROUPS = {
    "http://acs.amazonaws.com/groups/global/AllUsers": (ANONYMOUS.name, ANY_AWS_ACCOUNT.name),
    "http://acs.amazonaws.com/groups/global/AuthenticatedUsers": (ANY_AWS_ACCOUNT.name,),
}
_ACL_PERMISSION = {"READ": "read", "READ_ACP": "read", "WRITE": "write", "WRITE_ACP": "admin", "FULL_CONTROL": "admin"}


class BucketIndex:
    """Links bucket-attached resources (policy, ACL, public access block) to their bucket."""

    def __init__(self, snap: Snapshot):
        self.snap = snap
        self.buckets = snap.of_type("aws_s3_bucket")
        self.by_name = {b.get("bucket"): b for b in self.buckets if isinstance(b.get("bucket"), str)}

    def bucket_for(self, res: Resource) -> Resource | None:
        name = res.get("bucket")
        if isinstance(name, str) and name in self.by_name:
            return self.by_name[name]
        refs = self.snap.references.get(strip_index(res.address), {}).get("bucket", [])
        for ref in refs:
            matches = [b for b in self.buckets if strip_index(b.address) == ref]
            if len(matches) == 1:
                return matches[0]
            # count/for_each: pair resources that share an index, e.g. [0] with [0]
            suffix = res.address[len(strip_index(res.address)) :]
            for b in matches:
                if b.address.endswith(suffix) and suffix:
                    return b
        return None

    def attached(self, bucket: Resource, rtype: str) -> list[Resource]:
        return [r for r in self.snap.of_type(rtype) if self.bucket_for(r) is bucket]


def _scope_fn(bucket: str, action: str):
    if action in OBJECT_ACTIONS:
        return lambda stmt: object_scope(stmt, bucket)
    arn = f"arn:aws:s3:::{bucket}"
    return lambda stmt: "*" if resource_matches(stmt, arn) else None


def policy_exposure(statements: list[Statement], bucket: str, probe: Probe) -> dict[str, tuple[Tri, str, tuple]]:
    """level -> (result, scope, granting Sids) for the levels this probe can reach."""
    out = {}
    for level, actions in LEVELS.items():
        best = None
        for action in actions:
            d = decide(statements, probe, action, _scope_fn(bucket, action))
            if d.result is Tri.FALSE:
                continue
            if best is None or (d.result is Tri.TRUE and best[0] is not Tri.TRUE):
                best = (d.result, d.scope, d.allowed_by)
        if best:
            out[level] = best
    return out


def _bucket_name(bucket: Resource | None, statements: list[Statement]) -> str | None:
    if bucket is not None and isinstance(bucket.get("bucket"), str):
        return bucket.get("bucket")
    for stmt in statements:
        for r in stmt.resources:
            m = re.match(r"^arn:aws:s3:::([^/*?]+)", r)
            if m:
                return m.group(1)
    return None


def _pab(index: BucketIndex, bucket: Resource | None) -> dict[str, bool | None]:
    """Effective Block Public Access flags. None = not configured in this plan (do not rely on it)."""
    flags: dict[str, bool | None] = dict.fromkeys(PAB_FLAGS)
    sources = list(index.snap.of_type("aws_s3_account_public_access_block"))
    if bucket is not None:
        sources += index.attached(bucket, "aws_s3_bucket_public_access_block")
    for src in sources:
        for flag in PAB_FLAGS:
            value = src.get(flag)
            if value is True:
                flags[flag] = True
            elif value is False and flags[flag] is None:
                flags[flag] = False
    return flags


def _acl_grants(index: BucketIndex, bucket: Resource) -> list[tuple[str, str, str]]:
    """(probe name, level, origin) grants from canned or explicit ACLs."""
    grants: list[tuple[str, str, str]] = []
    acl_sources = [(bucket.address, bucket.get("acl"), None)]
    for acl_res in index.attached(bucket, "aws_s3_bucket_acl"):
        acl_sources.append((acl_res.address, acl_res.get("acl"), acl_res.get("access_control_policy")))
    for address, canned, explicit in acl_sources:
        if isinstance(canned, str):
            for probe_name, levels in _CANNED.get(canned, {}).items():
                grants += [(probe_name, level, f"{address} acl={canned}") for level in levels]
        for policy in explicit or []:
            for grant in (policy or {}).get("grant", []) or []:
                level = _ACL_PERMISSION.get(str(grant.get("permission")))
                for grantee in grant.get("grantee", []) or []:
                    for probe_name in _GROUPS.get(str(grantee.get("uri")), ()):
                        if level:
                            grants.append((probe_name, level, f"{address} grant {grant.get('permission')}"))
    return grants


def _acls_disabled(index: BucketIndex, bucket: Resource) -> bool:
    for oc in index.attached(bucket, "aws_s3_bucket_ownership_controls"):
        for rule in oc.get("rule") or []:
            if isinstance(rule, dict) and rule.get("object_ownership") == "BucketOwnerEnforced":
                return True
    return False


def _accepted(bucket: Resource | None, level: str) -> str:
    """Public *read* can be accepted in code with a justification tag; write/admin never can."""
    if bucket is None or level != "read":
        return ""
    tags = bucket.get("tags") or {}
    reason = tags.get(ACCEPT_TAG, "") if isinstance(tags, dict) else ""
    return reason.strip() if isinstance(reason, str) and len(reason.strip()) >= 10 else ""


def analyze_buckets(snap: Snapshot, account_id: str | None = None) -> list[Finding]:
    index = BucketIndex(snap)
    findings: list[Finding] = []

    for pol in snap.of_type("aws_s3_bucket_policy"):
        bucket = index.bucket_for(pol)
        anchor = pol.address
        if pol.is_unknown("policy") or not isinstance(pol.get("policy"), str):
            findings.append(
                Finding("SPW005", "medium", anchor, "Bucket policy is only known after apply, so it was not checked.")
            )
            continue
        try:
            statements = parse_policy(pol.get("policy"))
        except PolicyError as exc:
            findings.append(Finding("SPW005", "medium", anchor, f"Bucket policy could not be parsed: {exc}."))
            continue
        name = _bucket_name(bucket, statements)
        if name is None:
            findings.append(Finding("SPW005", "medium", anchor, "Bucket policy is not linked to a known bucket."))
            continue
        pab = _pab(index, bucket)
        for probe in PROBES:
            for level, (result, scope, sids) in policy_exposure(statements, name, probe).items():
                if pab["restrict_public_buckets"]:
                    continue  # AWS ignores public-policy grants to outsiders when RestrictPublicBuckets is on
                severity = BASE_SEVERITY[level]
                where = "every object" if scope == "*" else f"keys under {scope}"
                cond = ""
                if result is Tri.UNKNOWN:
                    severity, cond = downgrade(severity), " (conditional: a condition Spillway cannot decide)"
                note = ""
                spoofable = sorted(
                    {k for st in statements if st.sid in sids for k in attacker_controlled(st.conditions, probe)}
                )
                if spoofable:
                    note += f" {', '.join(spoofable)} is set by the requester, so it does not restrict access."
                if pab["block_public_policy"]:
                    note += " BlockPublicPolicy should make AWS reject this policy at apply time."
                findings.append(
                    Finding(
                        "SPW001",
                        severity,
                        anchor,
                        f"{probe.description} can {level} {where} in s3://{name}{cond}, via {', '.join(sids)}.{note}",
                        key=f"{probe.name}:{level}",
                        details={"bucket": name, "probe": probe.name, "level": level, "scope": scope},
                        suppressed=_accepted(bucket, level),
                    )
                )

        for stmt in statements:
            if stmt.effect != "Allow" or stmt.principal is None:
                continue
            for principal in stmt.principal.aws:
                acct = account_of(principal)
                if acct is None or acct == account_id:
                    continue
                if account_id is None:
                    sev, why = "info", " (pass --account-id to tell your own accounts from external ones)"
                else:
                    sev, why = "medium", ""
                findings.append(
                    Finding(
                        "SPW003",
                        sev,
                        anchor,
                        f"{stmt.sid} grants account {acct} access to s3://{name}{why}.",
                        key=f"{acct}:{stmt.sid}",
                    )
                )
            if stmt.principal.service:
                keys = {k.lower() for block in stmt.conditions.values() for k in block}
                if not keys & SOURCE_KEYS:
                    findings.append(
                        Finding(
                            "SPW004",
                            "medium",
                            anchor,
                            f"{stmt.sid} grants {', '.join(stmt.principal.service)} on s3://{name} with no "
                            "aws:SourceArn/aws:SourceAccount condition.",
                            key=stmt.sid,
                        )
                    )

    for bucket in index.buckets:
        pab = _pab(index, bucket)
        off = [f for f in PAB_FLAGS if pab[f] is False]
        if off:
            findings.append(
                Finding("SPW006", "medium", bucket.address, f"Block Public Access turned off: {', '.join(off)}.")
            )
        if pab["ignore_public_acls"] or _acls_disabled(index, bucket):
            continue
        seen = set()
        for probe_name, level, origin in _acl_grants(index, bucket):
            if (probe_name, level) in seen:
                continue
            seen.add((probe_name, level))
            probe = ANONYMOUS if probe_name == ANONYMOUS.name else ANY_AWS_ACCOUNT
            findings.append(
                Finding(
                    "SPW002",
                    BASE_SEVERITY[level],
                    bucket.address,
                    f"{probe.description} can {level} via ACL ({origin}).",
                    key=f"{probe_name}:{level}",
                    suppressed=_accepted(bucket, level),
                )
            )
    return findings
