"""IAM role trust policies (who can become this role?) and identity policies (least privilege)."""

from __future__ import annotations

from spillway.conditions import ANY_AWS_ACCOUNT
from spillway.evaluate import decide
from spillway.findings import Finding
from spillway.loader import Snapshot
from spillway.policy import PolicyError, Statement, account_of, action_matches, parse_policy
from spillway.tri import Tri

GITHUB_OIDC = "token.actions.githubusercontent.com"
IDENTITY_POLICY_TYPES = {
    "aws_iam_policy": "policy",
    "aws_iam_role_policy": "policy",
    "aws_iam_user_policy": "policy",
    "aws_iam_group_policy": "policy",
}


def _load(res, attr: str, findings: list[Finding], what: str) -> list[Statement] | None:
    if res.is_unknown(attr):
        findings.append(Finding("SPW005", "medium", res.address, f"{what} is only known after apply, not checked."))
        return None
    doc = res.get(attr)
    if not isinstance(doc, str) or not doc.strip():
        return None
    try:
        return parse_policy(doc)
    except PolicyError as exc:
        findings.append(Finding("SPW005", "medium", res.address, f"{what} could not be parsed: {exc}."))
        return None


def _condition_values(stmt: Statement, key: str) -> list[str] | None:
    found = None
    for block in stmt.conditions.values():
        for k, values in block.items():
            if k.lower() == key.lower():
                found = (found or []) + list(values)
    return found


def _github_sub_risk(values: list[str] | None) -> str | None:
    if values is None:
        return "has no condition on the token subject, so any GitHub repository's workflow can assume it"
    for v in values:
        repo = v.removeprefix("repo:")
        owner = repo.split("/", 1)[0]
        if not v.startswith("repo:") or "*" in owner or "?" in owner or "/" not in repo:
            return f"accepts subject {v!r}, which is not pinned to one owner's repository"
    return None


def analyze_roles(snap: Snapshot, account_id: str | None = None) -> list[Finding]:
    findings: list[Finding] = []
    for role in snap.of_type("aws_iam_role"):
        statements = _load(role, "assume_role_policy", findings, "Trust policy")
        if not statements:
            continue
        d = decide(statements, ANY_AWS_ACCOUNT, "sts:AssumeRole", lambda _s: "*")
        if d.result is not Tri.FALSE:
            sure = d.result is Tri.TRUE
            findings.append(
                Finding(
                    "SPW101",
                    "critical" if sure else "high",
                    role.address,
                    f"Any AWS account can assume this role{'' if sure else ' (conditional)'}, "
                    f"via {', '.join(d.allowed_by)}.",
                    key="any-aws-account",
                )
            )
        for stmt in statements:
            if stmt.effect != "Allow" or stmt.principal is None:
                continue
            if any(GITHUB_OIDC in f for f in stmt.principal.federated) and action_matches(
                stmt, "sts:AssumeRoleWithWebIdentity"
            ):
                risk = _github_sub_risk(_condition_values(stmt, f"{GITHUB_OIDC}:sub"))
                if risk:
                    findings.append(
                        Finding("SPW103", "critical", role.address, f"GitHub OIDC trust {risk}.", key=stmt.sid)
                    )
            if not action_matches(stmt, "sts:AssumeRole"):
                continue
            for principal in stmt.principal.aws:
                acct = account_of(principal)
                if acct is None or acct == account_id:
                    continue
                guarded = _condition_values(stmt, "sts:ExternalId") or _condition_values(stmt, "aws:PrincipalOrgID")
                if guarded:
                    continue
                findings.append(
                    Finding(
                        "SPW102",
                        "medium" if account_id else "info",
                        role.address,
                        f"Account {acct} can assume this role with no sts:ExternalId or aws:PrincipalOrgID condition"
                        + ("" if account_id else " (pass --account-id to tell your own accounts from external ones)")
                        + ".",
                        key=acct,
                    )
                )
    return findings


def analyze_identity_policies(snap: Snapshot) -> list[Finding]:
    findings: list[Finding] = []
    for rtype, attr in IDENTITY_POLICY_TYPES.items():
        for res in snap.of_type(rtype):
            statements = _load(res, attr, findings, "Identity policy")
            for stmt in statements or []:
                if stmt.effect != "Allow":
                    continue
                if stmt.not_actions:
                    findings.append(
                        Finding(
                            "SPW204",
                            "medium",
                            res.address,
                            f"{stmt.sid} allows everything except {', '.join(stmt.not_actions)}.",
                            key=stmt.sid,
                        )
                    )
                    continue
                all_resources = "*" in stmt.resources
                if not all_resources:
                    continue
                if "*" in stmt.actions:
                    findings.append(
                        Finding(
                            "SPW201",
                            "high",
                            res.address,
                            f"{stmt.sid} allows Action '*' on Resource '*' (administrator access).",
                            key=stmt.sid,
                        )
                    )
                    continue
                for action in stmt.actions:
                    service, _, name = action.partition(":")
                    if name == "*":
                        findings.append(
                            Finding(
                                "SPW202",
                                "medium",
                                res.address,
                                f"{stmt.sid} allows every {service} action on every resource.",
                                key=f"{stmt.sid}:{service.lower()}",
                            )
                        )
                if action_matches(stmt, "iam:PassRole"):
                    findings.append(
                        Finding(
                            "SPW203",
                            "high",
                            res.address,
                            f"{stmt.sid} allows iam:PassRole on every role, a common privilege-escalation path.",
                            key=stmt.sid,
                        )
                    )
    return findings
