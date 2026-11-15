"""Finding model and the rule catalog."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field

SEVERITIES = ("info", "low", "medium", "high", "critical")


def severity_rank(severity: str) -> int:
    return SEVERITIES.index(severity)


def downgrade(severity: str) -> str:
    return SEVERITIES[max(0, severity_rank(severity) - 1)]


@dataclass(frozen=True)
class Rule:
    id: str
    title: str
    attack: str  # MITRE ATT&CK technique this exposure enables
    help: str


RULES: dict[str, Rule] = {
    r.id: r
    for r in (
        Rule(
            "SPW001",
            "Bucket policy grants access to principals outside your account",
            "T1530 Data from Cloud Storage",
            "Scope Principal to specific accounts or roles, or add a Deny with aws:PrincipalOrgID / aws:SourceVpce, "
            "and keep S3 Block Public Access on.",
        ),
        Rule(
            "SPW002",
            "Bucket ACL grants access to AllUsers or AuthenticatedUsers",
            "T1530 Data from Cloud Storage",
            "Set object_ownership = BucketOwnerEnforced (disables ACLs) or ignore_public_acls = true.",
        ),
        Rule(
            "SPW003",
            "Bucket policy grants a named external AWS account",
            "T1530 Data from Cloud Storage",
            "Confirm the account is a partner you intend to trust; prefer a role in that account over :root.",
        ),
        Rule(
            "SPW004",
            "Service principal granted without aws:SourceArn or aws:SourceAccount",
            "T1530 Data from Cloud Storage",
            "Add aws:SourceArn or aws:SourceAccount so another customer's resource of the same service cannot use the "
            "grant (confused deputy).",
        ),
        Rule(
            "SPW005",
            "Policy could not be evaluated",
            "-",
            "The policy is computed at apply time, malformed, or not linked to a resource. Spillway fails closed: "
            "rescan the applied state (terraform show -json) or make the ARNs known at plan time.",
        ),
        Rule(
            "SPW006",
            "S3 Block Public Access explicitly turned off",
            "T1530 Data from Cloud Storage",
            "Set all four aws_s3_bucket_public_access_block settings to true unless the bucket must be public.",
        ),
        Rule(
            "SPW101",
            "Role trust policy lets principals outside your account assume the role",
            "T1078.004 Valid Accounts: Cloud Accounts",
            "Trust specific role ARNs, require sts:ExternalId for third parties, or restrict with aws:PrincipalOrgID.",
        ),
        Rule(
            "SPW102",
            "Cross-account role trust without sts:ExternalId or aws:PrincipalOrgID",
            "T1078.004 Valid Accounts: Cloud Accounts",
            "Third-party trust should require an sts:ExternalId to prevent confused-deputy role assumption.",
        ),
        Rule(
            "SPW103",
            "GitHub Actions OIDC trust not pinned to a repository",
            "T1078.004 Valid Accounts: Cloud Accounts",
            "Add a StringEquals/StringLike condition on token.actions.githubusercontent.com:sub naming your "
            "repository (and branch or environment), e.g. repo:my-org/my-repo:ref:refs/heads/main.",
        ),
        Rule(
            "SPW201",
            "Identity policy grants every action on every resource",
            "T1098 Account Manipulation",
            "Replace Action '*' with the specific actions the workload uses (IAM Access Analyzer can generate them).",
        ),
        Rule(
            "SPW202",
            "Identity policy grants a whole service on every resource",
            "T1098 Account Manipulation",
            "Scope the actions and the Resource ARNs to what the workload needs.",
        ),
        Rule(
            "SPW203",
            "iam:PassRole allowed on every role",
            "T1098 Account Manipulation",
            "Restrict iam:PassRole to the role ARNs the workload must pass and add iam:PassedToService.",
        ),
        Rule(
            "SPW204",
            "Allow statement uses NotAction",
            "T1098 Account Manipulation",
            "Allow + NotAction grants every action not listed, including ones AWS adds later. List actions instead.",
        ),
    )
}


@dataclass(frozen=True)
class Finding:
    rule_id: str
    severity: str
    address: str  # Terraform resource address the finding is anchored to
    message: str
    key: str = ""  # distinguishes several findings of one rule on one resource
    details: dict[str, str] = field(default_factory=dict, compare=False, hash=False)
    suppressed: str = field(default="", compare=False, hash=False)  # justification, if accepted in code

    @property
    def rule(self) -> Rule:
        return RULES[self.rule_id]

    @property
    def fingerprint(self) -> str:
        """Stable across plans, so a before/after diff can tell new findings from old ones."""
        raw = f"{self.rule_id}|{self.address}|{self.key}"
        return hashlib.sha256(raw.encode()).hexdigest()[:16]
