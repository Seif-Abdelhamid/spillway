"""Run every analyzer on the before and after snapshots and classify findings as new, existing or fixed."""

from __future__ import annotations

from dataclasses import dataclass

from spillway.findings import Finding, severity_rank
from spillway.iam import analyze_identity_policies, analyze_roles
from spillway.loader import Document, Snapshot
from spillway.s3 import analyze_buckets


def analyze_snapshot(snap: Snapshot, account_id: str | None = None) -> list[Finding]:
    findings = analyze_buckets(snap, account_id) + analyze_roles(snap, account_id) + analyze_identity_policies(snap)
    unique = {f.fingerprint: f for f in findings}
    return sorted(unique.values(), key=lambda f: (-severity_rank(f.severity), f.address, f.rule_id, f.key))


@dataclass
class Result:
    kind: str
    new: list[Finding]
    existing: list[Finding]
    fixed: list[Finding]

    @property
    def current(self) -> list[Finding]:
        return self.new + self.existing

    def gated(self, fail_on: str, gate: str) -> list[Finding]:
        """Findings that should fail the pipeline. Accepted (suppressed) findings never do."""
        if fail_on == "none":
            return []
        pool = self.new if gate == "new" else self.current
        return [f for f in pool if not f.suppressed and severity_rank(f.severity) >= severity_rank(fail_on)]


def analyze(doc: Document, account_id: str | None = None) -> Result:
    after = analyze_snapshot(doc.after, account_id)
    before = analyze_snapshot(doc.before, account_id) if doc.before.resources else []
    before_fp = {f.fingerprint for f in before}
    after_fp = {f.fingerprint for f in after}
    return Result(
        kind=doc.kind,
        new=[f for f in after if f.fingerprint not in before_fp],
        existing=[f for f in after if f.fingerprint in before_fp],
        fixed=[f for f in before if f.fingerprint not in after_fp],
    )
