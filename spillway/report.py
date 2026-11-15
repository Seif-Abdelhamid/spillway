"""Text, JSON and SARIF 2.1.0 output.

Resource addresses, Sids and bucket names come from the (untrusted) plan. Text output strips
control characters and newlines so a crafted Sid cannot inject terminal escape sequences or
GitHub Actions workflow commands (which must start at the beginning of a log line).
"""

from __future__ import annotations

import json
import re

from spillway import __version__
from spillway.analyze import Result
from spillway.findings import RULES, Finding
from spillway.locate import locate

_CONTROL = re.compile("[\\x00-\\x1f\\x7f-\\x9f\\u2028\\u2029]")
SARIF_LEVEL = {"critical": "error", "high": "error", "medium": "warning", "low": "note", "info": "note"}
SECURITY_SEVERITY = {"critical": "9.5", "high": "8.0", "medium": "5.5", "low": "3.0", "info": "1.0"}


def clean(text: str) -> str:
    return _CONTROL.sub(" ", text)


def _line(f: Finding, tag: str) -> str:
    accepted = f"  [accepted in code: {clean(f.suppressed)}]" if f.suppressed else ""
    return f"  {tag:<5} {f.severity.upper():<8} {f.rule_id}  {clean(f.address)}\n        {clean(f.message)}{accepted}"


def to_text(result: Result, gated: list[Finding]) -> str:
    out = [f"spillway {__version__}: analyzed a Terraform {result.kind}"]
    for title, items, tag in (("New in this change", result.new, "NEW"), ("Already present", result.existing, "OLD")):
        if items:
            out.append(f"\n{title} ({len(items)}):")
            out += [_line(f, tag) for f in items]
    if result.fixed:
        out.append(f"\nFixed by this change ({len(result.fixed)}):")
        out += [_line(f, "FIXED") for f in result.fixed]
    if not result.current and not result.fixed:
        out.append("\nNo findings.")
    out.append(f"\nGate: {'FAIL' if gated else 'pass'} ({len(gated)} finding(s) at or above the threshold)")
    return "\n".join(out) + "\n"


def _finding_dict(f: Finding, status: str) -> dict:
    return {
        "rule": f.rule_id,
        "title": f.rule.title,
        "severity": f.severity,
        "status": status,
        "address": f.address,
        "message": f.message,
        "attack": f.rule.attack,
        "fingerprint": f.fingerprint,
        "details": f.details,
        "accepted": f.suppressed or None,
    }


def to_json(result: Result, gated: list[Finding]) -> str:
    findings = (
        [_finding_dict(f, "new") for f in result.new]
        + [_finding_dict(f, "existing") for f in result.existing]
        + [_finding_dict(f, "fixed") for f in result.fixed]
    )
    return json.dumps(
        {
            "tool": "spillway",
            "version": __version__,
            "kind": result.kind,
            "gate_failed": bool(gated),
            "findings": findings,
        },
        indent=2,
    )


def to_sarif(result: Result, plan_uri: str, locations: dict[str, tuple[str, int]] | None = None) -> str:
    locations = locations or {}
    used = sorted({f.rule_id for f in result.current})
    rules = [
        {
            "id": rid,
            "name": rid,
            "shortDescription": {"text": RULES[rid].title},
            "help": {"text": RULES[rid].help},
            "properties": {"tags": ["security", "terraform", "aws"], "attack": RULES[rid].attack},
        }
        for rid in used
    ]
    results = []
    for f in result.current:
        loc = locate(f.address, locations)
        physical = (
            {"artifactLocation": {"uri": loc[0]}, "region": {"startLine": loc[1]}}
            if loc
            else {"artifactLocation": {"uri": plan_uri}}
        )
        entry = {
            "ruleId": f.rule_id,
            "ruleIndex": used.index(f.rule_id),
            "level": SARIF_LEVEL[f.severity],
            "message": {"text": f"{f.address}: {f.message}"},
            "locations": [
                {
                    "physicalLocation": physical,
                    "logicalLocations": [{"fullyQualifiedName": f.address, "kind": "resource"}],
                }
            ],
            "partialFingerprints": {"spillway/v1": f.fingerprint},
            "properties": {"security-severity": SECURITY_SEVERITY[f.severity], "new": f in result.new},
        }
        if f.suppressed:
            entry["suppressions"] = [{"kind": "inSource", "justification": f.suppressed}]
        results.append(entry)
    sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "spillway",
                        "version": __version__,
                        "informationUri": "https://github.com/Seif-Abdelhamid/spillway",
                        "rules": rules,
                    }
                },
                "results": results,
            }
        ],
    }
    return json.dumps(sarif, indent=2)
