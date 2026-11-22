"""Command-line entry point.

Exit codes: 0 = gate passed, 1 = gate failed, 2 = the input could not be analyzed
(fail closed: a broken plan never looks like a clean one).
"""

from __future__ import annotations

import argparse
import re
import sys

from spillway import __version__
from spillway.analyze import analyze
from spillway.findings import SEVERITIES
from spillway.loader import DEFAULT_MAX_BYTES, InputError, load
from spillway.locate import index_sources
from spillway.report import to_json, to_sarif, to_text


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="spillway",
        description="Who can reach your S3 buckets and IAM roles after this Terraform change?",
    )
    p.add_argument("--version", action="version", version=f"spillway {__version__}")
    p.add_argument("input", help="output of `terraform show -json tfplan` (or of `terraform show -json` for state)")
    p.add_argument("--format", choices=("text", "json", "sarif"), default="text")
    p.add_argument("--output", "-o", help="write the report here instead of stdout")
    p.add_argument("--fail-on", choices=(*SEVERITIES, "none"), default="high", help="lowest severity that fails")
    p.add_argument(
        "--gate",
        choices=("new", "all"),
        default="new",
        help="fail only on findings this change introduces (default) or on every current finding",
    )
    p.add_argument("--account-id", help="your 12-digit AWS account ID, to tell own accounts from external ones")
    p.add_argument(
        "--tf-dir",
        help="Terraform root module directory: adds file:line locations to SARIF and lets Spillway read policies "
        "the plan leaves unknown until apply",
    )
    p.add_argument("--max-bytes", type=int, default=DEFAULT_MAX_BYTES, help=argparse.SUPPRESS)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.account_id is not None and not re.fullmatch(r"\d{12}", args.account_id):
        print("spillway: --account-id must be 12 digits", file=sys.stderr)
        return 2
    try:
        doc = load(args.input, args.max_bytes)
    except InputError as exc:
        print(f"spillway: {exc}", file=sys.stderr)
        return 2

    result = analyze(doc, args.account_id, tf_dir=args.tf_dir)
    gated = result.gated(args.fail_on, args.gate)
    if args.format == "json":
        report = to_json(result, gated)
    elif args.format == "sarif":
        report = to_sarif(result, args.input, index_sources(args.tf_dir) if args.tf_dir else None)
    else:
        report = to_text(result, gated)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(report)
        if args.format != "text":
            print(to_text(result, gated), end="")
    else:
        print(report, end="" if report.endswith("\n") else "\n")
    return 1 if gated else 0
