"""Policies that the plan shows as "known after apply" are recovered from the .tf source when possible."""

import json

import pytest

from spillway.analyze import analyze
from spillway.loader import parse_document
from spillway.source import SourceError, parse_hcl_value, recover_policies
from tests.helpers import bucket, plan, res

ACCT = "123456789012"

RISKY_TF = """
data "aws_caller_identity" "me" {}

resource "aws_s3_bucket" "shares" { bucket = "shares-bucket" }

# comment with jsonencode( and } braces that must not confuse the scanner
resource "aws_s3_bucket_policy" "shares" {
  bucket = aws_s3_bucket.shares.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "ShareLinksFromOurSite"
      Effect    = "Allow"
      Principal = "*"
      Action    = "s3:GetObject"
      Resource  = "${aws_s3_bucket.shares.arn}/shared/*"
      Condition = { StringLike = { "aws:Referer" = "https://example.com/*" } }
    }]
  })
}
"""


def _plan_with_unknown_policy(bucket_name="shares-bucket"):
    return plan(
        bucket(bucket_name, address="aws_s3_bucket.shares"),
        res("aws_s3_bucket_policy.shares", {}, unknown={"policy": True, "bucket": True}),
    )


def _write(tmp_path, text):
    (tmp_path / "main.tf").write_text(text)
    return str(tmp_path)


def _findings(doc, tf_dir, account_id=ACCT):
    return {(f.rule_id, f.address): f for f in analyze(doc, account_id, tf_dir=tf_dir).current}


def test_unknown_bucket_policy_is_recovered_and_public_read_is_found(tmp_path):
    doc = parse_document(_plan_with_unknown_policy())
    found = _findings(doc, _write(tmp_path, RISKY_TF))
    assert ("SPW005", "aws_s3_bucket_policy.shares") not in found
    f = found[("SPW001", "aws_s3_bucket_policy.shares")]
    assert "s3://shares-bucket" in f.message
    assert "aws:referer" in f.message.lower()  # the spoofable Referer note still applies
    assert "read from the .tf source" in f.message


def test_without_tf_dir_it_still_fails_closed(tmp_path):
    doc = parse_document(_plan_with_unknown_policy())
    found = {(f.rule_id, f.address) for f in analyze(doc, ACCT).current}
    assert ("SPW005", "aws_s3_bucket_policy.shares") in found


def test_unresolvable_reference_keeps_spw005(tmp_path):
    tf = RISKY_TF.replace('"*"\n      Action', "var.reader_arn\n      Action")
    doc = parse_document(_plan_with_unknown_policy())
    found = _findings(doc, _write(tmp_path, tf))
    assert ("SPW005", "aws_s3_bucket_policy.shares") in found
    assert ("SPW001", "aws_s3_bucket_policy.shares") not in found


def test_unknown_bucket_name_keeps_spw005(tmp_path):
    doc = parse_document(
        plan(
            res("aws_s3_bucket.shares", {}, unknown={"bucket": True}),
            res("aws_s3_bucket_policy.shares", {}, unknown={"policy": True}),
        )
    )
    found = _findings(doc, _write(tmp_path, RISKY_TF))
    assert ("SPW005", "aws_s3_bucket_policy.shares") in found


def test_resource_with_count_is_not_guessed(tmp_path):
    head = 'resource "aws_s3_bucket_policy" "shares" {'
    tf = RISKY_TF.replace(head, head + "\n  count = 1")
    doc = parse_document(
        plan(
            bucket("shares-bucket", address="aws_s3_bucket.shares"),
            res("aws_s3_bucket_policy.shares[0]", {}, unknown={"policy": True}),
        )
    )
    found = _findings(doc, _write(tmp_path, tf))
    assert ("SPW005", "aws_s3_bucket_policy.shares[0]") in found


def test_heredoc_policy_with_interpolation(tmp_path):
    tf = """
resource "aws_s3_bucket_policy" "shares" {
  bucket = aws_s3_bucket.shares.id
  policy = <<-EOT
    {"Version": "2012-10-17", "Statement": [{"Sid": "Pub", "Effect": "Allow", "Principal": "*",
      "Action": "s3:GetObject", "Resource": "${aws_s3_bucket.shares.arn}/*"}]}
  EOT
}
"""
    doc = parse_document(_plan_with_unknown_policy())
    found = _findings(doc, _write(tmp_path, tf))
    assert ("SPW001", "aws_s3_bucket_policy.shares") in found


OIDC_PROVIDER = (
    "arn:aws:iam::${data.aws_caller_identity.me.account_id}:oidc-provider/token.actions.githubusercontent.com"
)
TRUST_TF = """
data "aws_caller_identity" "me" {}
resource "aws_iam_role" "deploy" {
  name = "deploy"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Federated = "OIDC_PROVIDER" }
      Action    = "sts:AssumeRoleWithWebIdentity"
      Condition = { StringLike = { "token.actions.githubusercontent.com:sub" = "repo:*" } }
    }]
  })
}
""".replace("OIDC_PROVIDER", OIDC_PROVIDER)


def test_unknown_trust_policy_recovered_with_account_id(tmp_path):
    doc = parse_document(plan(res("aws_iam_role.deploy", {"name": "deploy"}, unknown={"assume_role_policy": True})))
    found = _findings(doc, _write(tmp_path, TRUST_TF))
    assert ("SPW103", "aws_iam_role.deploy") in found
    # Without the account ID the data source cannot be resolved, so it stays fail-closed.
    found = _findings(doc, str(tmp_path), account_id=None)
    assert ("SPW005", "aws_iam_role.deploy") in found


def test_hcl_value_parser_handles_the_subset():
    value = parse_hcl_value(
        '{ a = "x", "b:c" = [1, 2.5, true, null], d = { e = "${x}" } /* c */ }', lambda expr: f"<{expr}>"
    )
    assert value == {"a": "x", "b:c": [1, 2.5, True, None], "d": {"e": "<x>"}}


@pytest.mark.parametrize(
    "text",
    [
        "{ a = " * 200 + "1" + " }" * 200,  # hostile nesting
        '{ a = "unterminated }',
        '{ a = "%{ if true }x%{ endif }" }',  # template directives are not evaluated
        '{ a = upper("x") }',  # function calls are not evaluated
    ],
)
def test_hcl_parser_rejects_what_it_cannot_evaluate(text):
    with pytest.raises(SourceError):
        parse_hcl_value(text, lambda expr: None)


def test_recovered_json_is_valid_policy_json(tmp_path):
    doc = parse_document(_plan_with_unknown_policy())
    snap = recover_policies(doc.after, _write(tmp_path, RISKY_TF), ACCT)
    pol = snap.resources["aws_s3_bucket_policy.shares"]
    assert not pol.is_unknown("policy")
    assert "policy" in pol.from_source
    stmt = json.loads(pol.get("policy"))["Statement"][0]
    assert stmt["Resource"] == "arn:aws:s3:::shares-bucket/shared/*"
