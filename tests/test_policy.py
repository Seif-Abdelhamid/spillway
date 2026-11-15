import json

import pytest

from spillway.policy import (
    MAX_POLICY_BYTES,
    PolicyError,
    account_of,
    action_matches,
    glob_match,
    object_scope,
    parse_policy,
)
from tests.helpers import BUCKET, allow, policy


def test_parses_single_statement_object_and_string_fields():
    doc = json.dumps({"Statement": {"Effect": "Allow", "Principal": "*", "Action": "s3:GetObject", "Resource": "*"}})
    [stmt] = parse_policy(doc)
    assert stmt.effect == "Allow"
    assert stmt.principal.wildcard
    assert stmt.actions == ("s3:GetObject",)
    assert stmt.sid == "#0"


def test_aws_wildcard_principal_is_the_same_as_star():
    [stmt] = parse_policy(policy(allow(principal={"AWS": ["*", "arn:aws:iam::111122223333:root"]})))
    assert stmt.principal.wildcard
    assert stmt.principal.aws == ("arn:aws:iam::111122223333:root",)


def test_condition_values_are_normalized_to_strings():
    [stmt] = parse_policy(policy(allow(Condition={"Bool": {"aws:SecureTransport": True}, "NumericLessThan": {"x": 5}})))
    assert stmt.conditions == {"Bool": {"aws:SecureTransport": ("true",)}, "NumericLessThan": {"x": ("5",)}}


@pytest.mark.parametrize(
    "doc",
    [
        "not json",
        "[]",
        json.dumps({"Statement": "nope"}),
        json.dumps({"Statement": [{"Effect": "Maybe", "Action": "*"}]}),
        json.dumps({"Statement": [{"Effect": "Allow"}]}),
        json.dumps({"Statement": [{"Effect": "Allow", "Action": 7}]}),
        json.dumps({"Statement": [{"Effect": "Allow", "Action": "*", "Principal": {"Martian": "x"}}]}),
        json.dumps({"Statement": [{"Effect": "Allow", "Action": "*", "Condition": {"StringEquals": "x"}}]}),
        json.dumps({"Statement": [{"Effect": "Allow", "Action": "*", "Condition": {"StringEquals": {"k": [{}]}}}]}),
        "[" * 100_000 + "]" * 100_000,
    ],
)
def test_malformed_or_hostile_policies_raise_policy_error(doc):
    with pytest.raises(PolicyError):
        parse_policy(doc)


def test_oversized_policy_is_refused_before_parsing():
    with pytest.raises(PolicyError, match="larger than"):
        parse_policy(" " * (MAX_POLICY_BYTES + 1))


def test_glob_semantics():
    assert glob_match("arn:aws:s3:::b/*", "arn:aws:s3:::b/x/y")
    assert glob_match("s3:Get?bject", "s3:GetObject")
    assert not glob_match("arn:aws:s3:::b", "arn:aws:s3:::b/x")
    assert not glob_match("a.c", "abc"), "regex metacharacters are literal"


def test_actions_are_case_insensitive_and_not_action_inverts():
    [stmt] = parse_policy(policy(allow(action="S3:get*")))
    assert action_matches(stmt, "s3:GetObject")
    [stmt] = parse_policy(policy({"Effect": "Allow", "NotAction": "iam:*", "Resource": "*"}))
    assert action_matches(stmt, "s3:PutObject")
    assert not action_matches(stmt, "iam:PassRole")


@pytest.mark.parametrize(
    ("resource", "scope"),
    [
        (f"arn:aws:s3:::{BUCKET}/*", "*"),
        ("arn:aws:s3:::*", "*"),
        ("*", "*"),
        (f"arn:aws:s3:::{BUCKET}/public/*", "public/"),
        ([f"arn:aws:s3:::{BUCKET}/a/*", f"arn:aws:s3:::{BUCKET}/b/*"], "a/, b/"),
        (f"arn:aws:s3:::{BUCKET}/exact.txt", "exact.txt"),
        (f"arn:aws:s3:::{BUCKET}", None),
        ("arn:aws:s3:::other-bucket/*", None),
    ],
)
def test_object_scope(resource, scope):
    [stmt] = parse_policy(policy(allow(resource=resource)))
    assert object_scope(stmt, BUCKET) == scope


def test_object_scope_with_not_resource():
    [stmt] = parse_policy(policy({"Effect": "Allow", "Principal": "*", "Action": "*", "NotResource": "arn:aws:s3:::x"}))
    assert object_scope(stmt, BUCKET) == "*"


def test_account_of():
    assert account_of("111122223333") == "111122223333"
    assert account_of("arn:aws:iam::111122223333:role/x") == "111122223333"
    assert account_of("arn:aws-us-gov:iam::111122223333:root") == "111122223333"
    assert account_of("arn:aws:iam::cloudfront:user/x") is None
