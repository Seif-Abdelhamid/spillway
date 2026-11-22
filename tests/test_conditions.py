import pytest

from spillway.conditions import ANONYMOUS, ANY_AWS_ACCOUNT, attacker_controlled, evaluate_conditions, evaluate_operator
from spillway.tri import Tri, tri_and, tri_or

BOTH = (ANONYMOUS, ANY_AWS_ACCOUNT)


@pytest.mark.parametrize("probe", BOTH)
@pytest.mark.parametrize(
    ("op", "key", "values", "expected"),
    [
        # Network origin: outsiders are never in your VPC endpoint or IP range.
        ("StringEquals", "aws:SourceVpce", ("vpce-1",), Tri.FALSE),
        ("IpAddress", "aws:SourceIp", ("203.0.113.0/24",), Tri.FALSE),
        ("IpAddress", "aws:SourceIp", ("0.0.0.0/0",), Tri.TRUE),
        ("IpAddress", "aws:SourceIp", ("::/0",), Tri.TRUE),
        ("NotIpAddress", "aws:SourceIp", ("203.0.113.0/24",), Tri.TRUE),
        ("IpAddress", "aws:SourceIp", ("not-an-ip",), Tri.UNKNOWN),
        # Org membership: a negated check matches outsiders, which is what makes Deny-unless-org work.
        ("StringNotEquals", "aws:PrincipalOrgID", ("o-abc123",), Tri.TRUE),
        ("StringEquals", "aws:PrincipalOrgID", ("o-abc123",), Tri.FALSE),
        # Requester-chosen keys are not access control.
        ("StringLike", "aws:Referer", ("https://example.com/*",), Tri.TRUE),
        ("StringNotLike", "aws:Referer", ("https://example.com/*",), Tri.TRUE),
        ("StringEquals", "aws:UserAgent", ("internal-app",), Tri.TRUE),
        # Attackers use HTTPS.
        ("Bool", "aws:SecureTransport", ("false",), Tri.FALSE),
        ("Bool", "aws:SecureTransport", ("true",), Tri.TRUE),
        # Service-to-service keys are absent for a direct caller.
        ("ArnLike", "aws:SourceArn", ("arn:aws:cloudfront::1:distribution/*",), Tri.FALSE),
        ("StringEqualsIfExists", "aws:SourceAccount", ("111122223333",), Tri.TRUE),
        ("Null", "aws:SourceArn", ("true",), Tri.TRUE),
        ("Null", "aws:SourceArn", ("false",), Tri.FALSE),
        # What Spillway cannot model is UNKNOWN, never silently safe.
        ("ForAnyValue:StringEquals", "aws:TagKeys", ("x",), Tri.UNKNOWN),
        ("StringEquals", "s3:prefix", ("home/",), Tri.UNKNOWN),
        ("DateLessThan", "aws:SourceIp", ("2030-01-01",), Tri.UNKNOWN),
    ],
)
def test_operator_semantics(probe, op, key, values, expected):
    assert evaluate_operator(op, key, values, probe) is expected


def test_principal_keys_differ_between_anonymous_and_authenticated():
    # aws:PrincipalArn is absent for anonymous requests and some unknown ARN for an external account.
    assert evaluate_operator("StringLike", "aws:PrincipalArn", ("*",), ANONYMOUS) is Tri.FALSE
    assert evaluate_operator("StringLike", "aws:PrincipalArn", ("*",), ANY_AWS_ACCOUNT) is Tri.TRUE
    assert evaluate_operator("ArnLike", "aws:PrincipalArn", ("arn:aws:iam::*:role/x",), ANY_AWS_ACCOUNT) is Tri.UNKNOWN
    assert evaluate_operator("StringEquals", "aws:PrincipalAccount", ("1",), ANY_AWS_ACCOUNT) is Tri.FALSE
    assert evaluate_operator("NumericEquals", "aws:PrincipalAccount", ("1",), ANY_AWS_ACCOUNT) is Tri.UNKNOWN


def test_key_names_are_case_insensitive():
    assert evaluate_operator("StringEquals", "AWS:SOURCEVPCE", ("vpce-1",), ANONYMOUS) is Tri.FALSE


def test_blocks_are_anded():
    cond = {"StringLike": {"aws:Referer": ("x",)}, "StringEquals": {"aws:SourceVpce": ("vpce-1",)}}
    assert evaluate_conditions(cond, ANONYMOUS) is Tri.FALSE
    assert evaluate_conditions({}, ANONYMOUS) is Tri.TRUE


def test_attacker_controlled_keys():
    cond = {"StringLike": {"aws:Referer": ("x",)}, "StringEquals": {"aws:SourceVpce": ("v",)}}
    assert attacker_controlled(cond, ANONYMOUS) == ["aws:Referer"]


def test_three_valued_logic():
    assert tri_and([Tri.TRUE, Tri.UNKNOWN]) is Tri.UNKNOWN
    assert tri_and([Tri.UNKNOWN, Tri.FALSE]) is Tri.FALSE
    assert tri_or([Tri.FALSE, Tri.UNKNOWN]) is Tri.UNKNOWN
    assert tri_or([Tri.UNKNOWN, Tri.TRUE]) is Tri.TRUE
    assert ~Tri.UNKNOWN is Tri.UNKNOWN
    assert ~Tri.TRUE is Tri.FALSE
