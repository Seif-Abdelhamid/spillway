import pytest

from spillway.loader import parse_document
from spillway.s3 import ACCEPT_TAG, analyze_buckets
from tests.helpers import BUCKET, allow, bucket, bucket_policy, deny, pab, plan, policy, res


def scan(*changes, account_id=None, **kw):
    return analyze_buckets(parse_document(plan(*changes, **kw)).after, account_id)


def by_rule(findings, rule):
    return [f for f in findings if f.rule_id == rule]


def exposures(findings):
    return {(f.details["probe"], f.details["level"], f.severity) for f in by_rule(findings, "SPW001")}


def test_public_read_policy_is_high_for_both_outsider_probes():
    found = scan(bucket(), bucket_policy(policy(allow())))
    assert exposures(found) == {("anonymous", "read", "high"), ("any-aws-account", "read", "high")}


def test_public_write_and_admin_are_critical():
    doc = policy(
        allow(
            action=["s3:PutObject", "s3:PutBucketPolicy"],
            resource=[f"arn:aws:s3:::{BUCKET}", f"arn:aws:s3:::{BUCKET}/*"],
        )
    )
    found = scan(bucket(), bucket_policy(doc))
    assert ("anonymous", "write", "critical") in exposures(found)
    assert ("anonymous", "admin", "critical") in exposures(found)
    assert not any(level == "read" for _, level, _ in exposures(found))


def test_bucket_level_action_needs_the_bucket_arn_not_the_object_arn():
    found = scan(bucket(), bucket_policy(policy(allow(action="s3:ListBucket", resource=f"arn:aws:s3:::{BUCKET}/*"))))
    assert exposures(found) == set()


def test_deny_unless_in_my_org_removes_the_exposure():
    doc = policy(allow(), deny(Condition={"StringNotEquals": {"aws:PrincipalOrgID": "o-abc123"}}))
    assert exposures(scan(bucket(), bucket_policy(doc))) == set()


def test_deny_on_plain_http_does_not_remove_the_exposure():
    doc = policy(allow(), deny(Condition={"Bool": {"aws:SecureTransport": "false"}}))
    assert exposures(scan(bucket(), bucket_policy(doc)))


def test_deny_on_a_prefix_only_does_not_cancel_a_whole_bucket_grant():
    doc = policy(allow(), deny(resource=f"arn:aws:s3:::{BUCKET}/private/*"))
    assert exposures(scan(bucket(), bucket_policy(doc)))


def test_deny_with_not_principal_applies_to_outsiders():
    doc = policy(allow(), deny(principal=None, NotPrincipal={"AWS": "arn:aws:iam::111122223333:role/app"}))
    doc = doc.replace('"Principal": null, ', "")
    assert exposures(scan(bucket(), bucket_policy(doc))) == set()


def test_vpc_endpoint_condition_makes_a_star_principal_private():
    doc = policy(allow(Condition={"StringEquals": {"aws:SourceVpce": "vpce-1"}}))
    assert exposures(scan(bucket(), bucket_policy(doc))) == set()


def test_referer_condition_is_reported_as_spoofable():
    doc = policy(allow(Condition={"StringLike": {"aws:Referer": "https://example.com/*"}}))
    [finding, *_] = by_rule(scan(bucket(), bucket_policy(doc)), "SPW001")
    assert finding.severity == "high"
    assert "aws:Referer is set by the requester" in finding.message


def test_undecidable_condition_is_reported_as_conditional_one_level_lower():
    doc = policy(allow(action="s3:PutObject", Condition={"StringEquals": {"s3:x-amz-acl": "private"}}))
    found = by_rule(scan(bucket(), bucket_policy(doc)), "SPW001")
    assert {f.severity for f in found} == {"high"}
    assert all("conditional" in f.message for f in found)


def test_sure_grant_wins_over_a_conditional_one():
    doc = policy(
        allow(sid="Cond", Condition={"StringEquals": {"s3:ExistingObjectTag/x": "y"}}),
        allow(sid="Open"),
    )
    [f, *_] = by_rule(scan(bucket(), bucket_policy(doc)), "SPW001")
    assert f.severity == "high" and "via Open" in f.message and "conditional" not in f.message


def test_prefix_grant_reports_the_prefix():
    doc = policy(allow(resource=f"arn:aws:s3:::{BUCKET}/public/*"))
    [f, *_] = by_rule(scan(bucket(), bucket_policy(doc)), "SPW001")
    assert "keys under public/" in f.message
    assert f.details["scope"] == "public/"


def test_restrict_public_buckets_neutralizes_policy_grants():
    found = scan(bucket(), bucket_policy(policy(allow())), pab())
    assert exposures(found) == set()
    assert by_rule(found, "SPW006") == []


def test_block_public_policy_alone_adds_a_note_and_turned_off_flags_are_reported():
    found = scan(bucket(), bucket_policy(policy(allow())), pab(restrict_public_buckets=False))
    assert all("BlockPublicPolicy" in f.message for f in by_rule(found, "SPW001"))
    [off] = by_rule(found, "SPW006")
    assert "restrict_public_buckets" in off.message


def test_account_level_block_public_access_applies_to_every_bucket():
    account_pab = res("aws_s3_account_public_access_block.this", {"restrict_public_buckets": True})
    assert exposures(scan(bucket(), bucket_policy(policy(allow())), account_pab)) == set()


@pytest.mark.parametrize(
    ("acl", "expected"),
    [
        ("public-read", {("anonymous", "read"), ("any-aws-account", "read")}),
        ("public-read-write", {(p, lv) for p in ("anonymous", "any-aws-account") for lv in ("read", "write")}),
        ("authenticated-read", {("any-aws-account", "read")}),
        ("private", set()),
    ],
)
def test_canned_acls(acl, expected):
    found = scan(bucket(), res("aws_s3_bucket_acl.b", {"bucket": BUCKET, "acl": acl}))
    assert {tuple(f.key.split(":")) for f in by_rule(found, "SPW002")} == expected


def test_legacy_inline_acl_on_the_bucket_resource():
    assert by_rule(scan(bucket(acl="public-read")), "SPW002")


def test_explicit_acl_grant_to_all_users():
    acp = [
        {
            "grant": [
                {
                    "permission": "WRITE",
                    "grantee": [{"type": "Group", "uri": "http://acs.amazonaws.com/groups/global/AllUsers"}],
                },
                {"permission": "READ", "grantee": [{"type": "CanonicalUser", "id": "abc"}]},
            ]
        }
    ]
    found = by_rule(
        scan(bucket(), res("aws_s3_bucket_acl.b", {"bucket": BUCKET, "access_control_policy": acp})), "SPW002"
    )
    assert {f.key for f in found} == {"anonymous:write", "any-aws-account:write"}
    assert {f.severity for f in found} == {"critical"}


def test_acls_ignored_when_ownership_is_enforced_or_ignore_public_acls():
    acl = res("aws_s3_bucket_acl.b", {"bucket": BUCKET, "acl": "public-read"})
    owner = res(
        "aws_s3_bucket_ownership_controls.b", {"bucket": BUCKET, "rule": [{"object_ownership": "BucketOwnerEnforced"}]}
    )
    assert by_rule(scan(bucket(), acl, owner), "SPW002") == []
    assert by_rule(scan(bucket(), acl, pab()), "SPW002") == []


def test_policy_known_only_after_apply_fails_closed():
    pol = res("aws_s3_bucket_policy.p", {"bucket": BUCKET}, unknown={"policy": True})
    [f] = scan(bucket(), pol)
    assert (f.rule_id, f.severity) == ("SPW005", "medium")


def test_malformed_policy_fails_closed():
    [f] = scan(bucket(), bucket_policy('{"Statement": [{"Effect": "Allow"}]}'))
    assert f.rule_id == "SPW005" and "could not be parsed" in f.message


def test_policy_with_no_linkable_bucket_fails_closed():
    [f] = scan(bucket_policy(policy(allow(resource="*")), bucket_name=None))
    assert f.rule_id == "SPW005"


def test_link_by_configuration_reference_when_bucket_name_is_computed():
    b = res("aws_s3_bucket.b", {"bucket_prefix": "logs-"}, unknown={"bucket": True})
    pol = res(
        "aws_s3_bucket_policy.p", {"policy": policy(allow(resource="arn:aws:s3:::logs-x/*"))}, unknown={"bucket": True}
    )
    config = [
        {
            "address": "aws_s3_bucket_policy.p",
            "expressions": {"bucket": {"references": ["aws_s3_bucket.b.id", "aws_s3_bucket.b"]}},
        }
    ]
    found = scan(b, pol, config_resources=config)
    assert by_rule(found, "SPW001")
    assert by_rule(found, "SPW001")[0].details["bucket"] == "logs-x"


def test_count_indexed_resources_pair_by_index():
    b0 = bucket("a", address="aws_s3_bucket.b[0]")
    b1 = bucket("b", address="aws_s3_bucket.b[1]")
    pol = res(
        "aws_s3_bucket_policy.p[1]", {"policy": policy(allow(resource="arn:aws:s3:::b/*"))}, unknown={"bucket": True}
    )
    acl = res("aws_s3_bucket_acl.a[0]", {"acl": "public-read"}, unknown={"bucket": True})
    config = [
        {
            "address": "aws_s3_bucket_policy.p",
            "expressions": {"bucket": {"references": ["aws_s3_bucket.b[count.index]", "aws_s3_bucket.b"]}},
        },
        {"address": "aws_s3_bucket_acl.a", "expressions": {"bucket": {"references": ["aws_s3_bucket.b"]}}},
    ]
    found = scan(b0, b1, pol, acl, config_resources=config)
    assert {f.details["bucket"] for f in by_rule(found, "SPW001")} == {"b"}
    assert {f.address for f in by_rule(found, "SPW002")} == {"aws_s3_bucket.b[0]"}


def test_named_external_account_is_info_without_account_id_and_medium_with_it():
    doc = policy(allow(principal={"AWS": ["arn:aws:iam::999988887777:root", "111122223333"]}))
    found = by_rule(scan(bucket(), bucket_policy(doc)), "SPW003")
    assert {(f.severity, f.key.split(":")[0]) for f in found} == {("info", "999988887777"), ("info", "111122223333")}
    found = by_rule(scan(bucket(), bucket_policy(doc), account_id="111122223333"), "SPW003")
    assert [(f.severity, f.key.split(":")[0]) for f in found] == [("medium", "999988887777")]


def test_service_principal_without_source_condition_is_a_confused_deputy_risk():
    svc = {"Service": "cloudfront.amazonaws.com"}
    found = scan(bucket(), bucket_policy(policy(allow(principal=svc))))
    assert [f.rule_id for f in found] == ["SPW004"]
    guarded = allow(
        principal=svc, Condition={"StringEquals": {"AWS:SourceArn": "arn:aws:cloudfront::1:distribution/E1"}}
    )
    assert scan(bucket(), bucket_policy(policy(guarded))) == []


def test_accept_tag_suppresses_public_read_but_never_write():
    tagged = bucket(tags={ACCEPT_TAG: "public website assets, reviewed by security"})
    doc = policy(allow(action=["s3:GetObject", "s3:PutObject"]))
    found = by_rule(scan(tagged, bucket_policy(doc)), "SPW001")
    assert {f.details["level"]: bool(f.suppressed) for f in found} == {"read": True, "write": False}


def test_accept_tag_needs_a_real_justification():
    tagged = bucket(tags={ACCEPT_TAG: "ok"})
    found = by_rule(scan(tagged, bucket_policy(policy(allow()))), "SPW001")
    assert not any(f.suppressed for f in found)
