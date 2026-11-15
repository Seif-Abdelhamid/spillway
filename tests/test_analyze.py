from spillway.analyze import analyze
from spillway.loader import parse_document
from tests.helpers import BUCKET, allow, bucket, bucket_policy, plan, policy, res

PUBLIC = policy(allow())


def test_new_existing_and_fixed_are_separated():
    doc = plan(
        bucket(),
        # Existing public read stays; a new public write is added.
        bucket_policy(
            policy(allow(action=["s3:GetObject", "s3:PutObject"])), before={"bucket": BUCKET, "policy": PUBLIC}
        ),
        # An admin-wildcard identity policy is being scoped down.
        res(
            "aws_iam_policy.p",
            {"policy": policy(allow(principal=None, action="s3:GetObject", resource="*"))},
            before={"policy": policy(allow(principal=None, action="*", resource="*"))},
        ),
    )
    result = analyze(parse_document(doc))
    assert {f.details["level"] for f in result.new if f.rule_id == "SPW001"} == {"write"}
    assert {f.details["level"] for f in result.existing if f.rule_id == "SPW001"} == {"read"}
    assert [f.rule_id for f in result.fixed] == ["SPW201"]


def test_gate_modes_and_thresholds():
    doc = plan(
        bucket(), bucket_policy(policy(allow(action="s3:PutObject")), before={"bucket": BUCKET, "policy": PUBLIC})
    )
    result = analyze(parse_document(doc))
    assert {f.severity for f in result.gated("critical", "new")} == {"critical"}
    assert result.gated("critical", "all") == result.gated("critical", "new")
    assert result.gated("none", "all") == []
    assert len(result.gated("info", "all")) == len(result.current)


def test_existing_findings_do_not_fail_the_new_gate():
    doc = plan(bucket(), bucket_policy(PUBLIC, before={"bucket": BUCKET, "policy": PUBLIC}))
    result = analyze(parse_document(doc))
    assert result.new == [] and result.existing
    assert result.gated("high", "new") == []
    assert result.gated("high", "all")


def test_accepted_findings_never_gate():
    tagged = bucket(tags={"spillway:accept-public-read": "static website, approved in SEC-42"})
    result = analyze(parse_document(plan(tagged, bucket_policy(PUBLIC))))
    assert result.new and result.gated("info", "all") == []


def test_results_are_sorted_most_severe_first_and_deduplicated():
    doc = plan(bucket(), bucket_policy(policy(allow(sid="A"), allow(sid="B", action="s3:PutObject"))))
    sev = [f.severity for f in analyze(parse_document(doc)).current]
    assert sev == sorted(sev, key=["info", "low", "medium", "high", "critical"].index, reverse=True)
    fps = [f.fingerprint for f in analyze(parse_document(doc)).current]
    assert len(fps) == len(set(fps))
