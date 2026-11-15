import json

import pytest

from spillway.loader import InputError, load, parse_document
from tests.helpers import bucket, plan, res


def write(tmp_path, content, name="plan.json"):
    p = tmp_path / name
    p.write_text(content if isinstance(content, str) else json.dumps(content))
    return str(p)


def test_plan_splits_before_and_after(tmp_path):
    doc = plan(
        res("aws_s3_bucket.kept", {"bucket": "k"}, before={"bucket": "k"}),
        res("aws_s3_bucket.new", {"bucket": "n"}),
        res("aws_s3_bucket.gone", {"bucket": "g"}, before={"bucket": "g"}, actions=["delete"]),
        {"address": "data.aws_caller_identity.c", "mode": "data", "type": "aws_caller_identity", "change": {}},
    )
    d = load(write(tmp_path, doc))
    assert d.kind == "plan"
    assert set(d.before.resources) == {"aws_s3_bucket.kept", "aws_s3_bucket.gone"}
    assert set(d.after.resources) == {"aws_s3_bucket.kept", "aws_s3_bucket.new"}


def test_after_unknown_marks_computed_attributes():
    d = parse_document(plan(res("aws_s3_bucket_policy.p", {"bucket": "b"}, unknown={"policy": True, "x": {"y": True}})))
    r = d.after.resources["aws_s3_bucket_policy.p"]
    assert r.is_unknown("policy") and not r.is_unknown("x")


def test_state_document_with_child_modules():
    doc = {
        "format_version": "1.0",
        "values": {
            "root_module": {
                "resources": [
                    {"address": "aws_s3_bucket.a", "type": "aws_s3_bucket", "name": "a", "values": {"bucket": "a"}}
                ],
                "child_modules": [
                    {
                        "resources": [
                            {"address": "module.m.aws_s3_bucket.b", "type": "aws_s3_bucket", "name": "b", "values": {}},
                            {"address": "module.m.data.x.y", "mode": "data", "type": "x", "name": "y", "values": {}},
                        ]
                    }
                ],
            }
        },
    }
    d = parse_document(doc)
    assert d.kind == "state"
    assert set(d.after.resources) == {"aws_s3_bucket.a", "module.m.aws_s3_bucket.b"}
    assert d.before.resources == {}


def test_configuration_references_keep_module_prefixes_and_drop_variables():
    doc = plan(
        bucket(),
        config_resources=[
            {
                "address": "aws_s3_bucket_policy.p",
                "expressions": {"bucket": {"references": ["var.x", "aws_s3_bucket.b.id"]}},
            }
        ],
        module_calls={
            "m": {
                "module": {
                    "resources": [
                        {
                            "address": "aws_s3_bucket_acl.a",
                            "expressions": {"bucket": {"references": ["aws_s3_bucket.c[0]"]}},
                        }
                    ]
                }
            }
        },
    )
    refs = parse_document(doc).after.references
    assert refs["aws_s3_bucket_policy.p"]["bucket"] == ["aws_s3_bucket.b"]
    assert refs["module.m.aws_s3_bucket_acl.a"]["bucket"] == ["module.m.aws_s3_bucket.c"]


@pytest.mark.parametrize(
    ("content", "message"),
    [
        ("{not json", "invalid JSON"),
        ("[1, 2]", "top level"),
        ('{"resource_changes": []}', "format_version"),
        ('{"format_version": "1.0"}', "no resource_changes or values"),
        ('{"format_version": "1.0", "resource_changes": [{"address": "a"}]}', "malformed"),
        ('{"format_version": "1.0", "resource_changes": [{"type": "t", "change": {"after": {}}}]}', "address"),
        ("[" * 200_000 + "]" * 200_000, "nesting"),
    ],
)
def test_bad_input_raises_input_error(tmp_path, content, message):
    with pytest.raises(InputError, match=message):
        load(write(tmp_path, content))


def test_size_limit(tmp_path):
    path = write(tmp_path, plan())
    with pytest.raises(InputError, match="limit"):
        load(path, max_bytes=10)


def test_missing_file():
    with pytest.raises(InputError, match="cannot read"):
        load("/nonexistent/plan.json")
