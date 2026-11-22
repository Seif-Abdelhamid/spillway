"""Build minimal `terraform show -json` documents in the documented plan/state formats."""

from __future__ import annotations

import json

BUCKET = "data-bucket"


def policy(*statements: dict) -> str:
    return json.dumps({"Version": "2012-10-17", "Statement": list(statements)})


def allow(principal="*", action="s3:GetObject", resource=f"arn:aws:s3:::{BUCKET}/*", sid="S", **extra) -> dict:
    stmt = {"Sid": sid, "Effect": "Allow", "Action": action, "Resource": resource}
    if principal is not None:
        stmt["Principal"] = principal
    stmt.update(extra)
    return stmt


def deny(principal="*", action="s3:*", resource=None, sid="D", **extra) -> dict:
    stmt = {
        "Sid": sid,
        "Effect": "Deny",
        "Principal": principal,
        "Action": action,
        "Resource": resource or [f"arn:aws:s3:::{BUCKET}", f"arn:aws:s3:::{BUCKET}/*"],
    }
    stmt.update(extra)
    return stmt


def res(address: str, values: dict, unknown: dict | None = None, before: dict | None = None, actions=None) -> dict:
    rtype, name = address.split(".")[-2:]
    name = name.split("[")[0]
    return {
        "address": address,
        "mode": "managed",
        "type": rtype,
        "name": name,
        "change": {
            "actions": actions or (["update"] if before is not None else ["create"]),
            "before": before,
            "after": values,
            "after_unknown": unknown or {},
        },
    }


def bucket(name: str = BUCKET, address: str = "aws_s3_bucket.b", **values) -> dict:
    return res(address, {"bucket": name, **values})


def bucket_policy(doc: str, bucket_name: str | None = BUCKET, address="aws_s3_bucket_policy.p", **kw) -> dict:
    values = {"policy": doc}
    if bucket_name is not None:
        values["bucket"] = bucket_name
    return res(address, values, **kw)


def pab(**flags) -> dict:
    values = {
        "bucket": BUCKET,
        "block_public_acls": True,
        "ignore_public_acls": True,
        "block_public_policy": True,
        "restrict_public_buckets": True,
    }
    values.update(flags)
    return res("aws_s3_bucket_public_access_block.b", values)


def plan(*changes: dict, config_resources: list | None = None, module_calls: dict | None = None) -> dict:
    doc = {"format_version": "1.2", "terraform_version": "1.9.8", "resource_changes": list(changes)}
    if config_resources is not None or module_calls is not None:
        doc["configuration"] = {
            "root_module": {"resources": config_resources or [], "module_calls": module_calls or {}}
        }
    return doc
