"""Evaluate IAM Condition blocks against an *adversary* rather than a specific request.

The question Spillway asks is not "is this request allowed?" but "can an attacker shape a
request so that it is allowed?". Each probe therefore describes, per condition key, what the
attacker controls:

* ABSENT    - the key is never in the attacker's request context (e.g. aws:SourceVpce for
              someone on the internet).
* OTHER     - present, but its value is fixed by AWS and is not one of yours (e.g. the
              attacker's own aws:PrincipalAccount).
* ATTACKER  - present and chosen freely by the attacker (e.g. aws:Referer, aws:UserAgent).
* a literal - a value AWS sets the same way for everyone who uses the API normally
              (aws:SecureTransport is "true" because the attacker will simply use HTTPS).

Keys a probe says nothing about evaluate to UNKNOWN, which is reported as a *conditional*
exposure instead of being silently treated as safe or unsafe.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field

from spillway.policy import glob_match
from spillway.tri import Tri, tri_and, tri_or

ABSENT = object()
OTHER = object()
ATTACKER = object()

_POSITIVE = {
    "StringEquals",
    "StringEqualsIgnoreCase",
    "StringLike",
    "ArnEquals",
    "ArnLike",
    "IpAddress",
    "Bool",
    "BinaryEquals",
    "NumericEquals",
    "NumericLessThan",
    "NumericLessThanEquals",
    "NumericGreaterThan",
    "NumericGreaterThanEquals",
    "DateEquals",
    "DateLessThan",
    "DateLessThanEquals",
    "DateGreaterThan",
    "DateGreaterThanEquals",
}
_NEGATED = {
    "StringNotEquals": "StringEquals",
    "StringNotEqualsIgnoreCase": "StringEqualsIgnoreCase",
    "StringNotLike": "StringLike",
    "ArnNotEquals": "ArnEquals",
    "ArnNotLike": "ArnLike",
    "NotIpAddress": "IpAddress",
    "NumericNotEquals": "NumericEquals",
    "DateNotEquals": "DateEquals",
}


@dataclass(frozen=True)
class Probe:
    name: str
    description: str
    context: dict[str, object] = field(default_factory=dict)

    def value(self, key: str) -> object | None:
        return self.context.get(key.lower())


def _ctx(**pairs: object) -> dict[str, object]:
    return {k.replace("__", ":").lower(): v for k, v in pairs.items()}


_SHARED = _ctx(
    aws__SourceVpce=ABSENT,
    aws__SourceVpc=ABSENT,
    aws__VpcSourceIp=ABSENT,
    aws__SourceArn=ABSENT,
    aws__SourceAccount=ABSENT,
    aws__SourceOrgID=ABSENT,
    aws__CalledVia=ABSENT,
    aws__ViaAWSService="false",
    aws__SecureTransport="true",
    aws__SourceIp=OTHER,
    aws__Referer=ATTACKER,
    aws__UserAgent=ATTACKER,
    sts__ExternalId=ATTACKER,
)

ANONYMOUS = Probe(
    "anonymous",
    "Anyone on the internet (no AWS credentials)",
    {
        **_SHARED,
        **_ctx(
            aws__PrincipalOrgID=ABSENT,
            aws__PrincipalAccount=ABSENT,
            aws__PrincipalArn=ABSENT,
            aws__PrincipalOrgPaths=ABSENT,
            aws__userid=ABSENT,
            aws__username=ABSENT,
            aws__PrincipalTag=ABSENT,
            sts__ExternalId=ABSENT,
        ),
    },
)

ANY_AWS_ACCOUNT = Probe(
    "any-aws-account",
    "Any principal in an AWS account you do not own",
    {
        **_SHARED,
        **_ctx(
            aws__PrincipalOrgID=OTHER,
            aws__PrincipalAccount=OTHER,
            aws__PrincipalArn=OTHER,
            aws__PrincipalOrgPaths=OTHER,
            aws__userid=OTHER,
            aws__username=OTHER,
        ),
    },
)

PROBES = (ANONYMOUS, ANY_AWS_ACCOUNT)


def attacker_controlled(conditions: dict[str, dict[str, tuple[str, ...]]], probe: Probe) -> list[str]:
    """Condition keys in this block whose value the requester chooses (so they are not access control)."""
    return sorted({k for block in conditions.values() for k in block if probe.value(k) is ATTACKER})


def _single(op: str, pattern: str, value: object) -> Tri:
    """Does `pattern` (one condition value) match a context value of the given kind?"""
    if value is ATTACKER:
        return Tri.TRUE
    if op == "IpAddress":
        try:
            net = ipaddress.ip_network(pattern, strict=False)
        except ValueError:
            return Tri.UNKNOWN
        # An attacker "somewhere on the internet" only matches a range that covers everything.
        return Tri.TRUE if net.prefixlen == 0 else Tri.FALSE
    if value is OTHER:
        if op in ("StringLike", "ArnLike"):
            if pattern.strip("*") == "":
                return Tri.TRUE
            return Tri.UNKNOWN if ("*" in pattern or "?" in pattern) else Tri.FALSE
        if op in ("StringEquals", "StringEqualsIgnoreCase", "ArnEquals", "BinaryEquals"):
            return Tri.FALSE
        return Tri.UNKNOWN
    if isinstance(value, str):
        if op in ("StringLike", "ArnLike"):
            return Tri.TRUE if glob_match(pattern, value) else Tri.FALSE
        if op in ("StringEquals", "ArnEquals", "BinaryEquals"):
            return Tri.TRUE if pattern == value else Tri.FALSE
        if op == "StringEqualsIgnoreCase":
            return Tri.TRUE if pattern.lower() == value.lower() else Tri.FALSE
        if op == "Bool":
            return Tri.TRUE if pattern.lower() == value.lower() else Tri.FALSE
    return Tri.UNKNOWN


def evaluate_operator(operator: str, key: str, values: tuple[str, ...], probe: Probe) -> Tri:
    """Evaluate one `{operator: {key: values}}` entry. Values within a key are OR-ed."""
    if ":" in operator and operator.split(":", 1)[0] in ("ForAnyValue", "ForAllValues"):
        return Tri.UNKNOWN  # multi-valued keys: not modelled, so never assumed safe
    if_exists = operator.endswith("IfExists")
    op = operator.removesuffix("IfExists")
    value = probe.value(key)
    if value is None:
        return Tri.UNKNOWN

    if op == "Null":
        # {"Null": {"key": "true"}} is true when the key is absent.
        want_absent = any(v.lower() == "true" for v in values)
        return Tri.TRUE if (value is ABSENT) == want_absent else Tri.FALSE

    if value is ABSENT:
        if if_exists:
            return Tri.TRUE
        if op in _NEGATED:
            return Tri.TRUE  # a negated operator matches when the key is missing
        return Tri.FALSE if op in _POSITIVE else Tri.UNKNOWN

    if op in _NEGATED:
        if value is ATTACKER:
            return Tri.TRUE  # the attacker simply sends a value you did not list
        return ~tri_or(_single(_NEGATED[op], v, value) for v in values)
    if op in _POSITIVE:
        return tri_or(_single(op, v, value) for v in values)
    return Tri.UNKNOWN


def evaluate_conditions(conditions: dict[str, dict[str, tuple[str, ...]]], probe: Probe) -> Tri:
    """All operators and all keys in a Condition block are AND-ed."""
    return tri_and(
        evaluate_operator(op, key, values, probe) for op, block in conditions.items() for key, values in block.items()
    )
