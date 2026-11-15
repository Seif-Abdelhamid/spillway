"""Parse IAM policy documents (bucket, trust and identity policies) into a normalized form.

Policies arrive as JSON strings inside an untrusted Terraform plan, so parsing is defensive:
a size cap, strict types, and a PolicyError instead of a crash on anything malformed. The
caller turns a PolicyError into a finding (fail closed), never into "no exposure".
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from functools import lru_cache

# AWS caps bucket policies at 20 KB and managed IAM policies at 6,144 characters.
# Anything far beyond that is not a real policy and is refused before parsing.
MAX_POLICY_BYTES = 64 * 1024


class PolicyError(ValueError):
    """The policy document could not be parsed safely."""


@dataclass(frozen=True)
class Principal:
    """A normalized principal block. `wildcard` is True for "*" and {"AWS": "*"}."""

    wildcard: bool = False
    aws: tuple[str, ...] = ()
    service: tuple[str, ...] = ()
    federated: tuple[str, ...] = ()
    canonical: tuple[str, ...] = ()


@dataclass(frozen=True)
class Statement:
    sid: str
    effect: str  # "Allow" | "Deny"
    principal: Principal | None  # None for identity policies (no Principal element)
    not_principal: Principal | None
    actions: tuple[str, ...]
    not_actions: tuple[str, ...]
    resources: tuple[str, ...]
    not_resources: tuple[str, ...]
    # {operator: {key: (values...)}}
    conditions: dict[str, dict[str, tuple[str, ...]]] = field(default_factory=dict)


def _as_list(value, what: str) -> tuple[str, ...]:
    if value is None:
        return ()
    if isinstance(value, str):
        return (value,)
    if isinstance(value, list) and all(isinstance(v, str) for v in value):
        return tuple(value)
    raise PolicyError(f"{what} must be a string or a list of strings")


def _cond_values(value, what: str) -> tuple[str, ...]:
    # Condition values may be strings, booleans or numbers in real policies.
    items = value if isinstance(value, list) else [value]
    out = []
    for v in items:
        if isinstance(v, bool):
            out.append("true" if v else "false")
        elif isinstance(v, (str, int, float)):
            out.append(str(v))
        else:
            raise PolicyError(f"{what} has a non-scalar value")
    return tuple(out)


def _principal(value) -> Principal:
    if value == "*":
        return Principal(wildcard=True)
    if not isinstance(value, dict):
        raise PolicyError("Principal must be '*' or an object")
    aws = _as_list(value.get("AWS"), "Principal.AWS")
    unknown = set(value) - {"AWS", "Service", "Federated", "CanonicalUser"}
    if unknown:
        raise PolicyError(f"unknown principal type(s): {sorted(unknown)}")
    return Principal(
        wildcard="*" in aws,
        aws=tuple(a for a in aws if a != "*"),
        service=_as_list(value.get("Service"), "Principal.Service"),
        federated=_as_list(value.get("Federated"), "Principal.Federated"),
        canonical=_as_list(value.get("CanonicalUser"), "Principal.CanonicalUser"),
    )


def _statement(raw, index: int) -> Statement:
    if not isinstance(raw, dict):
        raise PolicyError(f"Statement[{index}] is not an object")
    effect = raw.get("Effect")
    if effect not in ("Allow", "Deny"):
        raise PolicyError(f"Statement[{index}] has invalid Effect {effect!r}")
    sid = raw.get("Sid", f"#{index}")
    if not isinstance(sid, str):
        raise PolicyError(f"Statement[{index}] Sid must be a string")
    conditions: dict[str, dict[str, tuple[str, ...]]] = {}
    cond = raw.get("Condition", {})
    if not isinstance(cond, dict):
        raise PolicyError(f"Statement[{index}] Condition must be an object")
    for op, block in cond.items():
        if not isinstance(block, dict):
            raise PolicyError(f"Statement[{index}] Condition.{op} must be an object")
        conditions[op] = {k: _cond_values(v, f"Condition.{op}.{k}") for k, v in block.items()}
    stmt = Statement(
        sid=sid,
        effect=effect,
        principal=_principal(raw["Principal"]) if "Principal" in raw else None,
        not_principal=_principal(raw["NotPrincipal"]) if "NotPrincipal" in raw else None,
        actions=_as_list(raw.get("Action"), "Action"),
        not_actions=_as_list(raw.get("NotAction"), "NotAction"),
        resources=_as_list(raw.get("Resource"), "Resource"),
        not_resources=_as_list(raw.get("NotResource"), "NotResource"),
        conditions=conditions,
    )
    if not stmt.actions and not stmt.not_actions:
        raise PolicyError(f"Statement[{index}] has neither Action nor NotAction")
    return stmt


def parse_policy(document) -> list[Statement]:
    """Accept a JSON string or an already-decoded dict and return its statements."""
    if isinstance(document, str):
        if len(document.encode("utf-8", "surrogatepass")) > MAX_POLICY_BYTES:
            raise PolicyError(f"policy is larger than {MAX_POLICY_BYTES} bytes")
        try:
            document = json.loads(document)
        except (ValueError, RecursionError) as exc:
            raise PolicyError(f"policy is not valid JSON: {exc.__class__.__name__}") from None
    if not isinstance(document, dict):
        raise PolicyError("policy must be a JSON object")
    statements = document.get("Statement")
    if isinstance(statements, dict):
        statements = [statements]
    if not isinstance(statements, list):
        raise PolicyError("policy has no Statement list")
    return [_statement(s, i) for i, s in enumerate(statements)]


_ACCOUNT_RE = re.compile(r"^(?:arn:aws[\w-]*:(?:iam|sts)::)?(\d{12})(?::|$)")


def account_of(principal: str) -> str | None:
    """'123456789012' or 'arn:aws:iam::123456789012:role/x' -> '123456789012'."""
    m = _ACCOUNT_RE.match(principal)
    return m.group(1) if m else None


@lru_cache(maxsize=4096)
def _glob_regex(pattern: str, ignore_case: bool) -> re.Pattern[str]:
    # IAM wildcards: '*' = any run of characters, '?' = exactly one. Everything else is literal.
    body = "".join(".*" if c == "*" else "." if c == "?" else re.escape(c) for c in pattern)
    return re.compile(f"^{body}$", re.IGNORECASE | re.DOTALL if ignore_case else re.DOTALL)


def glob_match(pattern: str, value: str, ignore_case: bool = False) -> bool:
    return bool(_glob_regex(pattern, ignore_case).match(value))


def action_matches(stmt: Statement, action: str) -> bool:
    """IAM action names are case-insensitive."""
    if stmt.actions:
        return any(glob_match(p, action, ignore_case=True) for p in stmt.actions)
    return not any(glob_match(p, action, ignore_case=True) for p in stmt.not_actions)


def resource_matches(stmt: Statement, resource: str | None) -> bool:
    """Trust policies have no Resource element; `resource=None` means "the policy's own resource"."""
    if resource is None:
        return True
    if stmt.resources:
        return any(glob_match(p, resource) for p in stmt.resources)
    if stmt.not_resources:
        return not any(glob_match(p, resource) for p in stmt.not_resources)
    return True


def object_scope(stmt: Statement, bucket: str) -> str | None:
    """For object actions, which keys of `bucket` does this statement cover?

    Returns "*" when it covers every key, a comma-separated list of key prefixes or keys
    (e.g. "public/") for a partial grant, or None if it covers no object in the bucket.
    """
    base = f"arn:aws:s3:::{bucket}/"
    probes = (base + "a", base + "spillway/probe.bin")
    if not stmt.resources:
        return "*" if all(resource_matches(stmt, p) for p in probes) else None
    partial: list[str] = []
    for pattern in stmt.resources:
        if all(glob_match(pattern, p) for p in probes):
            return "*"
        literal = re.split(r"[*?]", pattern, maxsplit=1)[0]
        if literal.startswith(base) and len(literal) > len(base):
            partial.append(literal[len(base) :])
    return ", ".join(dict.fromkeys(partial)) if partial else None
