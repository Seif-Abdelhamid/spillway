"""Load `terraform show -json` output (a saved plan or applied state) safely.

The plan file is untrusted input: in a pull-request pipeline it is produced from code the
PR author controls. Loading enforces a size cap, survives hostile nesting, and accepts only
the documented shapes. Nothing in the file is executed or used to make network calls.
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field

DEFAULT_MAX_BYTES = 50 * 1024 * 1024


class InputError(ValueError):
    """The input is not a readable Terraform JSON document."""


@dataclass(frozen=True)
class Resource:
    address: str
    type: str
    name: str
    values: dict
    unknown: frozenset[str] = frozenset()  # top-level attributes "known after apply"

    def get(self, attr: str):
        return self.values.get(attr)

    def is_unknown(self, attr: str) -> bool:
        return attr in self.unknown


@dataclass
class Snapshot:
    """Every managed resource at one point in time (before or after the change)."""

    resources: dict[str, Resource] = field(default_factory=dict)
    # resource address (index stripped) -> attribute -> referenced resource addresses (index stripped)
    references: dict[str, dict[str, list[str]]] = field(default_factory=dict)

    def of_type(self, *types: str) -> list[Resource]:
        return [r for r in self.resources.values() if r.type in types]


@dataclass
class Document:
    kind: str  # "plan" | "state"
    before: Snapshot
    after: Snapshot


_INDEX = re.compile(r"\[[^\]]*\]")


def strip_index(address: str) -> str:
    return _INDEX.sub("", address)


def _require(cond: bool, msg: str) -> None:
    if not cond:
        raise InputError(msg)


def _resource(raw: dict, values, unknown) -> Resource:
    _require(isinstance(raw.get("address"), str) and isinstance(raw.get("type"), str), "resource without address/type")
    _require(isinstance(values, dict), f"{raw['address']}: values must be an object")
    unknown_keys = frozenset(k for k, v in unknown.items() if v is True) if isinstance(unknown, dict) else frozenset()
    return Resource(raw["address"], raw["type"], str(raw.get("name", "")), values, unknown_keys)


def _walk_state_module(module: dict, snap: Snapshot) -> None:
    for raw in module.get("resources", []) or []:
        if isinstance(raw, dict) and raw.get("mode", "managed") == "managed":
            res = _resource(raw, raw.get("values", {}), {})
            snap.resources[res.address] = res
    for child in module.get("child_modules", []) or []:
        if isinstance(child, dict):
            _walk_state_module(child, snap)


def _walk_config(module: dict, prefix: str, refs: dict[str, dict[str, list[str]]], depth: int = 0) -> None:
    _require(depth < 32, "module nesting too deep")
    for raw in module.get("resources", []) or []:
        if not isinstance(raw, dict) or not isinstance(raw.get("address"), str):
            continue
        attrs: dict[str, list[str]] = {}
        for attr, expr in (raw.get("expressions") or {}).items():
            if isinstance(expr, dict) and isinstance(expr.get("references"), list):
                found = []
                for ref in expr["references"]:
                    if isinstance(ref, str) and not ref.startswith(("var.", "local.", "data.", "module.", "each.")):
                        parts = strip_index(ref).split(".")
                        if len(parts) >= 2:
                            found.append(prefix + ".".join(parts[:2]))
                attrs[attr] = list(dict.fromkeys(found))
        refs[prefix + raw["address"]] = attrs
    for name, call in (module.get("module_calls") or {}).items():
        if isinstance(call, dict) and isinstance(call.get("module"), dict):
            _walk_config(call["module"], f"{prefix}module.{name}.", refs, depth + 1)


def parse_document(doc: dict) -> Document:
    _require(isinstance(doc, dict), "top level must be a JSON object")
    _require("format_version" in doc, "not terraform JSON output (no format_version); use `terraform show -json`")
    before, after = Snapshot(), Snapshot()

    if "resource_changes" in doc or "planned_values" in doc:
        for rc in doc.get("resource_changes", []) or []:
            _require(isinstance(rc, dict) and isinstance(rc.get("change"), dict), "malformed resource_changes entry")
            if rc.get("mode", "managed") != "managed":
                continue
            change = rc["change"]
            if isinstance(change.get("before"), dict):
                res = _resource(rc, change["before"], {})
                before.resources[res.address] = res
            if isinstance(change.get("after"), dict) and change.get("actions") != ["delete"]:
                res = _resource(rc, change["after"], change.get("after_unknown", {}))
                after.resources[res.address] = res
        config = doc.get("configuration", {})
        if isinstance(config, dict) and isinstance(config.get("root_module"), dict):
            _walk_config(config["root_module"], "", after.references)
            before.references = after.references
        return Document("plan", before, after)

    values = doc.get("values")
    _require(isinstance(values, dict) and isinstance(values.get("root_module"), dict), "no resource_changes or values")
    _walk_state_module(values["root_module"], after)
    return Document("state", before, after)


def load(path: str, max_bytes: int = DEFAULT_MAX_BYTES) -> Document:
    try:
        size = os.stat(path).st_size
    except OSError as exc:
        raise InputError(f"cannot read {path}: {exc.strerror}") from None
    _require(size <= max_bytes, f"{path} is {size} bytes, over the {max_bytes}-byte limit")
    with open(path, "rb") as fh:
        raw = fh.read(max_bytes + 1)
    try:
        doc = json.loads(raw)
    except RecursionError:
        raise InputError("JSON nesting too deep") from None
    except ValueError as exc:
        raise InputError(f"invalid JSON: {exc}") from None
    return parse_document(doc)
