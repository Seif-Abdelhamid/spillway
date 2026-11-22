"""Recover policies that a plan shows as "known after apply" from the Terraform source.

When a bucket is created in the same plan, a policy such as
``jsonencode({... Resource = "${aws_s3_bucket.b.arn}/*" ...})`` is unknown until apply, because the
bucket ARN is computed. The plan JSON then holds no policy text at all, only the references. Yet
the risky parts (Effect, Principal "*", Action, Condition) are usually literals in the .tf file, and
the ARN is predictable from the bucket name, which *is* known at plan time.

This module reads only that narrow, common shape and only when every piece resolves:

* root-module ``resource`` blocks without ``count``/``for_each``;
* a policy argument written as ``jsonencode({...})`` with literal HCL objects, tuples, strings,
  numbers and booleans, a heredoc, or a quoted JSON string;
* interpolations limited to known plan values of other root resources, the predictable ARNs of
  ``aws_s3_bucket`` and ``aws_iam_role``, and ``data.aws_caller_identity.*.account_id`` when
  ``--account-id`` is given.

Anything else (variables, locals, function calls, template directives, unknown names) makes the
whole policy unresolvable, and Spillway keeps reporting SPW005 (fail closed). Nothing is executed:
this is a bounded hand-written parser, and the .tf files are treated as untrusted input.
"""

from __future__ import annotations

import json
import os
import re
from collections.abc import Callable
from dataclasses import replace

from spillway.loader import Resource, Snapshot

MAX_TF_FILES = 2000
MAX_TF_BYTES = 2 * 1024 * 1024
MAX_DEPTH = 64
MAX_POLICY_BYTES = 64 * 1024

# attribute holding a policy document, per resource type
POLICY_ATTRS = {
    "aws_s3_bucket_policy": "policy",
    "aws_iam_role": "assume_role_policy",
    "aws_iam_policy": "policy",
    "aws_iam_role_policy": "policy",
    "aws_iam_user_policy": "policy",
    "aws_iam_group_policy": "policy",
}

_IDENT = re.compile(r"[A-Za-z_][A-Za-z0-9_-]*")
_NUMBER = re.compile(r"-?\d+(\.\d+)?([eE][+-]?\d+)?")
_TRAVERSAL = re.compile(r"[A-Za-z_][A-Za-z0-9_-]*(\.[A-Za-z_][A-Za-z0-9_-]*)+")
_RESOURCE_HEAD = re.compile(r'^[ \t]*resource[ \t]+"([A-Za-z0-9_-]+)"[ \t]+"([A-Za-z0-9_-]+)"[ \t]*\{', re.MULTILINE)
_HEREDOC = re.compile(r"<<(-?)([A-Za-z_][A-Za-z0-9_]*)[ \t]*\n")

Resolver = Callable[[str], "str | None"]


class SourceError(ValueError):
    """The source expression is outside the subset Spillway evaluates."""


class _Parser:
    def __init__(self, text: str, resolve: Resolver, pos: int = 0):
        self.text, self.resolve, self.pos = text, resolve, pos

    # -- low-level scanning -------------------------------------------------------------------
    def skip_space(self, newlines: bool = True) -> None:
        t = self.text
        while self.pos < len(t):
            c = t[self.pos]
            if c in " \t\r" or (newlines and c == "\n"):
                self.pos += 1
            elif c == "#" or t.startswith("//", self.pos):
                end = t.find("\n", self.pos)
                self.pos = len(t) if end < 0 else end
            elif t.startswith("/*", self.pos):
                end = t.find("*/", self.pos + 2)
                if end < 0:
                    raise SourceError("unterminated comment")
                self.pos = end + 2
            else:
                return

    def peek(self) -> str:
        return self.text[self.pos] if self.pos < len(self.text) else ""

    def expect(self, ch: str) -> None:
        self.skip_space()
        if self.peek() != ch:
            raise SourceError(f"expected {ch!r} at offset {self.pos}")
        self.pos += 1

    # -- values -------------------------------------------------------------------------------
    def value(self, depth: int = 0):
        if depth > MAX_DEPTH:
            raise SourceError("expression nested too deeply")
        self.skip_space()
        c = self.peek()
        if c == "{":
            return self.object(depth)
        if c == "[":
            return self.tuple(depth)
        if c == '"':
            return self.template()
        if self.text.startswith("<<", self.pos):
            return self.heredoc()
        m = _NUMBER.match(self.text, self.pos)
        if m and m.group(0):
            self.pos = m.end()
            num = m.group(0)
            return float(num) if any(x in num for x in ".eE") else int(num)
        m = _TRAVERSAL.match(self.text, self.pos) or _IDENT.match(self.text, self.pos)
        if m:
            word = m.group(0)
            self.pos = m.end()
            if word in ("true", "false", "null"):
                return {"true": True, "false": False, "null": None}[word]
            self.skip_space(newlines=False)
            if self.peek() and self.peek() in "([":
                raise SourceError(f"function call or index on {word!r} is not evaluated")
            resolved = self.resolve(word)
            if resolved is None:
                raise SourceError(f"cannot resolve {word!r} at plan time")
            return resolved
        raise SourceError(f"unsupported expression at offset {self.pos}")

    def object(self, depth: int) -> dict:
        self.expect("{")
        out: dict = {}
        while True:
            self.skip_space()
            if self.peek() == "}":
                self.pos += 1
                return out
            if self.peek() == '"':
                key = self.template()
            else:
                m = _IDENT.match(self.text, self.pos)
                if not m:
                    raise SourceError(f"bad object key at offset {self.pos}")
                key, self.pos = m.group(0), m.end()
            self.skip_space()
            if not self.peek() or self.peek() not in "=:":
                raise SourceError(f"expected '=' after key {key!r}")
            self.pos += 1
            out[key] = self.value(depth + 1)
            self.skip_space(newlines=False)
            if self.peek() == ",":
                self.pos += 1

    def tuple(self, depth: int) -> list:
        self.expect("[")
        out: list = []
        while True:
            self.skip_space()
            if self.peek() == "]":
                self.pos += 1
                return out
            out.append(self.value(depth + 1))
            self.skip_space()
            if self.peek() == ",":
                self.pos += 1
            elif self.peek() != "]":
                raise SourceError(f"expected ',' or ']' at offset {self.pos}")

    def _interpolation(self) -> str:
        """At '${': return the resolved text and move past the closing brace."""
        start = self.pos + 2
        end = self.text.find("}", start)
        if end < 0:
            raise SourceError("unterminated interpolation")
        expr = self.text[start:end].strip().strip("~").strip()
        if not (_TRAVERSAL.fullmatch(expr) or _IDENT.fullmatch(expr)):
            raise SourceError(f"interpolation {expr!r} is not a plain reference")
        resolved = self.resolve(expr)
        if resolved is None:
            raise SourceError(f"cannot resolve {expr!r} at plan time")
        self.pos = end + 1
        return resolved

    def template(self) -> str:
        t = self.text
        self.pos += 1  # opening quote
        out: list[str] = []
        escapes = {"n": "\n", "t": "\t", "r": "\r", '"': '"', "\\": "\\"}
        while self.pos < len(t):
            c = t[self.pos]
            if c == '"':
                self.pos += 1
                return "".join(out)
            if c == "\n":
                break
            if c == "\\":
                nxt = t[self.pos + 1 : self.pos + 2]
                if nxt not in escapes:
                    raise SourceError(f"unsupported escape \\{nxt}")
                out.append(escapes[nxt])
                self.pos += 2
            elif t.startswith("$${", self.pos) or t.startswith("%%{", self.pos):
                out.append(t[self.pos + 1 : self.pos + 3])
                self.pos += 3
            elif t.startswith("${", self.pos):
                out.append(self._interpolation())
            elif t.startswith("%{", self.pos):
                raise SourceError("template directives are not evaluated")
            else:
                out.append(c)
                self.pos += 1
        raise SourceError("unterminated string")

    def heredoc(self) -> str:
        m = _HEREDOC.match(self.text, self.pos)
        if not m:
            raise SourceError("malformed heredoc")
        indent, marker = m.group(1) == "-", m.group(2)
        body_start = m.end()
        end = re.compile(rf"^[ \t]*{re.escape(marker)}[ \t]*$", re.MULTILINE).search(self.text, body_start)
        if not end:
            raise SourceError("unterminated heredoc")
        lines = self.text[body_start : end.start()].split("\n")
        if lines and lines[-1].strip() == "":
            lines.pop()
        if indent:
            pad = min((len(x) - len(x.lstrip()) for x in lines if x.strip()), default=0)
            lines = [x[pad:] for x in lines]
        self.pos = end.end()
        body = _Parser("\n".join(lines), self.resolve)
        out: list[str] = []
        while body.pos < len(body.text):
            if body.text.startswith("$${", body.pos) or body.text.startswith("%%{", body.pos):
                out.append(body.text[body.pos + 1 : body.pos + 3])
                body.pos += 3
            elif body.text.startswith("${", body.pos):
                out.append(body._interpolation())
            elif body.text.startswith("%{", body.pos):
                raise SourceError("template directives are not evaluated")
            else:
                out.append(body.text[body.pos])
                body.pos += 1
        return "".join(out)


def parse_hcl_value(text: str, resolve: Resolver):
    """Parse one HCL value from the supported subset. Raises SourceError for anything else."""
    p = _Parser(text, resolve)
    value = p.value()
    p.skip_space()
    if p.pos != len(text):
        raise SourceError(f"unexpected text at offset {p.pos}")
    return value


# -- locating resource blocks and arguments ------------------------------------------------------
def _block_end(text: str, open_brace: int) -> int:
    """Index just past the brace matching ``text[open_brace]``, skipping strings, comments, heredocs."""
    p = _Parser(text, lambda _e: "", open_brace + 1)
    depth = 1
    while p.pos < len(text):
        p.skip_space()
        c = p.peek()
        if c == "":
            break
        if c == '"':
            _skip_string(p)
        elif text.startswith("<<", p.pos) and _HEREDOC.match(text, p.pos):
            _skip_heredoc(p)
        elif c == "{":
            depth += 1
            p.pos += 1
        elif c == "}":
            depth -= 1
            p.pos += 1
            if depth == 0:
                return p.pos
        else:
            p.pos += 1
    raise SourceError("unterminated block")


def _skip_string(p: _Parser) -> None:
    t = p.text
    p.pos += 1
    while p.pos < len(t) and t[p.pos] not in '"\n':
        if t[p.pos] == "\\":
            p.pos += 1
        elif t.startswith("${", p.pos):
            end = t.find("}", p.pos)
            p.pos = len(t) if end < 0 else end
        p.pos += 1
    p.pos += 1


def _skip_heredoc(p: _Parser) -> None:
    m = _HEREDOC.match(p.text, p.pos)
    if m is None:
        raise SourceError("malformed heredoc")
    end = re.compile(rf"^[ \t]*{re.escape(m.group(2))}[ \t]*$", re.MULTILINE).search(p.text, m.end())
    p.pos = len(p.text) if not end else end.end()


def _top_level_args(body: str) -> dict[str, int]:
    """Name -> offset of the expression, for arguments directly in a block body (not nested blocks)."""
    args: dict[str, int] = {}
    p = _Parser(body, lambda _e: "")
    while p.pos < len(body):
        p.skip_space()
        m = _IDENT.match(body, p.pos)
        if not m:
            if p.peek() == "":
                break
            if p.peek() == '"':
                _skip_string(p)
            elif p.peek() in "{[(":
                close = {"{": "}", "[": "]", "(": ")"}[p.peek()]
                p.pos = _matching(body, p.pos, p.peek(), close)
            elif body.startswith("<<", p.pos) and _HEREDOC.match(body, p.pos):
                _skip_heredoc(p)
            else:
                p.pos += 1
            continue
        name = m.group(0)
        p.pos = m.end()
        p.skip_space(newlines=False)
        if p.peek() == "=" and body[p.pos + 1 : p.pos + 2] != "=":
            p.pos += 1
            p.skip_space(newlines=False)
            args.setdefault(name, p.pos)
    return args


def _matching(text: str, start: int, open_ch: str, close_ch: str) -> int:
    if open_ch == "{":
        return _block_end(text, start)
    depth, p = 0, _Parser(text, lambda _e: "", start)
    while p.pos < len(text):
        p.skip_space()
        c = p.peek()
        if c == '"':
            _skip_string(p)
            continue
        if text.startswith("<<", p.pos) and _HEREDOC.match(text, p.pos):
            _skip_heredoc(p)
            continue
        if c == open_ch:
            depth += 1
        elif c == close_ch:
            depth -= 1
            if depth == 0:
                return p.pos + 1
        p.pos += 1
    raise SourceError("unbalanced brackets")


def index_resource_blocks(tf_dir: str) -> dict[str, str]:
    """Address -> block body text, for root-module resources in ``tf_dir`` (not subdirectories)."""
    root = os.path.realpath(tf_dir)
    blocks: dict[str, str] = {}
    try:
        names = sorted(os.listdir(root))
    except OSError:
        return blocks
    tf_files = [n for n in names if n.endswith(".tf")][:MAX_TF_FILES]
    for fname in tf_files:
        path = os.path.join(root, fname)
        if os.path.islink(path) or not os.path.isfile(path) or os.path.getsize(path) > MAX_TF_BYTES:
            continue
        with open(path, encoding="utf-8", errors="replace") as fh:
            text = fh.read()
        for m in _RESOURCE_HEAD.finditer(text):
            try:
                end = _block_end(text, m.end() - 1)
            except SourceError:
                continue
            address = f"{m.group(1)}.{m.group(2)}"
            if address in blocks:
                blocks[address] = ""  # duplicate definitions: refuse to guess
            else:
                blocks[address] = text[m.end() : end - 1]
    return blocks


# -- resolving references ------------------------------------------------------------------------
def make_resolver(snap: Snapshot, account_id: str | None) -> Resolver:
    """Map a plain reference such as ``aws_s3_bucket.b.arn`` to its plan-time value, or None."""

    def resolve(expr: str) -> str | None:
        parts = expr.split(".")
        if len(parts) == 4 and parts[0] == "data" and parts[1] == "aws_caller_identity" and parts[3] == "account_id":
            return account_id
        if len(parts) != 3:
            return None
        res = snap.resources.get(f"{parts[0]}.{parts[1]}")
        if res is None:
            return None
        attr = parts[2]
        if not res.is_unknown(attr) and isinstance(res.get(attr), (str, int)) and not isinstance(res.get(attr), bool):
            return str(res.get(attr))
        name_attr = {"aws_s3_bucket": "bucket", "aws_iam_role": "name"}.get(res.type)
        if name_attr is None or res.is_unknown(name_attr) or not isinstance(res.get(name_attr), str):
            return None
        name = res.get(name_attr)
        if res.type == "aws_s3_bucket":
            return {"arn": f"arn:aws:s3:::{name}", "id": name, "bucket": name}.get(attr)
        if attr == "name" or attr == "id":
            return name
        path = res.get("path") if isinstance(res.get("path"), str) and not res.is_unknown("path") else "/"
        if attr == "arn" and account_id:
            return f"arn:aws:iam::{account_id}:role{path}{name}"
        return None

    return resolve


def _policy_text(body: str, attr: str, resolve: Resolver) -> str | None:
    args = _top_level_args(body)
    if "count" in args or "for_each" in args or attr not in args:
        return None
    p = _Parser(body, resolve, args[attr])
    if body.startswith("jsonencode", p.pos):
        p.pos += len("jsonencode")
        p.expect("(")
        value = p.value()
        p.expect(")")
        if not isinstance(value, dict):
            raise SourceError("policy is not an object")
        text = json.dumps(value)
    elif body.startswith("<<", p.pos) or p.peek() == '"':
        text = p.value()
    else:
        return None
    if not isinstance(text, str) or len(text) > MAX_POLICY_BYTES:
        return None
    json.loads(text)  # must be JSON; ValueError is handled by the caller
    return text


def recover_policies(snap: Snapshot, tf_dir: str, account_id: str | None = None) -> Snapshot:
    """A copy of ``snap`` where unknown policy attributes are filled in from source when fully resolvable."""
    pending = [
        r
        for r in snap.resources.values()
        if r.type in POLICY_ATTRS
        and r.is_unknown(POLICY_ATTRS[r.type])
        and "[" not in r.address
        and not r.address.startswith("module.")
    ]
    if not pending:
        return snap
    blocks = index_resource_blocks(tf_dir)
    resolve = make_resolver(snap, account_id)
    resources = dict(snap.resources)
    for res in pending:
        attr = POLICY_ATTRS[res.type]
        body = blocks.get(res.address)
        if not body:
            continue
        try:
            text = _policy_text(body, attr, resolve)
        except (SourceError, ValueError, RecursionError):
            continue
        if text is None:
            continue
        values = {**res.values, attr: text}
        resources[res.address] = replace(
            res, values=values, unknown=res.unknown - {attr}, from_source=res.from_source | {attr}
        )
    return Snapshot(resources=resources, references=snap.references)


def source_note(res: Resource | None) -> str:
    """Suffix for findings on a policy that was recovered from source."""
    if res is None or not res.from_source:
        return ""
    return " (policy read from the .tf source; the plan leaves it unknown until apply)"
