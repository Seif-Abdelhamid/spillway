"""Generic resource-policy evaluation for one probe and one action.

Follows the IAM evaluation order that matters for outsiders: an explicit Deny that surely
applies wins; otherwise an Allow that surely applies grants access; an Allow whose
conditions cannot be decided makes the result UNKNOWN (reported as "conditional").
A Deny whose conditions cannot be decided is never relied on.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable
from dataclasses import dataclass

from spillway.conditions import Probe, evaluate_conditions
from spillway.policy import Statement, action_matches
from spillway.tri import Tri, tri_and


def principal_matches(stmt: Statement, probe: Probe) -> Tri:
    """Probes are outsiders: they match only wildcard principals (or a NotPrincipal that omits them)."""
    if stmt.principal is not None:
        return Tri.TRUE if stmt.principal.wildcard else Tri.FALSE
    if stmt.not_principal is not None:
        return Tri.FALSE if stmt.not_principal.wildcard else Tri.TRUE
    return Tri.FALSE


@dataclass(frozen=True)
class Decision:
    result: Tri
    allowed_by: tuple[str, ...] = ()  # Sids of the statements that grant
    scope: str = "*"


def decide(
    statements: Iterable[Statement],
    probe: Probe,
    action: str,
    scope_of: Callable[[Statement], str | None],
) -> Decision:
    """`scope_of(stmt)` returns which part of the resource a statement covers ("*" = all, None = none)."""
    statements = list(statements)
    for stmt in statements:
        if stmt.effect != "Deny" or not action_matches(stmt, action) or scope_of(stmt) != "*":
            continue
        if tri_and([principal_matches(stmt, probe), evaluate_conditions(stmt.conditions, probe)]) is Tri.TRUE:
            return Decision(Tri.FALSE)

    grants: dict[Tri, list[tuple[str, str]]] = {Tri.TRUE: [], Tri.UNKNOWN: []}
    for stmt in statements:
        if stmt.effect != "Allow" or not action_matches(stmt, action):
            continue
        scope = scope_of(stmt)
        if scope is None:
            continue
        applies = tri_and([principal_matches(stmt, probe), evaluate_conditions(stmt.conditions, probe)])
        if applies is not Tri.FALSE:
            grants[applies].append((stmt.sid, scope))
    for result in (Tri.TRUE, Tri.UNKNOWN):
        if grants[result]:
            sids = tuple(dict.fromkeys(sid for sid, _ in grants[result]))
            scopes = [scope for _, scope in grants[result]]
            scope = "*" if "*" in scopes else ", ".join(dict.fromkeys(scopes))
            return Decision(result, sids, scope)
    return Decision(Tri.FALSE)
