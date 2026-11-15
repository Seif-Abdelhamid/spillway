"""Three-valued logic. The analyzer never guesses: anything it cannot decide is UNKNOWN."""

from __future__ import annotations

from enum import Enum


class Tri(Enum):
    FALSE = 0
    UNKNOWN = 1
    TRUE = 2

    def __invert__(self) -> Tri:
        if self is Tri.UNKNOWN:
            return Tri.UNKNOWN
        return Tri.FALSE if self is Tri.TRUE else Tri.TRUE


def tri_and(values) -> Tri:
    result = Tri.TRUE
    for v in values:
        if v is Tri.FALSE:
            return Tri.FALSE
        if v is Tri.UNKNOWN:
            result = Tri.UNKNOWN
    return result


def tri_or(values) -> Tri:
    result = Tri.FALSE
    for v in values:
        if v is Tri.TRUE:
            return Tri.TRUE
        if v is Tri.UNKNOWN:
            result = Tri.UNKNOWN
    return result


def from_bool(b: bool) -> Tri:
    return Tri.TRUE if b else Tri.FALSE
