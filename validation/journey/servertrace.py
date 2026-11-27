"""The Rust server's stdout trace contract, parsed in one place.

The startup endpoint line and the ``entry``, ``gameplay`` and ``persistence``
lines are a contract the server refactor must keep byte-identical. Every other
part of the journey reads server output only through this module.

Known outcomes are checked for exact field names and order. A line that starts
with a contract prefix but does not match its known shape is ``malformed``
and the journey treats it as a contract violation. An unknown gameplay outcome
with well-formed ``key=value`` fields is kept with ``known=False`` so new
server behavior does not break routine runs.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

ENDPOINT_RE = re.compile(
    r"login=127\.0\.0\.1:(\d+) world=127\.0\.0\.1:(\d+) zone=127\.0\.0\.1:(\d+) zone_id=(\d+)"
)
HEAD_RE = re.compile(
    r"(entry|gameplay|persistence) attempt=(none|\d+)(?: stage=([a-z_]+))? outcome=([a-z_]+)(?: (.*))?"
)
NUMBER_RE = re.compile(r"-?\d+(?:\.\d+)?")
TOKEN_RE = re.compile(r"([a-z_]+)=(\S+)")

POSE_FIELDS = ("character", "zone", "x", "y", "z", "heading")
GAMEPLAY_FIELDS = {
    "moved": ("sequence", "x", "y", "z"),
    "stopped": ("sequence", "x", "y", "z"),
    "targeted": ("entity_id", "incarnation", "spawn_id", "npc_type"),
    "attack_armed": ("source_entity", "target_entity", "incarnation"),
    "attack_off": ("canceled",),
    "melee_hit": (
        "source_entity",
        "target_entity",
        "incarnation",
        "spawn_id",
        "npc_type",
        "damage",
        "hp_before",
        "hp_after",
    ),
    "melee_refused": ("source_entity", "target_entity", "incarnation", "reason"),
    "camp_started": (),
    "camp_canceled": (),
    "camp_incomplete": (),
    "logout_without_camp": (),
    "camp_completed": (),
    "camp_interrupted": ("reason",),
}
PERSISTENCE_FIELDS = {
    ("save", "ok"): POSE_FIELDS,
    ("load", "ok"): POSE_FIELDS,
    ("load", "seeded"): POSE_FIELDS,
    ("save", "failed"): ("kind",),
    ("save", "uncertain"): ("kind",),
    ("load", "failed"): ("kind",),
    ("save", "disabled"): (),
}
NUMERIC = {
    "sequence",
    "x",
    "y",
    "z",
    "heading",
    "zone",
    "entity_id",
    "incarnation",
    "spawn_id",
    "npc_type",
    "source_entity",
    "target_entity",
    "damage",
    "hp_before",
    "hp_after",
}


@dataclass(frozen=True)
class Endpoints:
    login: int
    world: int
    zone: int
    zone_id: int
    raw: str


@dataclass(frozen=True)
class Line:
    """One parsed trace line.

    ``kind`` is entry, gameplay, persistence, endpoints, malformed or other.
    ``fields`` holds ``key=value`` details in order; for entry lines ``detail``
    holds the free-form remainder.
    """

    kind: str
    raw: str
    index: int
    attempt: str | None = None
    stage: str | None = None
    outcome: str | None = None
    fields: dict = field(default_factory=dict)
    detail: str = ""
    known: bool = True
    endpoints: Endpoints | None = None
    problem: str | None = None

    def number(self, key: str) -> float:
        return float(self.fields[key])

    def xyz(self) -> list[float]:
        return [float(self.fields[k]) for k in ("x", "y", "z")]

    def as_dict(self) -> dict:
        out = {"kind": self.kind, "index": self.index, "raw": self.raw}
        for key in ("attempt", "stage", "outcome", "problem"):
            value = getattr(self, key)
            if value is not None:
                out[key] = value
        if self.fields:
            out["fields"] = dict(self.fields)
        if not self.known:
            out["known"] = False
        return out


def _fields(rest: str | None) -> list[tuple[str, str]] | None:
    if not rest:
        return []
    out = []
    for token in rest.split(" "):
        match = TOKEN_RE.fullmatch(token)
        if not match:
            return None
        out.append((match[1], match[2]))
    return out


def _check(expected: tuple, pairs: list[tuple[str, str]]) -> str | None:
    names = tuple(k for k, _ in pairs)
    if names != expected:
        return f"fields {names} != {expected}"
    for key, value in pairs:
        if key in NUMERIC and not NUMBER_RE.fullmatch(value):
            return f"non-numeric {key}={value}"
    return None


def parse_line(raw: str, index: int = 0) -> Line:
    """Parse one stdout/stderr line (without its newline)."""
    match = ENDPOINT_RE.fullmatch(raw)
    if match:
        ports = [int(match[i]) for i in range(1, 5)]
        endpoints = Endpoints(*ports, raw=raw)
        return Line("endpoints", raw, index, endpoints=endpoints)
    prefix = raw.split(" ", 1)[0]
    if prefix not in ("entry", "gameplay", "persistence") or not raw.startswith(
        prefix + " attempt="
    ):
        return Line("other", raw, index)
    match = HEAD_RE.fullmatch(raw)
    if not match:
        return Line("malformed", raw, index, problem="head does not match")
    kind, attempt, stage, outcome, rest = match.groups()
    if kind == "entry":
        if stage is None:
            return Line("malformed", raw, index, problem="entry without stage")
        pairs = _fields(rest) or []
        return Line(
            kind, raw, index, attempt, stage, outcome, dict(pairs), detail=rest or ""
        )
    pairs = _fields(rest)
    if pairs is None:
        return Line("malformed", raw, index, attempt, stage, outcome, problem="bad fields")
    if kind == "gameplay":
        if stage is not None:
            return Line("malformed", raw, index, problem="gameplay with stage")
        expected = GAMEPLAY_FIELDS.get(outcome)
    else:
        if stage is None:
            return Line("malformed", raw, index, problem="persistence without stage")
        expected = PERSISTENCE_FIELDS.get((stage, outcome))
    if expected is None:
        return Line(kind, raw, index, attempt, stage, outcome, dict(pairs), known=False)
    problem = _check(expected, pairs)
    if problem:
        return Line("malformed", raw, index, attempt, stage, outcome, problem=problem)
    return Line(kind, raw, index, attempt, stage, outcome, dict(pairs))


def parse_log(text: str) -> list[Line]:
    """Parse complete lines only; a trailing partial line is ignored."""
    lines = text.split("\n")
    return [parse_line(raw, i) for i, raw in enumerate(lines[:-1])]


class Trace:
    """Convenience queries over one server process's parsed output."""

    def __init__(self, text: str):
        self.lines = parse_log(text)

    def endpoints(self) -> Endpoints | None:
        first = self.lines[0] if self.lines else None
        return first.endpoints if first and first.kind == "endpoints" else None

    def malformed(self) -> list[Line]:
        return [line for line in self.lines if line.kind == "malformed"]

    def of(self, kind: str, *, outcome: str | None = None, stage: str | None = None,
           attempt: str | None = None) -> list[Line]:
        return [
            line
            for line in self.lines
            if line.kind == kind
            and (outcome is None or line.outcome == outcome)
            and (stage is None or line.stage == stage)
            and (attempt is None or line.attempt == attempt)
        ]

    def entry(self) -> list[Line]:
        return self.of("entry")

    def gameplay(self, *outcomes: str) -> list[Line]:
        return [l for l in self.of("gameplay") if not outcomes or l.outcome in outcomes]

    def persistence(self, stage: str | None = None, outcome: str | None = None) -> list[Line]:
        return self.of("persistence", stage=stage, outcome=outcome)
