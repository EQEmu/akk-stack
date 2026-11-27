"""Pure assertions for the Qeynos2 journey. No clock, no processes, no sockets."""

from __future__ import annotations

import math


class CheckFailed(AssertionError):
    """A journey expectation did not hold."""


def require(condition, message: str) -> None:
    if not condition:
        raise CheckFailed(message)


def forward(previous: int, current: int) -> bool:
    """True when a u16 sequence moved forward by less than half the space."""
    return 0 < ((current - previous) & 0xFFFF) < 0x8000


def ordered_movement(lines, attempt: str, start_xyz) -> tuple[list, object]:
    """Check the server's moved/stopped gameplay lines for one attempt.

    Requires one or more ``moved`` samples followed by exactly one ``stopped``
    sample, all on ``attempt``. Each ``moved`` sample must step strictly west
    of the previous accepted pose with Y and Z unchanged, sequences must move
    forward, and the stop must equal the *final* accepted sample (not the
    first). Returns ``(moved_lines, stopped_line)``.
    """
    moves = [l for l in lines if l.outcome in ("moved", "stopped")]
    require(moves, "no server moved/stopped samples")
    require(all(l.attempt == attempt for l in moves), "moved/stopped on another attempt")
    require(len(moves) >= 2, "no server moved sample before stop")
    require(all(l.outcome == "moved" for l in moves[:-1]), "a sample followed the stop")
    require(moves[-1].outcome == "stopped", "server has not reported stopped")
    last = [float(v) for v in start_xyz]
    previous_sequence = None
    for line in moves:
        xyz = line.xyz()
        require(all(math.isfinite(v) for v in xyz), "non-finite server pose")
        sequence = int(line.fields["sequence"])
        require(0 <= sequence <= 0xFFFF, "sequence outside u16")
        if previous_sequence is not None:
            require(forward(previous_sequence, sequence), "position sequence not forward")
        previous_sequence = sequence
        if line.outcome == "moved":
            require(xyz[0] < last[0], f"moved sample not west of previous: {xyz} vs {last}")
            require(xyz[1:] == last[1:], f"moved sample changed Y/Z: {xyz} vs {last}")
        else:
            require(xyz == last, f"stop {xyz} differs from final accepted sample {last}")
        last = xyz
    return moves[:-1], moves[-1]


def unique_replies(rows, opcode: str) -> list[dict]:
    """Server replies of one opcode, first copy per (peer, sequence)."""
    seen = set()
    out = []
    for row in rows:
        if row.get("direction") != "server_to_client" or row.get("opcode") != opcode:
            continue
        key = (row["dst_port"], row["sequence"])
        if key in seen:
            continue
        seen.add(key)
        out.append(row)
    return out


def wire_positions(updates: list[dict], moves: list, player: int) -> None:
    """Each accepted moved/stopped sample has one matching 0x7dfc reply, in order."""
    require(len(updates) == len(moves), f"{len(updates)} position replies for {len(moves)} samples")
    previous = None
    for reply, line in zip(updates, moves):
        require(reply["entity"] == player, f"position reply for entity {reply['entity']}")
        require(reply["position"] == line.xyz(), f"wire {reply['position']} != trace {line.xyz()}")
        if previous is not None:
            require(forward(previous, reply["sequence"]), "wire sequence not forward")
        previous = reply["sequence"]


def parse_pose(raw: bytes) -> dict:
    """Parse the server's ``clientab.pose`` record."""
    text = raw.decode("ascii")
    fields = text.strip().split()
    require(text.endswith("\n") and len(fields) == 7, f"pose record shape: {text!r}")
    return {
        "format": fields[0],
        "character": fields[1],
        "zone": int(fields[2]),
        "xyz": [float(v) for v in fields[3:6]],
        "heading": int(fields[6]),
    }


def pose_line_matches(line, pose: dict) -> bool:
    return (
        line.fields["character"] == pose["character"]
        and int(line.fields["zone"]) == pose["zone"]
        and line.xyz() == pose["xyz"]
        and int(line.fields["heading"]) == pose["heading"]
    )


def hp_percent(hp: int, max_hp: int) -> int:
    return hp * 100 // max_hp
