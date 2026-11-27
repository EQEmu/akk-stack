"""Headless Qeynos2 journey, run inside the disposable container.

Invoked by the host as ``python3 -B -s -E /journey/guest.py ...``. The script
directory (the read-only harness copy) is the only import location used.
Writes ``guest-result.json`` and raw logs under ``--output``; never exits
without attempting to stop every process it started.
"""

from __future__ import annotations

import argparse
import datetime
import hashlib
import json
import os
import secrets
import signal
import subprocess
import sys
import time
import traceback
import urllib.error
import urllib.request
from pathlib import Path

import checks
import fixture as F
import observer as obs
from checks import CheckFailed, require
from servertrace import Trace

API_PORT = 18766


def utc() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


class Child:
    def __init__(self, name: str, argv: list[str], log: Path):
        self.name = name
        self.log = log
        self.handle = log.open("xb", buffering=0)
        self.started = time.monotonic()
        self.process = subprocess.Popen(
            argv, stdout=self.handle, stderr=subprocess.STDOUT, start_new_session=True
        )
        self.exit = None
        self.signal_sent = None

    def alive(self) -> bool:
        return self.process.poll() is None

    def text(self) -> str:
        return self.log.read_bytes().decode("utf-8", "replace")

    def stop(self, timeout: float) -> dict:
        was_live = self.alive()
        at = time.monotonic()
        if was_live:
            self.signal_sent = "SIGTERM"
            try:
                os.killpg(self.process.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
        try:
            code = self.process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            self.signal_sent = "SIGKILL"
            os.killpg(self.process.pid, signal.SIGKILL)
            code = self.process.wait(timeout=5)
        try:
            os.killpg(self.process.pid, 0)
            group_absent = False
        except ProcessLookupError:
            group_absent = True
        except PermissionError:
            group_absent = False
        self.handle.close()
        return {
            "pid": self.process.pid,
            "exit": code,
            "signal_sent": self.signal_sent,
            "was_running": was_live,
            "stop_seconds": round(time.monotonic() - at, 3),
            "group_absent": group_absent,
        }


class Api:
    def __init__(self, token: str):
        self.token = token
        self.fence = None
        self.receipts = []

    def call(self, path: str, body=None, timeout=2.0):
        request = urllib.request.Request(
            f"http://127.0.0.1:{API_PORT}/v2/player/{path}",
            headers={"Authorization": "Bearer " + self.token, "Content-Type": "application/json"},
            data=None if body is None else json.dumps(body).encode(),
            method="GET" if body is None else "PUT",
        )
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return json.load(response)

    def state(self) -> dict:
        data = self.call("state")
        self.fence = data
        return data.get("state", data)

    def command(self, name: str, operation: dict) -> dict:
        require(self.fence is not None, "no state fence before command")
        payload = {
            "session": self.fence["session"],
            "zone_epoch": self.fence["zone_epoch"],
            "operation": operation,
        }
        at = time.monotonic()
        response = self.call("commands/" + name, payload)
        self.receipts.append({"id": name, "operation": operation, "monotonic": at, "response": response})
        return response

    def receipt(self, name: str) -> dict:
        return self.call("commands/" + name)


class Journey:
    def __init__(self, args):
        self.out = Path(args.output)
        self.logs = self.out / "logs"
        self.evidence_dir = self.out / "evidence"
        self.server_bin = args.server
        self.client_bin = args.client
        self.maps = Path(args.maps)
        self.result = {
            "schema": "qeynos2-journey-guest/v1",
            "started_utc": utc(),
            "milestones": [],
            "first_failed_milestone": None,
            "failure": None,
            "processes": {},
            "trace_contract_violations": [],
        }
        self.children: list[Child] = []
        self.observer = None
        self.secrets: list[str] = []
        self.api = None
        self.facts = {}

    # ---- plumbing -------------------------------------------------------
    def save_evidence(self, name: str, data) -> str:
        path = self.evidence_dir / (name + ".json")
        path.write_text(json.dumps(data, indent=2, default=str))
        return str(path.relative_to(self.out))

    def wait(self, predicate, timeout: float, message: str, interval=0.05, watch=()):
        deadline = time.monotonic() + timeout
        while True:
            for child in watch:
                require(child.alive(), f"{child.name} exited (code {child.process.poll()}) while waiting: {message}")
                require(child.log.stat().st_size < F.LOG_LIMIT_BYTES, f"{child.name} log over budget")
            value = predicate()
            if value:
                return value
            require(time.monotonic() < deadline, f"timed out after {timeout}s: {message}")
            time.sleep(interval)

    def trace(self, server: Child) -> Trace:
        trace = Trace(server.text())
        bad = trace.malformed()
        if bad:
            self.result["trace_contract_violations"] = [l.as_dict() for l in bad]
            raise CheckFailed(f"server trace contract violation: {bad[0].raw!r} ({bad[0].problem})")
        return trace

    def wire(self, predicate, message: str) -> list[dict]:
        """Wait until the selected rows are all ACKed by the client peer."""
        def attempt():
            error = self.observer.error
            if error:
                raise obs.ObserverError("observer error: " + error)
            rows = self.observer.rows
            selected = predicate(rows)
            if not selected:
                return None
            acks = [r for r in rows if r["direction"] == "client_to_server"]
            try:
                return obs.correlate({"error": None, "rows": selected + acks})
            except obs.ObserverError:
                return None
        return self.wait(attempt, F.WIRE_ACK_TIMEOUT, message)

    def run(self):
        steps = [getattr(self, "m_" + name) for name in F.GUEST]
        try:
            for name, step in zip(F.GUEST, steps):
                record = {"name": name, "status": "running", "evidence": {}}
                self.result["milestones"].append(record)
                at = time.monotonic()
                try:
                    step(record["evidence"])
                    record["status"] = "pass"
                except BaseException as error:
                    record["status"] = "fail"
                    self.result["first_failed_milestone"] = name
                    self.result["failure"] = {
                        "milestone": name,
                        "type": type(error).__name__,
                        "message": str(error),
                        "traceback": traceback.format_exc(),
                    }
                    if not isinstance(error, Exception):
                        raise
                    break
                finally:
                    record["seconds"] = round(time.monotonic() - at, 3)
        finally:
            self.cleanup()
            done = {m["name"] for m in self.result["milestones"]}
            for name in F.GUEST:
                if name not in done:
                    self.result["milestones"].append({"name": name, "status": "not_run"})
            self.result["finished_utc"] = utc()
            self.result["status"] = (
                "PASS" if all(m["status"] == "pass" for m in self.result["milestones"]) else "FAIL"
            )
            self.result["command_receipts"] = self.api.receipts if self.api else []
            (self.out / "guest-result.json").write_text(json.dumps(self.result, indent=2, default=str))
        return self.result

    def cleanup(self):
        if self.observer:
            try:
                self.save_evidence("observer-final", self.observer.stop())
            except Exception as error:  # evidence only
                self.result["observer_stop_error"] = repr(error)
            self.observer = None
        for child in reversed(self.children):
            if child.exit is None:
                child.exit = child.stop(F.CHILD_STOP_TIMEOUT)
            self.result["processes"][child.name] = child.exit
        self.result["guest_processes_reaped"] = all(
            c.exit and c.exit["group_absent"] for c in self.children
        )
        redactions = {}
        for path in sorted(self.logs.glob("*.log")):
            raw = path.read_bytes()
            count = 0
            for secret in self.secrets:
                count += raw.count(secret.encode())
                raw = raw.replace(secret.encode(), b"[REDACTED]")
            if count:
                path.write_bytes(raw)
            redactions[path.name] = count
        self.result["log_redactions"] = redactions

    # ---- helpers for journey steps --------------------------------------
    def start_server(self, name: str) -> tuple[Child, object]:
        server = Child(name, [self.server_bin, F.SERVER_MODE, str(self.credentials), str(self.state_dir)],
                       self.logs / f"{name}.log")
        self.children.append(server)

        def ready():
            trace = self.trace(server)
            return trace if trace.endpoints() and len(trace.lines) >= 2 else None

        trace = self.wait(ready, F.SERVER_START_TIMEOUT, f"{name} endpoint and load lines", watch=[server])
        return server, trace

    def start_client(self, name: str, endpoints) -> Child:
        self.profile["login"]["login_port"] = endpoints.login
        self.profile["login"]["world_port"] = endpoints.world
        self.profile_path.write_text(json.dumps(self.profile))
        self.profile_path.chmod(0o600)
        client = Child(name, [self.client_bin, "--profile", str(self.profile_path)], self.logs / f"{name}.log")
        self.children.append(client)
        return client

    def await_ready(self, server: Child, client: Child) -> dict:
        def ready():
            try:
                state = self.api.state()
            except (OSError, ValueError):
                return None
            require(state.get("phase") != "failed", f"headless phase failed: {state.get('failure') or state.get('error')}")
            return state if state.get("phase") == "ready" else None

        state = self.wait(ready, F.READY_TIMEOUT, "client Ready", interval=0.1, watch=[server, client])
        require(state["zone"]["id"] == F.ZONE_ID and state["zone"]["name"] == F.ZONE_NAME, f"zone {state['zone']}")
        require(state["geometry"]["digest"] == self.geometry_digest, f"geometry {state['geometry']['digest']}")
        require(state["geometry"]["region"]["status"] == "ready", "client region data not ready")
        return state

    def entry_stages(self, server: Child, evidence: dict) -> str:
        # Client Ready can precede the server's final entry line by a tick.
        def complete():
            trace = self.trace(server)
            return trace if trace.of("entry", stage="client_ready") else None

        trace = self.wait(complete, 2.0, "server entry stage client_ready", watch=[server])
        entries = trace.entry()
        evidence["server_entry"] = [l.raw for l in entries]
        require([l.stage for l in entries] == list(F.ENTRY_STAGES), f"entry stages {[l.stage for l in entries]}")
        require(len({l.attempt for l in entries}) == 1, "entry stages span attempts")
        require(all(l.outcome == "ok" for l in entries), "entry stage not ok")
        return entries[0].attempt

    def self_spawn(self, message: str) -> dict:
        def spawn(rows):
            return checks.unique_replies(rows, "0x5089")
        proof = self.wire(spawn, message)
        require(len(proof) == 1, f"{len(proof)} self spawns")
        return proof[0]

    # ---- milestones ------------------------------------------------------
    def m_observer_self_check(self, ev):
        self.logs.mkdir(mode=0o700)
        self.evidence_dir.mkdir(mode=0o700)
        result = obs.self_check(F.CHARACTER)
        ev["status"] = result["status"]
        ev["file"] = self.save_evidence("observer-self-check", result)

    def m_server_start(self, ev):
        user = "jrny" + secrets.token_hex(8)
        password = secrets.token_hex(24)
        token = secrets.token_hex(32)
        self.secrets = [user, password, token]
        private = Path("/tmp/journey")
        private.mkdir(mode=0o700)
        self.credentials = private / "credentials"
        self.credentials.write_text(user + "\n" + password + "\n")
        self.credentials.chmod(0o600)
        self.state_dir = self.out / "state"
        self.state_dir.mkdir(mode=0o700)
        map_bytes = (self.maps / "qeynos2.map").read_bytes()
        self.geometry_digest = "sha256:" + hashlib.sha256(map_bytes).hexdigest()
        self.profile_path = private / "client-profile.json"
        self.profile = {
            "login": {"login_host": "127.0.0.1", "login_port": 0, "world_port": 0,
                      "username": user, "password": password, "character_name": F.CHARACTER},
            "expected_world": {"name": F.WORLD_NAME, "host": F.WORLD_HOST},
            "api_port": API_PORT,
            "control_token": token,
            "maps_dir": str(self.maps),
        }
        self.api = Api(token)
        server, trace = self.start_server("server1")
        self.server = server
        endpoints = trace.endpoints()
        ev["endpoints"] = endpoints.raw
        require(endpoints.zone_id == F.ZONE_ID, f"zone_id {endpoints.zone_id}")
        load = trace.lines[1]
        ev["load"] = load.raw
        require(load.kind == "persistence" and load.stage == "load" and load.outcome == "seeded",
                "empty state directory did not report load seeded")
        require(load.fields["character"] == F.CHARACTER and int(load.fields["zone"]) == F.ZONE_ID
                and load.xyz() == list(F.SEED_XYZ) and int(load.fields["heading"]) == F.SEED_HEADING,
                f"seed pose {load.raw}")
        self.endpoints = endpoints
        self.observer = obs.Observer(endpoints.zone, F.CHARACTER)
        require(self.observer.error is None, f"observer: {self.observer.error}")

    def m_entry(self, ev):
        self.client = self.start_client("client1", self.endpoints)
        state = self.await_ready(self.server, self.client)
        ev["client_ready"] = {k: state.get(k) for k in ("phase", "zone", "geometry", "self")}
        self.attempt = self.entry_stages(self.server, ev)
        ev["attempt"] = self.attempt
        self.player = state["self"]["id"]
        spawn = self.self_spawn("first self spawn ACKed")
        ev["self_spawn"] = spawn
        require(spawn["reply"]["position"] == list(F.SEED_XYZ), f"spawn {spawn['reply']['position']}")
        require(spawn["reply"]["heading"] == F.SEED_HEADING, "spawn heading")
        self.start_state = state

    def m_move(self, ev):
        require(self.start_state["self"]["position"][:2] == list(F.SEED_XYZ[:2]),
                f"client start {self.start_state['self']['position']}")
        self.api.command("journey-move-1", F.MOVE)
        moved_at = time.monotonic()
        seen_active = False

        # Never truncate the lease: wait for the client to start and then end
        # the movement on its own before the explicit stop.
        def expired():
            nonlocal seen_active
            active = self.api.state()["self"]["motion_active"]
            seen_active = seen_active or active
            lease_over = time.monotonic() - moved_at >= F.MOVE["duration_ms"] / 1000
            return lease_over and not active

        self.wait(expired, F.MOTION_EXPIRE_TIMEOUT + F.MOVE["duration_ms"] / 1000,
                  "client movement lease expiry", interval=0.02, watch=[self.server, self.client])
        ev["lease_seconds"] = round(time.monotonic() - moved_at, 3)
        ev["client_motion_observed_active"] = seen_active
        trace = self.wait(lambda: (t := self.trace(self.server)).gameplay("moved") and t,
                          F.STOP_TIMEOUT, "server moved sample", watch=[self.server, self.client])
        ev["first_moved"] = trace.gameplay("moved")[0].raw
        # A client that reports its resting position itself can make the
        # server report stop before the explicit stop command.
        ev["stopped_before_stop_command"] = bool(self.trace(self.server).gameplay("stopped"))

    def m_stop(self, ev):
        self.api.command("journey-stop-1", {"kind": "stop"})
        stop_at = time.monotonic()
        self.wait(lambda: self.trace(self.server).gameplay("stopped"), F.STOP_TIMEOUT,
                  "server stopped sample", watch=[self.server, self.client])
        ev["stop_seconds"] = round(time.monotonic() - stop_at, 3)
        time.sleep(F.STOP_QUIET)
        trace = self.trace(self.server)
        lines = trace.gameplay("moved", "stopped")
        ev["server_samples"] = [l.raw for l in lines]
        moves, stop = checks.ordered_movement(lines, self.attempt, F.SEED_XYZ)
        self.stop_line = stop
        player = self.player
        count = len(lines)

        def updates(rows):
            found = [r for r in checks.unique_replies(rows, "0x7dfc") if r["entity"] == player]
            return found if len(found) >= count else None

        proof = self.wire(updates, "movement and stop replies ACKed")
        checks.wire_positions([p["reply"] for p in proof], lines, player)
        ev["wire"] = proof
        state = self.api.state()
        ev["client_prediction"] = state["self"]
        require(not state["self"]["motion_active"], "client still moving after stop")
        self.stopped_state = state

    def m_target(self, ev):
        rats = [e for e in self.stopped_state["nearby"]["entities"]
                if e["name"].startswith(F.RAT_NAME_PREFIX) and e["npc"] and not e["dead"]]
        require(len(rats) == 1, f"{len(rats)} live rats in received roster")
        rat = rats[0]
        self.rat = rat["id"]
        ev["roster_target"] = rat
        self.api.command("journey-target-1", {"kind": "target", "entity_id": rat["id"]})
        line = self.wait(lambda: self.trace(self.server).gameplay("targeted"), F.TARGET_TIMEOUT,
                         "server targeted line", watch=[self.server, self.client])[0]
        ev["server"] = line.raw
        require(line.attempt == self.attempt and int(line.fields["entity_id"]) == rat["id"]
                and int(line.fields["incarnation"]) == F.RAT_INCARNATION
                and int(line.fields["spawn_id"]) == F.RAT_SPAWN_ID
                and int(line.fields["npc_type"]) == F.RAT_NPC_TYPE, f"target identity {line.raw}")
        rat_id = rat["id"]
        proof = self.wire(lambda rows: checks.unique_replies(rows, "0x58e2"), "target reply ACKed")
        require(all(p["reply"]["entity"] == rat_id for p in proof), "target reply for another entity")
        ev["wire"] = proof
        needle = f"server forced target to spawn {rat_id}"
        applied = self.wait(lambda: [l for l in self.client.text().splitlines() if needle in l],
                            F.TARGET_TIMEOUT, "client target application log")
        ev["client_application"] = applied

    def m_hit(self, ev):
        attack_at = time.monotonic()
        self.api.command("journey-attack-1", {"kind": "attack", "lease_ms": F.ATTACK_LEASE_MS})
        try:
            try:
                self.wait(lambda: self.trace(self.server).gameplay("melee_hit"), F.HIT_TIMEOUT,
                          "server melee_hit", interval=0.02, watch=[self.server, self.client])
            except CheckFailed:
                pass  # verdict below; attack_off is still sent
        finally:
            self.api.command("journey-attack-off-1", {"kind": "attack_off"})
        time.sleep(max(0.0, attack_at + F.ATTACK_OBSERVE - time.monotonic()))
        ev["observation_seconds"] = round(time.monotonic() - attack_at, 3)
        trace = self.trace(self.server)
        melee = trace.gameplay("attack_armed", "melee_hit", "melee_refused", "attack_off")
        ev["server"] = [l.raw for l in melee]
        hits = trace.gameplay("melee_hit")
        require(len(hits) == 1, f"{len(hits)} melee hits (refused: {[l.raw for l in trace.gameplay('melee_refused')]})")
        hit = hits[0]
        damage = int(hit.fields["damage"])
        before, after = int(hit.fields["hp_before"]), int(hit.fields["hp_after"])
        require(hit.attempt == self.attempt and int(hit.fields["source_entity"]) == self.player
                and int(hit.fields["target_entity"]) == self.rat
                and int(hit.fields["incarnation"]) == F.RAT_INCARNATION
                and int(hit.fields["spawn_id"]) == F.RAT_SPAWN_ID
                and int(hit.fields["npc_type"]) == F.RAT_NPC_TYPE, f"hit attribution {hit.raw}")
        low, high = F.DAMAGE_RANGE
        require(low <= damage <= high and before == F.RAT_MAX_HP and after == before - damage,
                f"hit arithmetic {hit.raw}")
        require([l for l in trace.gameplay("attack_off") if l.index > hit.index],
                "server logged no attack_off after the hit")
        state = self.api.state()
        require(not state["self"]["attack_on"], "client attack still on")
        def effects(rows):
            damage_rows = checks.unique_replies(rows, "0x6f15")
            health_rows = checks.unique_replies(rows, "0x37b1")
            return damage_rows + health_rows if damage_rows and health_rows else None

        proof = self.wire(effects, "damage and health replies ACKed")
        damage_rows = [p["reply"] for p in proof if p["reply"]["opcode"] == "0x6f15"]
        health_rows = [p["reply"] for p in proof if p["reply"]["opcode"] == "0x37b1"]
        require(len(damage_rows) == 1 and len(health_rows) == 1, "extra or missing damage/health reply")
        d, h = damage_rows[0], health_rows[0]
        require((d["target"], d["source"], d["type"], d["spell"], d["damage"]) == (self.rat, self.player, 4, 0xFFFF, damage),
                f"damage packet {d}")
        require(h["entity"] == self.rat and h["percent"] == checks.hp_percent(after, F.RAT_MAX_HP), f"health packet {h}")
        ev["wire"] = proof
        needle = f"EQ: combat: {F.CHARACTER} hits "
        applied = [l for l in self.client.text().splitlines() if needle in l and f"for {damage} damage" in l]
        require(applied, "client combat log has no hit")
        ev["client_application"] = applied

    def m_camp(self, ev):
        camp_at = time.monotonic()
        self.api.command("journey-camp-1", {"kind": "camp"})
        try:
            code = self.client.process.wait(timeout=F.CAMP_TIMEOUT)
        except subprocess.TimeoutExpired:
            raise CheckFailed(f"client did not exit within {F.CAMP_TIMEOUT}s of camp")
        self.client.exit = self.client.stop(F.CHILD_STOP_TIMEOUT)
        ev["client_exit"] = {"exit": code, "seconds": round(time.monotonic() - camp_at, 3), "signal_sent": None}
        require(code == 0, f"client exited {code} after camp")
        require(self.server.alive(), "server exited during camp")
        trace = self.wait(lambda: (t := self.trace(self.server)).persistence("save") and t, 2.0,
                          "server save line", watch=[self.server])
        ev["server"] = [l.raw for l in trace.lines if l.kind == "persistence" or (l.outcome or "").startswith("camp")]
        require(trace.gameplay("camp_started") and trace.gameplay("camp_completed"), "camp not started/completed")
        saves = trace.persistence("save")
        require(len(saves) == 1 and saves[0].outcome == "ok", f"save {[l.raw for l in saves]}")
        pose_file = self.state_dir / F.POSE_FILE
        raw = pose_file.read_bytes()
        pose = checks.parse_pose(raw)
        ev["saved_pose"] = {"raw_ascii": raw.decode(), "sha256": hashlib.sha256(raw).hexdigest(),
                            "mode": oct(pose_file.stat().st_mode & 0o777)}
        require(pose["format"] == F.POSE_FORMAT and pose["character"] == F.CHARACTER and pose["zone"] == F.ZONE_ID,
                "pose record identity")
        require(checks.pose_line_matches(saves[0], pose), "save line differs from pose file")
        require(pose["xyz"] == self.stop_line.xyz(), f"saved {pose['xyz']} != stop {self.stop_line.xyz()}")
        require(pose["xyz"] != list(F.SEED_XYZ), "saved pose equals seed")
        self.pose, self.pose_raw = pose, raw

    def m_restart(self, ev):
        ev["first_observation"] = self.save_evidence("observer-session1", self.observer.stop())
        self.observer = None
        self.server.exit = self.server.stop(F.SERVER_STOP_TIMEOUT)
        ev["server1_exit"] = self.server.exit
        require(self.server.exit["exit"] in (0, -signal.SIGTERM), f"server1 exit {self.server.exit['exit']}")
        require(self.server.exit["group_absent"] and self.client.exit["group_absent"], "first processes remain")
        server, trace = self.start_server("server2")
        self.server = server
        endpoints = trace.endpoints()
        ev["endpoints"] = endpoints.raw
        load = trace.lines[1]
        ev["load"] = load.raw
        require(load.kind == "persistence" and load.stage == "load" and load.outcome == "ok", f"load {load.raw}")
        require(checks.pose_line_matches(load, self.pose), "loaded pose differs from saved pose")
        self.endpoints = endpoints
        self.observer = obs.Observer(endpoints.zone, F.CHARACTER)
        require(self.observer.error is None, f"observer: {self.observer.error}")

    def m_relog(self, ev):
        self.client = self.start_client("client2", self.endpoints)
        state = self.await_ready(self.server, self.client)
        ev["client_ready"] = {k: state.get(k) for k in ("phase", "zone", "geometry", "self")}
        ev["attempt"] = self.entry_stages(self.server, ev)
        spawn = self.self_spawn("relog self spawn ACKed")
        ev["self_spawn"] = spawn
        require(spawn["reply"]["position"] == self.pose["xyz"] and spawn["reply"]["heading"] == self.pose["heading"],
                f"relog spawn {spawn['reply']['position']} heading {spawn['reply']['heading']}")
        x, y, z = self.pose["xyz"]
        require(state["self"]["position"] == [x, y, z - F.CLIENT_FEET_OFFSET],
                f"client feet {state['self']['position']}")
        require((self.state_dir / F.POSE_FILE).read_bytes() == self.pose_raw, "pose file changed after reload")


def main(argv=None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", required=True)
    parser.add_argument("--server", required=True)
    parser.add_argument("--client", required=True)
    parser.add_argument("--maps", required=True)
    args = parser.parse_args(argv)
    os.umask(0o077)

    def terminate(signum, frame):
        raise SystemExit(128 + signum)

    signal.signal(signal.SIGTERM, terminate)
    result = Journey(args).run()
    print(json.dumps({"status": result["status"], "first_failed_milestone": result["first_failed_milestone"]}))
    return 0 if result["status"] == "PASS" else 1


if __name__ == "__main__":
    sys.exit(main())
