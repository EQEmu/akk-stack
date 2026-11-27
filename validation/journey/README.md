# Headless Qeynos2 journey

`scripts/qeynos2-journey` runs the Rust server's Qeynos2 journey with the
headless EQOxide client in a disposable rootless container. The journey is
login, zone entry, move, stop, target, one hit, camp, server restart, and relog
at the saved position. It replaces the hand-copied `worker.py` and `capture.py`
directories under `~/.local/state/eqemu-rust-*`. Those directories remain
historical evidence.

Routine runs do not seal artifacts and do not run the native C++ comparison.
Those remain separate, explicit steps.

## Run

```sh
scripts/qeynos2-journey run \
  --server /abs/bump-eqemu-rust --server-revision FULL_SERVER_SHA \
  --client /abs/eqoxide-headless --client-revision FULL_CLIENT_SHA \
  --maps /abs/dir-with-qeynos2.map-and-qeynos2.wtr
```

The script hashes and copies every input and records those hashes. It never
compares against a hard-coded binary hash. `--server-revision` and
`--client-revision` are labels only. The script does not check that a binary
was built from the named revision. Use `build-server` to produce a binary
together with its commit receipt. `--label` adds free text. `--output-root`
chooses the parent of the run directory and must be outside this source tree.
Maps must match the pinned fixture hashes in `fixture.py` unless
`--allow-unpinned-maps` is given.

One-time preparation loads the runtime image into the harness data root:

```sh
scripts/qeynos2-journey prepare-image \
  --archive ~/.local/state/eqemu-map-translation/pr118-beb1068-20261121-v1/runtime-legacy-layout-v1.tar
```

To build one exact server commit offline and run its tests in the same image:

```sh
scripts/qeynos2-journey build-server --repo /abs/bump-eqemu-rust --commit FULL_SHA
```

This writes `build.json` with the commit, tree, source archive hash, test
summaries and binary hash, plus the binary itself, under
`~/.local/state/eqemu-rust-journey/builds/`.

## Environment

Each command starts its own `dockerd-rootless.sh` as a transient user systemd
unit, `eqemu-rust-journey-<id>.service`, on its own socket. The unit has
`RuntimeMaxSec=3600`. All commands share the data root
`~/.local/state/eqemu-rust-journey/docker-data`, which holds only the runtime
image. A non-blocking lock in that directory makes concurrent commands fail
instead of sharing it. The default image is the PR118 runtime image
`sha256:630e294d…`: Debian 12, Python 3.11 and OpenSSL 3 with the legacy
provider.

The container has no network, 2 GiB memory without swap, one CPU, 256 PIDs, a
read-only root filesystem, a private `/tmp`, all capabilities dropped except
`NET_RAW`, and `no-new-privileges`. Inputs and the harness copy are mounted
read-only, and the run's `output/` is the only writable mount. Credentials and
the control token are generated inside the container. After the processes
exit, any occurrence of those values in the logs is replaced with
`[REDACTED]`, and `log_redactions` counts the replacements. Nothing else in the
logs is changed.

The command removes its container and stops its daemon unit in all cases,
including SIGINT or SIGTERM. It records each step in `cleanup`. It does not
touch `bump-akk-stack-validation`, the system Docker daemon, or other
`eqemu-*` units and data roots.

## Milestones

In order: `inputs`, `environment`, `observer_self_check`, `server_start`,
`entry`, `move`, `stop`, `target`, `hit`, `camp`, `restart`, `relog`,
`cleanup`. The journey stops at the first failure. Each later milestone is
`not_run`, except `cleanup`, which always runs.

| Milestone | Passes when |
| --- | --- |
| `observer_self_check` | Known loopback datagrams of all five selected opcodes, and their ACK, are captured and decoded exactly. This check found the real observer bug in the first movement run. |
| `server_start` | The endpoint line is first, with `zone_id=2`. The empty state directory reports `load outcome=seeded` at the seed pose. |
| `entry` | The client reports Ready in zone 2, with the pinned geometry digest and ready region data. The seven `entry` stages appear in order on one attempt, all `ok`. The ACKed self spawn is at the seed pose. |
| `move` | One 200 ms westward `move_for` runs and the client's lease ends on its own. The server reports at least one `moved` sample. |
| `stop` | After `stop`, the server reports exactly one `stopped`, within 8 s. All samples move strictly west on unchanged Y/Z, with sequences moving forward, and the stop equals the **final** accepted sample. Each sample has one ACKed `0x7dfc` reply with the same position. |
| `target` | The rat is selected from the roster by name. The server's `targeted` line matches its entity, incarnation, spawn and NPC type. The `0x58e2` reply is ACKed, and the client log shows the target applied. |
| `hit` | Exactly one attributed `melee_hit` occurs with 1–3 damage from 11 HP, followed by `attack_off`. The `0x6f15` and `0x37b1` replies match the trace and are ACKed. The client logs the hit. |
| `camp` | The client exits 0 on its own within 60 s. The server logs `camp_started`, `camp_completed` and one `save outcome=ok`. The save line, the pose file and the stop pose agree. |
| `restart` | `server1` stops on TERM. A new process on the same state directory reports `load outcome=ok` with the saved pose. |
| `relog` | A fresh client reaches Ready. All entry stages pass again. The ACKed self spawn has the saved pose and heading. The client reports its feet at Z − 3.125. The pose file is unchanged. |

The pinned client d034b7e reports its resting position only at a 1300 ms
keepalive, and its first stationary packet about 1300 ms after that. The stop
check therefore waits for the server's `stopped` line and compares against the
last sample. It passes whether the stop arrives before the stop command, as a
client that reports rest itself may do, or after it. `stop.evidence` records
`stop_seconds` and `move.evidence.stopped_before_stop_command`.

The journey never uses command receipts or client events as evidence. Effects
are proven by the server trace, by ACKed wire replies, and by client log
lines. Server trace parsing lives only in `servertrace.py`. A line that starts
with a contract prefix but changes a known shape fails the current milestone
as a trace contract violation.

## Result

`<run-dir>/result.json`, schema `qeynos2-journey-result/v1`:

* `status` is `PASS` or `FAIL`, and `exit_code` is the process exit code.
* `first_failed_milestone` and `failure` (`milestone`, `type`, `message`)
  name the first failure. `guest_traceback` holds the guest traceback.
* `milestones` lists every milestone with its `status` (`pass`, `fail` or
  `not_run`) and `seconds`. Guest milestones also carry `evidence`.
* `identity` records the hashes, sizes and paths of the server and client,
  their revision labels, and the hash of each map with whether it matches the
  pin.
* `fixture` records the fixture constants used.
* `harness` records the Stack commit, whether the harness files were dirty,
  and the hash of each harness file that ran.
* `image`, `environment` (daemon record and container argv), `container`
  (exit, OOM, timeout), and `cleanup` (container and daemon) describe the
  environment.
* `guest` holds the process exits, redaction counts, trace contract
  violations and command receipts.
* `artifacts` gives the paths to the raw logs (`output/logs/server1.log`,
  `client1.log`, `server2.log`, `client2.log`), `guest.log`, observer evidence
  and the state directory.

## Exit codes

| Code | Meaning |
| --- | --- |
| 0 | Every milestone passed, including cleanup. |
| 1 | A journey milestone failed. Cleanup completed. |
| 2 | Invalid arguments or inputs. Nothing was started. |
| 3 | The environment failed: daemon, image, container or guest crash, timeout or interruption. |
| 4 | Cleanup could not be confirmed, whatever the journey verdict. Check `cleanup`. |

## Tests

```sh
python3 -B -m unittest discover -s tests/journey -v
```

These tests cover the trace contract, the movement and wire checks (including
the old first-sample assertion as a red control), pose parsing, input identity
and the result table. Live observer tests run in `unshare -rn`, including a
negative control that reproduces the historical outgoing-only filter. No test
runs a candidate binary.
