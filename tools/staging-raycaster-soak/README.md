# Bounded staging raycaster observer

Implementation for central-z9g4 / central-cs66. This directory alone owns the helper,
examples, tests and this source assessment. Parent Stack owns deployment, actual
baseline/limits, independent reviews, rollback, T3 initial/final checks and the Ops
worklog `2026-11-15-rust-raycaster-staging-soak.md`. No live validation was performed.

The Python standard-library monitor queries exactly
`eqemu-staging-eqemu-server-1` and `eqemu-staging-mariadb-1` with read-only Docker
inspect/top. It never starts/stops monitored services or calls SQL, SSH or player commands.
Two fixed Docker exec calls verify and run the existing read-only readiness script
inside the server container, where its loopback world console is reachable. The only extra executable is the parent's reviewed existing
`bin/staging-health.py`, invoked with Python `-I` and no arguments inside that fixed container. Parent read the live script: it uses the container-local world console to query
zone readiness. Host execution would target the wrong loopback namespace. Both
host-visible and container-visible bytes must match the declared hash. Ready,
zone count and the two static zone names are validated, not just exit status. Its hash is checked every sample; its
output is drained under a cap and discarded, never stored or printed.

## Parent preparation and invocation

Copy `manifest.example.json` to a private reviewed manifest. Null limits and the
placeholder health SHA intentionally fail validation. Supply the exact deployed
release, production source commit, backend, world and zone SHA256, health-script
absolute path/hash, expected zone count, the fixed four native log paths, explicit log-observation contract and filesystem paths.
The example pins the supplied matched ON binaries from source
`1bcb08a994568fef84516f94614e463703eca574`. It does not attest the live deployment.
The backend and release are parent attestations. Executed world/zone hashes are
independently checked, and initial container image IDs are retained.

Before use, parent must predeclare limits from its live baseline receipt:

- Container memory in bytes and average CPU cores over each sample interval.
  Known allocation is server 6 GiB/2 CPU and DB 2 GiB/1 CPU. Allocation is not a
  safe abort threshold. Select headroom from observed usage, below allocation.
- Maximum per-process RSS, minimum host MemAvailable, minimum filesystem free
  bytes and maximum increase in visible on-disk log-family footprint high-water from the initial footprint.
- Exactly the four `logs` in the example, mapped by the verified host
  `/etc/logrotate.d/eqemu-staging` policy, SHA256
  `908247ab7494a776b017c23caa121c02a95ffba61fb5cb94164bb95501198478`.
  The policy is verified each sample. Docker/DB journals and other native logs
  are excluded; no quietness claim is made for them. Include the log/data/output
  filesystems in `disk_paths`. Unsupported cgroups, unreadable inputs and policy
  changes fail closed. Old manifests lack the new semantics and are refused.


Exact invocation, after replacing deployment paths:

```sh
/usr/bin/python3 -I -B /opt/eqemu-soak/monitor.py \
  --manifest /etc/eqemu-soak/manifest.json \
  --output /var/lib/eqemu-soak/run-UNIQUE-ID
```

Use a new output directory for every attempt. Default example duration is 24h;
manifest duration must be finite, positive and <=48h. Samples refuse lateness over90seconds and run at monotonic
five-minute targets with an endpoint sample, at most 577 total. Each sample has a
90s wall-time alarm, each subprocess a 20s timeout and 1 MiB pipe cap. Each
executable hash reads at most 512 MiB; unchanged executable identities reuse hashes.
The helper checks PID/starttime and executable device/inode/size/mtime each sample,
world/zone hashes and count, container/image/start identity, cgroup CPU usage,
current memory, allocation and memory events, process CPU/RSS, host memory and
filesystem free space. Each CPU counter has a monotonic read window; interval checks use the shortest
possible interval between successive windows, conservatively covering collection
time. CPU averages do not detect every short spike.

### Rotation, observed content and visible footprint

The selected future contract is `copytruncate-visible-footprint-v1`. It is a
new contract, never a reinterpretation of the stopped 13h15m/159-sample run.
There are exactly four active paths. Only `.1`, `.2.gz` through `.7.gz` belong
to each policy family. A bounded directory-name check, at most 4096 entries,
rejects unexpected suffixes instead of discovering more logs. Every accepted
file must be regular, single-link, nonsymlink, owned1000:1000 and not group/world
writable. Before/after read identity/size/timestamps must be stable. Missing active
files, archive-generation holes, malformed gzip, unexpected replacements or
unverifiable transitions fail closed.

Every plaintext range actually read is scanned for BAD/nonfinite/query-failure
patterns, including preexisting archives and baseline/verification anchors. A
private256-byte tail catches split BAD words across continuous append reads. A same-inode shrink or changed archive inventory requires a new
`.1`, matching prior offset anchor and the expected archive content-generation
shift. The helper validates compressed archive data/CRC with bounded expansion;
compressed bytes, expanded bytes, active reads and anchors share **one1MiB
budget per complete sample across all four families**, not a new cap per archive.
Backlog, malformed/oversized input, read races or exhaustion fail NONPASS.
A matching error in preexisting content also fails the observation. The receipt
does not classify that content as newly generated. Directory names are checked
again after the reads; a new unexpected suffix fails the entire sample.

A policy-consistent copytruncate is an explicit event recording the observation
window, old offset, available archive bytes and exact observed spans/counts/hashes.
Visible unread archive-tail and new active-prefix bytes are scanned for the
unchanged BAD/nonfinite/query-failure patterns. Separate unproved epochs are not
joined. `GAP_POSSIBLE` becomes sticky from the first accepted rotation and can
never clear. No missing-byte, recovered-byte, uninterrupted-content or absence-of-
errors claim is made for the unobserved gap. This is a finite scanner, not log
reconstruction or a complete native error vocabulary.

`log_growth_bytes` now means **increase in the high-water of visible on-disk
footprint**, summed over the four active files and finite policy archives,
relative to the initial footprint. Each sample records baseline/current/high-water
and increase. Archive file sizes are physical compressed sizes where applicable.
Compression/deletion may hide generated volume; this metric is NOT cumulative
bytes generated. Rotation never resets the high-water. The selected future limit
remains256MiB, with the separate20GiB free-disk guard unchanged. No public policy
or logging change is made by the observer.

## Output and abort semantics

Total helper-created file contents are capped at 16 MiB, with 64 KiB reserved for
the terminal receipt. Private directory mode is 0700 and files are 0600, then
0400 for exclusive one-time artifacts. No run can resume or overwrite another.
`manifest.json` freezes inputs; `baseline.json` freezes the first complete sample;
`samples.jsonl` stores complete samples; `partial.json` retains a failed sample;
`summary.json` is an exclusive terminal receipt published only after private
write, permission, fsync and readback checks. Directory-sync failure removes the
new publication and returns artifact failure. Consumers still require process
exit0 and the explicit scoped summary; missing receipts are incomplete. An initial failed sample has no
complete baseline, only partial evidence. Successful prior samples stay intact.

Nonfinite/invalid data, command failure/timeout, unhealthy containers, any observed
restart history, PID/executable identity change, OOM history, increased memory
events, exceeded resource/disk/log limits, signal interruption, artifact exhaustion
or observer exception returns NONPASS and stops monitoring. Exit 1 means recorded
NONPASS; exit 2 means setup/artifact failure. A completed run records `resource_health_status=PASS`, the footprint metric and
last complete footprint, and separate log coverage. If any rotation gap occurred,
status is **PASS_WITH_LOG_COVERAGE_GAP**, never plain PASS. Without an observed
rotation it is PASS, still scoped to sampled resource/health/identity/visible
footprint. `log_continuity=UNPROVEN` and `content_claim=observed_bytes_only` remain
explicit. Both completed resource outcomes return0; observer/fatal guard failure
returns1/NONPASS, with `resource_health_status=NONPASS`. Any observed BAD pattern
remains fatal. A coverage-gap outcome is not whole-runtime success or proof of
no native errors. `end_probe_eligible=false` prevents reuse as an automatic old
PASS gate; a separate explicit scoped root selection is required for future end
probes. No outcome establishes collision correctness, graceful shutdown or rollback.

Safe stop for the example unit:

```sh
systemctl stop eqemu-raycaster-soak.service
```

SIGTERM/SIGINT produce NONPASS and a terminal abort receipt. No monitored service
is stopped. Parent decides any rollback or action. SIGKILL, machine death, disk
write failure or external deletion can prevent a terminal receipt. An absent
summary is incomplete/NONPASS, never green. There is no restart or truncation.
The unit/timer files are examples only, not installed by this helper. The unit
stops before 48h and permits 30s for a receipt. A requested 48h run can therefore
end NONPASS at that hard ceiling; use 24h normally. Root is shown for Docker/proc
visibility, subject to parent's access review. The one-shot timer starts once.
No recurring schedule is supplied. Parent schedules T3 checks separately.

Host-only checks:

```sh
python3 -B -m unittest discover -s tools/staging-raycaster-soak -v
python3 -B -c 'import ast,pathlib; [ast.parse(p.read_text()) for p in pathlib.Path("tools/staging-raycaster-soak").glob("*.py")]'
```

## Historical private-probe assessment, 2026-11-15

The following is the original dated assessment, before the separate reviewed
PR39 private fixture and initial Q2/PoK qualification. It is retained as history,
not a current probe blocker. Source-only changes here do not change PR39 or
qualify another runtime. The initial native PASS and failed 24h attempt remain
separate retained evidence.

Source inspected in the supplied Server worktree, without executing it:
`tests/server_collision_ab/{README.md,run.py,scenario.py,route.json,pok-route.json}`,
`tests/map_server_validation/runtime.py`, `zone/collision_observation.h`,
`zone/quest_parser_collection.cpp`, `zone/main.cpp`, `zone/gm_commands/instance.cpp`,
`common/eqemu_config.{cpp,h}` and `common/path_manager.cpp`.

No safe persistent fixture is currently supplied. `runtime.py` creates/imports a
fresh smoke DB, deletes public zone spawns and replaces `quests/qeynos2/v0/2011.pl`.
`scenario.configure` changes spawn 10863, shared NPC 2011 attributes and global
rules/logging, then installs the Rat quest in q2 or PoK v0. These steps are suitable
only for the disposable fixture. Do not copy that quest over live Rat content,
delete public spawns, change shared NPC data/rules or reset/import staging DB.

Existing seams worth a separate bounded fixture design, not certified here:

- `zone/main.cpp:203-249` accepts a zone/port, launcher and instance ID; instance
  management exists in `zone/gm_commands/instance.cpp`. A task-owned private
  instance/version could isolate runtime entities from public zones. Creation,
  expiry, ownership, no public membership and cleanup still need review.
- `quest_parser_collection.cpp:1083-1102` selects `quests/<zone>/v<version>/...`
  before zone/global fallbacks. Config directory keys include quests/plugins,
  maps/logs/shared memory. `EQEmuConfig::parseFile` and PathManager locate a server
  root/config. A separately launched owned zone with a private server root,
  config and quest tree is a candidate; shared-world routing, ports, fallback
  scripts and config discovery need proof before using it on persistent staging.
  No unsupported per-instance config switch is assumed here.
- Existing quest FindGroundZ/CheckLoS and ordinary NPC MoveTo/saveguardspot paths
  are exercised by the fixture. The q2 route is actual OFF AdjustRoute nodes;
  PoK uses public grid 3 points 41-43. Real maps, fixed input hashes, exact native
  results, finite final pose, corridor/FixZ and destination checks remain required.

`EQEMU_COLLISION_OBSERVE=server-collision-npc-2011` gates only NPC type 2011, not a
private instance or task namespace. `collision_observation.h:11-37` has a
process-lifetime 4096-record budget shared by eligible calls and silently stops
emitting at exhaustion. Enabling it on a shared zone could observe public Rats
and spend the budget on them. A new private NPC type would not pass this gate.
A private zone process with only a task-owned runtime NPC of type 2011 might use
it without modifying the shared npc_types row, but this has not been implemented
or proven safe. Review ordinary spawning hooks and hostility/AI configuration.
Do not enable it on existing public processes based on this assessment.

Initial/hourly fixed ground/LoS plus ordinary routes therefore remain a finite
fixture gap. Parent needs a reviewed private-instance/process recipe, task-owned
quest/config files and data namespace, real-map load evidence, no public actor
interaction, explicit per-probe budget accounting and a stop/cleanup receipt.
Exhaustion, missing expected records or missing probe completion must be NONPASS.
The existing 4096 lifetime budget must cover the predeclared probe count or the
probe plan must be reduced; no unlimited tracing or new Server API is proposed.
The read-only observer is independently usable and makes no probe-success claim.
