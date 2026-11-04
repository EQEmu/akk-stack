# Disposable validation profiling

Profiling is opt-in on the master worker CLI. Ordinary build flags, workload
and cleanup gates remain the defaults. This source has a new identity. It does
not claim equality with installed ordinary or diagnostic v1/v2/v3 identities.

```sh
scripts/validate-worker-candidate --repo /absolute/eqemu --commit FULL_COMMIT \
  --config /etc/eqemu-validator/profiling.json \
  --profiling timeline --profile-output /private/fresh-run-directory
```

`timeline`, `heaptrack` and `perf` select one mode. A separate process samples
fixed world/zone executable inodes under the native UID every 200 ms. It writes
and flushes local data independently of observer probes. A second process tails
it to bounded serial frames. Console backpressure cannot block local sampling.
A VM hard kill can lose unexported bytes. Received prefixes remain partial
evidence. Scheduling, inaccessible procfs or OOM can delay or kill the sampler
itself. Check gaps and transport status before drawing conclusions.

The timeline records monotonic timestamps, PID plus start ticks, CPU user/system
ticks, physical RSS, kernel-reported HWM and separately labeled virtual size.
The summary reports sampled RSS maximum, not true peak. Observed HWM is a
separate kernel estimate and may be unavailable after death. RSS includes shared
pages and profiler overhead; summing it does not give private heap. Guest
meminfo/PSI are guest-wide. Cgroup path/counters describe the sampler's actual
cgroup, including siblings, not one process or host QEMU memory. Boot identity
and clock frequency are metadata. Helpers and processes shorter than a sampling
interval can be missed. Old identities remain explicit after exit/lost access.

Trusted `Session.stage(name, state)` events carry monotonic times independently
of samples. The adapter records shared-memory preparation and readiness. This
interface permits later reviewed Server events without hardcoding map phases.
This change adds no Server events.

## Allocation and CPU modes

Heaptrack uses its preload library and a FIFO drained by the independent
sampler. It profiles world/zone directly, retaining their native PIDs/return
codes. Allocation stacks, live requested heap and churn differ from mmap,
shared-memory or allocator resident overhead. `X` argv and `S` suppression
records are stripped before persistence. The bounded interpreter and
`heaptrack_print` run while guest binaries/debug symbols exist, with separate
stdout and diagnostics. Keep raw and interpreted files together. Massif is a
possible separately reviewed fallback, never a silent substitution.

Perf preflight opens `task-clock:u` under the native UID and NoNewPrivileges
route before workload launch. Collection attaches to native PIDs at 99 Hz,
using frame-pointer callchains limited to 32 frames and a 64-page mmap buffer.
Startup before attachment is uncovered. This samples user CPU time, not hardware
cycles, wall-clock latency or off-CPU activity. It records no system-wide/kernel
stacks or DWARF stack-memory dumps. Perf headers are finalized before raw export.
The bounded report includes header/loss diagnostics. Guest preflight exit, UID,
selected event, paranoid policy value and bounded diagnostics are retained even
when the requested event is denied. Unresolved frames, lost
samples, throttling and finalization failures remain coverage limitations.
Hardware counters may be unavailable in KVM even when software events work.
Missing tools and denied requested events are infrastructure non-pass. No host
capability, ptrace policy, sysctl or service privilege is changed.

Profiling builds use RelWithDebInfo, native `-fno-omit-frame-pointer` and Rust
`-C force-frame-pointers=yes -C debuginfo=2`. Metadata binds CMake cache, compiler
database, compiler bytes/version, binary SHA256/build notes, tool bytes,
source/tree, input media and public fixture. Sanitizer flags and ASan/UBSan
symbols are rejected. Sanitized correctness is a separate run; master gains no
sanitizer mode here. Do not assume Heaptrack/ASan compatibility.

Metadata labels the fixed normal-world workload, readiness warmup and one
repetition. This is not a production performance baseline. Compare identical
source, inputs, flags, workload, warmup and repetition counts using matched
unsanitized runs with/without tools. Keep sanitizer correctness and
production-like baselines separate. No overhead correction is invented.

## Artifacts and failure

Workload verdict, native exits before/after cleanup, analyzer exits, export
result, database cleanup and VM cleanup remain separate. Profiling can make a
passing workload infrastructure non-pass; it cannot make a failed workload pass
or establish cleanup. Cleanup can terminate a target before Heaptrack flushes.
SIGKILL/OOM/cancel/deadline traces may omit allocations/frees even when readable.
Apparent leaks after abrupt death are not leak evidence. `complete` describes
machinery collection/export, not native trace finalization or correctness.

Raw files are separate from the small result. Limits are 4 MiB per file, 16 MiB
total transport, 64 KiB metadata/stages and 512 KiB per analyzer stream.
Oversized allocation/timeline files stop retention but keep draining and label
truncation. Tool timeout/overflow and malformed/offset export errors are explicit
non-pass. Receivers reject unknown names, paths, symlinks, repeated offsets and
oversized bytes. Chunk flushes do not claim power-loss durability. Raw profiles
contain source/library paths and address metadata. Do not publish them
automatically. They contain no intentional credential, argv, environment or
process-memory dump.

The worker retains one private collection in its state `last-profile`, replaced
by the next profiling collection. It survives disposable scratch cleanup.
Export needed evidence before another profiling run. Clients create fresh
mode-0700 directories and mode-0600 files. Broken sockets retain prefixes.
Read-only recovery requires the exact still-retained run ID and starts no VM:

```sh
scripts/validate-worker-candidate --config /etc/eqemu-validator/profiling.json \
  --export-profile EXACT_RUN_ID --profile-output /private/fresh-export-directory
```

Export exit zero means bytes exported. `workload_exit_code` is the original
native observer verdict, or null if it was unavailable. `execution_exit_code`
is the overall worker verdict. The collection's bounded `result_receipt` keeps
native/database/VM cleanup, collector/analyzer and transport outcomes separate.
This receipt includes only finite status codes and flags, with no raw error text,
even after later jobs replace last-result. Last-result stores the bounded
inventory, not raw bytes. Delete private
exports when no longer needed; root may remove the retained copy after export.
The original client transfer has its own completion/error flags, atomically
updated after that transfer. A later recovery export reports its own exit status
without rewriting the original execution or transfer outcome.
Before the original transfer, the collection durably records receipt finalization
as pending, partial and overall non-pass. Recovery repairs that receipt from the
matching bounded outcome or preserves pending uncertainty and the active marker.
Repeated receipt-write failure cannot turn an unknown transfer into success.
Heaptrack shutdown drains queued FIFO records within a one-second budget using
the same privacy filter. Queued remainder or a partial record marks finalization
incomplete and non-pass. An empty queue does not prove a complete native trace.

## Offline tools

The optional tool tar contains `manifest.json` and at most 64 regular
`debs/*.deb`. It pins package name/version/bytes/SHA256 and tool path/SHA256.
Select independently trusted public packages and a compatible dependency
closure for the guest distribution. Host Ubuntu 26.04 fixture packages do not
qualify the Ubuntu 24.04 guest. Build a data-only bundle from explicit debs:

```sh
python3 -B validation/worker/profile_inputs.py --mode heaptrack \
  --deb /private/noble/heaptrack_VERSION_amd64.deb \
  --deb /private/noble/libheaptrack_VERSION_amd64.deb \
  --deb /private/noble/EXACT_DEPENDENCY_VERSION_amd64.deb \
  --output /private/fresh-profilers.tar
```

This extracts package data into a temporary directory and executes no maintainer
script. Review the returned manifest/SHA256, then supply the exact pin:

```sh
scripts/validate-worker-candidate --repo /absolute/eqemu --commit FULL_COMMIT \
  --config /etc/eqemu-validator/profiling.json --profiling heaptrack \
  --profiler-input /private/fresh-profilers.tar --profiler-input-sha256 FULL_SHA256 \
  --profile-output /private/fresh-heaptrack-directory
```

Only the disposable guest installs packages, with no downloads/upgrades/removals.
Conflicting installed versions refuse. Installed tool bytes must match pins.
Without a bundle, requested tools must exist and their exact bytes are recorded.
There is no host package installation.

## Additive release proposal

Prepare a finite package from a clean committed checkout:

```sh
python3 -B validation/worker/profile_release.py prepare \
  --base b9996308a027ef5a3432dc451039f9fa2974b072 --package /private/fresh-release
```

It includes only the reviewed worker/frontend closure, a new independent code
manifest, config, service/socket, exact AppArmor profile, operator and a finite
`retained.json` snapshot of the old public-readable configs/code/units/policy.
That snapshot records actual file hashes, sizes, UID/GID and modes, including
ordinary UID1000 exceptions, and is bound by the package SHA256. Preparation
does not inspect private active markers or the worker lock. Every operation
compares current retained assets to this reviewed snapshot under the existing
shared lock before creating a journal or changing any asset. The first apply
cannot adopt a newly observed baseline. Later operations must also match it.
Preparation runs no setup/staging or installed service commands.
Review all bytes, the returned package/operator pins and retained preconditions.
Before root execution, copy the package into a fresh root-owned mode-0700
directory, preserving no submitter ownership. Verify the copied operator and
package hashes against literal reviewed pins supplied directly to sha256sum.
Do not read expected pins from a submitter-writable checksum file. The operator refuses an unprotected
package directory; execute its protected copy.
The following are separate proposed root steps, not authorization to run them:

```sh
(
set -eu
sudo sha256sum --check - <<'REVIEWED_PINS'
REVIEWED_OPERATOR_SHA256  /root/reviewed-profile-release/operator.py
REVIEWED_PACKAGE_SHA256  /root/reviewed-profile-release/package.json
REVIEWED_PINS
sudo python3 -I /root/reviewed-profile-release/operator.py apply --package /root/reviewed-profile-release --package-sha256 REVIEWED_SHA256
)
```

Replace both checksum placeholders with the reviewed literal hashes before
running the command. The subshell must stop on failed verification before Python
runs. Repeat the complete verification block for each separately chosen `verify`,
`activate` or `rollback` operation, replacing only `apply`. Do not chain activation
or rollback after publication. The final handoff includes exact paths and literal
pins for each operation.

Apply publishes only `/srv/eqemu-validator-profiling/FULL_COMMIT`,
`/etc/eqemu-validator/profiling.json`, private state, unit/socket and profile.
It never replaces an existing asset. Activate loads this policy and starts only
this socket without enabling it at boot; no VM starts. Verify checks closure,
root ownership/modes and unit/policy syntax. Rollback removes only matching owned
files and retains nonempty evidence state. Drift, unknown files, collisions or
uncertain activity refuse. A root-owned journal supports repeated/interrupted
operations. Changed new assets require inspection, not forced deletion.

Every operation verifies all four retained ordinary/v1/v2/v3 selections, records
actual hashes/metadata, checks service/AFK/QEMU quiescence and holds the existing
ordinary `/var/lib/eqemu-validator/worker.lock`. This must already be a regular
owned mode-0600 file. The new runtime uses the same lock for execution/cleanup;
no candidate can choose/create another lock. New assets are root-protected.
Submitter-owned ordinary helpers remain owned as found. Prior snapshots do not
substitute for checks at operation time.

Guest tools, event/symbol availability, installed systemd/AppArmor behavior and
real VM cleanup require later qualification after a separate activation decision.
Host results alone do not qualify the route or authorize an EQEmu rerun.

## Trusted host checks

```sh
python3 -B -m unittest discover -s tests/worker -v
python3 -B -m unittest discover -s tests/validation -v
python3 -B tests/worker/run_profiling_fixtures.py --output /private/fresh-fixtures \
  --heaptrack-root /private/extracted-verified-host-packages
```

Only the adjacent finite C fixture is compiled/executed. It holds 16 MiB live,
performs 20,000 temporary 4 KiB allocations and executes `busy_stack`. A separate
run deliberately uses SIGKILL. Actual perf denial is recorded without changing
policy. No worker/VM, Cargo or EQEmu candidate runs. Publication tests use a fake
filesystem and mocked root/service calls.

## Consolidated source contract

The sanitizer correctness route and profiling route are separate selections.
`--profile asan-ubsan-native-v1` cannot be combined with `--profiling`, profiler
inputs or profile export. Packaging and the worker request parser reject combined
selectors, including explicit null request fields. Profiling uses an unsanitized
symbolized build; its Rust frame-pointer/debug flags do not carry into ordinary
or sanitizer builds. Heaptrack preload is never combined with sanitizers.

The combined release includes both sets of helpers in its finite source identity.
Its hashes differ from historical installed releases. Preparing it does not admit
it or qualify any guest/application workload. Sanitizer admission preparation
keeps the original 15-helper retained inventory separate from the new 19-helper
release inventory; it does not require new profiling helpers in old releases.
Ordinary, diagnostic and profiling selections still use the same exclusive lock.

Frontend identity separately hashes its own `sanitizers.py`, even when an installed
copy lives elsewhere. Installed identity recognizes the retained master/v1/v2/v3
runtime SHA256 values and binds their explicit 14/15-helper inventories. Every old
helper must exist and its bytes participate in identity; a changed historical
runtime cannot select the historical inventory. These are read-only identity
contracts, never admission or execution authorization.

A profiling selection always binds all 24 release sources plus its manifest. Any
profiling helper in another selection requires the complete new 19-helper worker
inventory. A new runtime with all profiling helpers absent also refuses; missing
or partial new releases cannot fall back to a historical inventory. Current
frontend identities differ from historical frontend pins by design.
