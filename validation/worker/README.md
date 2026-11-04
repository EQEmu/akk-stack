# Unprivileged validation worker POC

This POC provisions a dedicated worker and qualifies one tiny offline VM.
It does not change the installed EQEmu validator or AFK configuration. Server
builds, Rust tests and actor behavior need later qualification.

The ordinary candidate command now includes a fresh normal DB/world/zone slice.
See [NORMAL-WORLD.md](NORMAL-WORLD.md) for inputs, readiness assertions, fixed
non-pass controls, cleanup and pending VM qualification. Changed worker assets
still require separate review/selection; this checkout does not install them.

Inspect and create the account first:

```sh
./scripts/setup-validation-worker --submitter bump --account-only --dry-run
sudo ./scripts/setup-validation-worker --submitter bump --account-only --apply
```

The defaults create `eqemu-validator`, a private group, the non-login shell
`/usr/sbin/nologin`, private state at `/var/lib/eqemu-validator`, and a root-owned
configuration marker at `/etc/eqemu-validator/config.json`. The initial supported
host is Ubuntu 26.04 with systemd 259 or later. Use the existing local account as
`--submitter` on another host. Select any custom worker, state, code and image
paths consistently from the first invocation because the marker records them.

Account-only setup installs no service or AppArmor policy and starts no VM.
Repeat it with `--check` for read-only verification. Reruns preserve the UID,
configuration and state. Conflicting accounts, files, symlinks and ownership
refuse before provisioning.

## Stage the runtime and install fixed policy

Use a reviewed checkout and an existing public cloud image with a verified
SHA256. Full setup copies the finite reviewed runtime/helper closure into the submitter-owned
`/srv/eqemu-validator-code` tree and the verified image into root-owned
`/var/lib/eqemu-validator-inputs/base.qcow2`. It does not download inputs.

```sh
sudo ./scripts/setup-validation-worker --submitter bump \
  --stage --base-source /path/to/verified-public-image \
  --base-sha256 VERIFIED_LOWERCASE_SHA256 --dry-run
sudo ./scripts/setup-validation-worker --submitter bump \
  --stage --base-source /path/to/verified-public-image \
  --base-sha256 VERIFIED_LOWERCASE_SHA256 --apply
```

The dry run verifies host prerequisites and collisions without writing. Root
access is needed to inspect loaded AppArmor profiles. Existing matching staged
files are retained. Changed or unknown staged files refuse; the installer never
overwrites them. The account marker remains unchanged when advancing from
account-only setup. Full setup installs a fixed socket, systemd worker template
and enforcing AppArmor profile, then enables the socket. It starts no VM and
continues to report `runtime_ready: false` pending ordinary runtime checks.

## Qualify through the ordinary client

These commands run as the configured submitter without sudo:

```sh
/srv/eqemu-validator-code/scripts/check-validation-worker
/srv/eqemu-validator-code/scripts/check-validation-worker --smoke
/srv/eqemu-validator-code/scripts/check-validation-worker --smoke --control assertion
/srv/eqemu-validator-code/scripts/check-validation-worker --smoke --control missing-result
/srv/eqemu-validator-code/scripts/check-validation-worker --smoke --control deadline
/srv/eqemu-validator-code/scripts/check-validation-worker --smoke --control controller-death
/srv/eqemu-validator-code/scripts/check-validation-worker --last-result
```

A plain check starts no VM. It observes actual worker identity, confinement,
KVM access and cgroup limits. Smoke starts one disposable VM with no network
interface and a fixed tiny guest script. Exit 0 means the tiny control passed,
1 means the guest assertion failed, and 2 means infrastructure or incomplete
execution. A readiness report alone does not qualify VM execution or cleanup.

The controller-death control starts QEMU, records its PID and deliberately kills
the controller. The client returns 2 because there is no final reply. The fixed
systemd stop hook must recover the owned scratch after terminating the cgroup.
Use `--last-result` afterward to inspect the retained result without reading
worker-private state directly. This read-only operation exits 0 when observation
succeeds; the nested result retains its original execution exit code. Recovery
remains a non-pass, with process-absence and scratch-removal evidence reported
separately. Kill or interrupt a client during a deadline smoke to test client
death, then inspect the last result through the same ordinary client.

Reviewed runtime and test-code changes belong in the submitter-owned code tree
and need no privileged setup. Fixed systemd/AppArmor policy changes still need
administrator review and provisioning. No candidate command runs on the host.

Run source regressions without sudo:

```sh
python3 -B -m unittest discover -s tests/worker -v
```

## Opt-in process profiling

See [PROFILING.md](PROFILING.md) for independent timelines, Heaptrack/perf,
bounded partial artifacts and the separate additive release proposal. Source
packaging and host fixtures do not activate or qualify a guest selection.

## Working-copy Rust formatting

`scripts/format-worker-snapshot` submits an uncommitted `rust/actors` snapshot to
one disposable offline VM. It uses the same pinned Rust bundle and
`cargo fmt --all` workspace as the final validator. `--check` adds `--check` to
that formatter invocation. It does not build the server, run Rust build scripts,
or certify a Git commit. Neither operation changes the caller's checkout.

```sh
scripts/format-worker-snapshot --identity
scripts/format-worker-snapshot --repo /absolute/eqemu --base FULL_BASE_SHA --snapshot-identity
scripts/format-worker-snapshot --repo /absolute/eqemu --base FULL_BASE_SHA --check --output /private/fresh-check.json
scripts/format-worker-snapshot --repo /absolute/eqemu --base FULL_BASE_SHA --output /private/fresh-format.json
```

The identity and snapshot queries run no Cargo commands and boot no VM. Results
bind the base, HEAD, complete Rust/config snapshot, trusted recipe, pinned Rust
bundle and worker implementation. The ordinary validator's format gate remains
check-only. Format success is only formatter success.

Snapshots contain tracked and new nonignored `.rs`, Cargo manifests/lockfiles,
and applicable Cargo/rustfmt configuration. Deletions are explicit. Target,
vendor, generated and submodule directories are outside this scope. Limits are
4 MiB and 512 source files, 512 KiB per file, and 1 MiB/128 returned file changes.
Changes can replace only captured regular `.rs` files. Private output artifacts
are fresh files with mode 0600; stdout carries a summary without source bytes.
Last-result observations retain metadata only, not returned file contents.

Applying changes is a separate, explicit caller-side operation. AFK and developer
tools use this shared helper rather than implementing their own file writer.
It boots no VM, runs no Cargo command and leaves the Git index alone. Supply the
identities captured before the formatter ran:

```sh
scripts/format-worker-snapshot --repo /absolute/eqemu --base FULL_BASE_SHA \
  --apply-result /private/fresh-format.json \
  --expected-input INPUT_SNAPSHOT_SHA256 --expected-recipe RECIPE_SHA256 \
  --expected-implementation WORKER_IMPLEMENTATION_SHA256 \
  --output /private/fresh-apply.json
```

The helper validates the entire result and current snapshot before staging any
writes. It preserves permissions, configuration and deletions. It stages all
replacement bytes first and rolls back its own writes on replacement or receipt
publication failure. If another writer changes a file during recovery, the helper
preserves that newer edit and reports failure. Work on the same checkout must
still be serialized by the caller. No multi-file filesystem operation can make
concurrent writers safe without that ownership rule.
SIGTERM and SIGINT enter the same rollback path. Replacement and ownership
bookkeeping defer those signals together; recovery ignores repeated cancellation.
A hard kill cannot run recovery and must be treated as an unconfirmed failure.

Exit 0 means the selected operation completed, 1 means a formatter/check
candidate failure, and 2 means unavailable infrastructure, invalid/stale data,
interruption or unconfirmed cleanup. Error and check results never return edits.
Artifacts must be outside the checkout. The operator must activate the reviewed
worker implementation separately; an older worker rejects the new operations.

## Advisory quick checks

`scripts/quick-worker-snapshot` runs a fixed check-only workload before a commit
is published. It captures tracked files and new nonignored regular files, raw
bytes, executable modes, deletions and pinned submodule identities. Ignored files
are omitted except applicable ancestor Cargo/rustfmt configuration. New target,
vendor, generated, CMakeFiles, Python cache and local `.env`/runtime-config files
are excluded. Tracked files in those locations remain source inputs. The source
limit is 256 MiB/10,000 files, 16 MiB per file; the manifest limit is 4 MiB.
Submodule working copies are excluded and verified fixed inputs supply them.

```sh
scripts/quick-worker-snapshot --identity
scripts/quick-worker-snapshot --repo /absolute/eqemu --base FULL_BASE_SHA --snapshot-identity
scripts/quick-worker-snapshot --repo /absolute/eqemu --base FULL_BASE_SHA \
  --expected-input INPUT_SNAPSHOT_SHA256 --output /private/fresh-quick.json \
  --websocketpp /absolute/pinned-websocketpp
```

Queries boot no VM and invoke no candidate tools. Execution checks the expected
snapshot before packaging, before submission and after completion. It never
writes the caller's source or index. The exact input identity covers native and
Rust source together. Returned output identity equals input identity.

The six fixed checks are Rust formatting, offline dependency availability,
Clippy, workspace library/tests, native configuration and affected native
objects. Format and Clippy failures do not prevent independent tests. Dependency
failure skips Clippy/tests and reports unavailable infrastructure, matching full
validation. This deliberately classifies metadata syntax errors conservatively
as unavailable too; the formatter's separate feedback can still identify them.
Independent native feedback continues when its prerequisites permit.

Native compilation uses CMake's generated compiler database to find each changed
C++ source's actual object outputs, then asks the generated Ninja build to build
those exact object targets. Ninja retains its PCH/generated-header prerequisites;
the client does not execute compiler argument text from an agent. At most eight
objects are selected. New translation units absent from the generated database,
changed headers/build inputs, deleted or renamed translation units, and Rust
bridge/build inputs report native coverage unavailable. A cold build has no
trustworthy header dependency database. Rust core internals alone do not select
native objects; that omission is explicit in the stage results.
Unknown inputs default to native coverage unavailable, including `.hh`, `.ipp`,
`.tpp` and extensionless included files. Outside bridge/build paths, unrelated-file exclusions are
Markdown/reStructuredText, root LICENSE/COPYING/NOTICE, known ancestor rustfmt
configuration and Rust actor core `.rs` internals other than `build.rs`.

The result is advisory, with one status and timing per selected check, explicit
completed/failed/unavailable/skipped lists, actual selected object paths and
bounded private compiler/Rust diagnostics including available file/line context.
It is at most 64 KiB. Stdout and last-result observations omit source diagnostics.
Exit 1 identifies source failures; exit 2 covers unavailable input/scope,
staleness, malformed evidence, cancellation or unconfirmed cleanup. Exit 0 never
substitutes for final linking, server startup, utility or in-server tests.

The worker uses the existing offline provisioning, disposable VM, resource
limits and owned cancellation/cleanup. Its fixed deadline is 3600 seconds and
client deadline 3630 seconds; callers allow the existing cleanup grace. It has no
persistent VM/cache. Cold provisioning, configuration and PCH generation may be
expensive. Actual VM qualification and comparison with full-validation timing
are required before claiming a feedback speed improvement.
Native path/reason details have explicit encoded-byte caps and omitted counts.
Omitted translation units force unavailable coverage. Diagnostics use a 3000-byte
JSON budget per stage, including Unicode escaping. Last-result native scope is
counts only, preserving its existing 16 KiB protocol.
The internal source-archive bound adds the maximum PAX header, UTF-8 path and
padding overhead to the existing source/file limits. It does not narrow those
caller-facing limits.
