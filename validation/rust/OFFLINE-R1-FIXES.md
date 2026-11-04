# R1 source closure fixes

R1 reviewed the frozen PR30 source at
`9ea0036a2e9e9091aedcc15633ae4eed83b32c82`. Both independent reviews found
missing frontend identity bindings; correctness review also reproduced an input
replacement race. Their package checks passed. Earlier package and source evidence
remain historical records and have not been rewritten.

The fixes are sequential:

1. `79c7df1` adds a finite `FRONTEND_FILES` source list shared by reuse identity
   and durable-job snapshots. It includes `snapshot.py`, `runtime.py`, `guest.py`
   and the conservative transitive local import closure, including imports inside
   worker-only functions. A static import regression checks the list, while real
   separate frontend-copy mutation/deletion tests check every listed file across
   ordinary/v1/v2/v3/new installed-closure fixtures. Installed inventories and
   strict historical/new-release selection rules are unchanged. A real job
   snapshot runs only the harmless frontend `--help` command and verifies copied
   bytes and recorded hashes. No additional files are required in old installed
   releases.
2. `2a8860e` retains each input record from the original pin check and verifies
   bounded, private staged copies against those records. The ISO reads the staged
   copies; its identity carries the original approved records. It never adopts a
   replacement by recording the source path again. The final check compares both
   staged and original inputs against the original records and deletes the payload
   on failure. This covers native, Rust, runtime and optional pinned profiler inputs.
   Staging requires additional temporary disk space for these public input copies.

The race regression replaces actual approved Rust bundle bytes with unapproved
22-byte data during harmless Git packaging stubs. Other cases cover replacement
of every pinned input, same-size changes, changes during ISO creation and
swap-and-restore of original paths. The ISO stub reads actual grafted file bytes;
only approved bytes may enter it. No candidate hooks, build scripts, compiler,
Cargo, installed worker or VM run. Missing or changed inputs fail closed.

See `offline-r1-fix-proof.json` for final source-closure hashes, reproduction and
passing test logs, package checks and exact Server binding. Reproduction logs use
new filenames under `data/offline-r1-fixes/`; earlier R1 and 75cb evidence remain
untouched. The sealed package tool did not change, so the original bundle,
manifest and all 16 package files remain valid without resealing or relabeling
them as a new package.

The original default path, old and added finite Rust identities, native/runtime
pins, quick/format selection and all installed consumers remain unchanged. Root
selection and two fresh complete source/package reviews are still required before
use. Server `d58d1fa4cb5ce656984d6ebaaeb78c8b70b06c85` remains the selected source;
its 95 utility and 21 inserver cases remain UNEXECUTED by this preparation work.
