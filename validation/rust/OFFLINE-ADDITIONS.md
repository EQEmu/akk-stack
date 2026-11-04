# Additive offline inputs

This source preparation binds Server `d58d1fa4cb5ce656984d6ebaaeb78c8b70b06c85`,
tree `c10c6c9b2c44e46faf4eb44465cd349352877893`, and its byte-exact
`rust/actors/Cargo.lock`, SHA256
`a5f3dd2f0ff9e407b12d1ca1d8e0dde5d48e4c20cac34c025fe483daa2149fed`.
All 37 registry entries are checked. No Server code, Cargo, compiler, installer,
build script, native test or VM runs during preparation. The expected 95 utility
and 21 inserver cases remain UNEXECUTED by this work.

`extend_offline.py` accepts only the original pinned bundle and four exact
checksum-verified retained `.crate` archives. It inspects bounded archives in
memory, rejecting links, devices, traversal, duplicates, file parents, special
modes and count/byte overflows. Verification precedes decompression. It adds Cargo
checksum files, verifies every registry file checksum, then writes sorted USTAR
archives with zero timestamps/owners. Original vendor file bytes and modes,
checksum files, all five component archives and vendor config stay exact. The
original bundle and cache files are read only. Archive metadata is normalized,
so outer/vendor archive lengths are not expected to grow monotonically.

The private output is a fresh directory named by the new bundle SHA256. Existing
packages are rejected. Files are read-only, directories private, user owned.
`manifest.json` binds source/tree/lock, recipe, tool, original bundle, unchanged
components, every vendor file, retained archive paths/hashes and package files.
`SHA256SUMS` also binds the manifest. Supplied provenance receipts are copied as
data. These are user-owned sealed artifacts, not root admission assets.

Rebuild, using a new output root each time:

```sh
python3 -B validation/rust/extend_offline.py \
  --base /home/bump/.local/state/eqemu-rust-validator/inputs/bundle-1.99.0-cxx194/rust-inputs.tar \
  --cache /home/bump/.local/state/eqemu-actor-population-mvp-20261031/cargo-cache/registry/cache/index.crates.io-1949cf8c6b5b557f \
  --lock validation/rust/offline-additions.lock \
  --output /private/fresh-output-root
```

Repeat `--evidence /path/to/receipt.json` for the retained-crate receipts, Server
binding, retained release provenance, download comparison and runtime interface
proof. Identical inputs, paths and evidence produce identical bundle, manifest
and package file bytes across fresh output roots. Rebuilding from the packaged
`extend_offline.py`, `offline-additions.json`, `Cargo.lock` and `crates/` also
reproduces the bundle; manifest provenance paths then describe that new location.
The four preliminary public downloads happened before cache steering. They were
compared byte-for-byte to retained staging archives; only retained archives feed
the package. No network access is part of this tool.

# Per-run selection and operator handoff

The full frontend preserves the original default operand exactly:
`~/.local/state/eqemu-rust-validator/inputs/bundle-1.99.0-cxx194/rust-inputs.tar`.
It accepts that original digest plus exactly one added digest and byte count:
`7bc2a72f9b8a3ebcea3dfcb879ab2d5bb0a23d5ab4913e85f9acd728a5ce932e`,
171284480 bytes. No hash flag, environment override, registry configuration change
or arbitrary bundle admission is added. Quick defaults to the original pin and permits the reviewed additive bundle with
`--rust-package additive-v1 --rust-input /absolute/reviewed/rust-inputs.tar`.
Its frontend, runtime and guest share exact hash/size selections; locked offline
dependency resolution still rejects incompatible source locks or missing closure.
Format retains the original pin.

After the parent's final source/package reviews and root selection decision,
the reviewed frontend can use the existing `--rust-input` operand. The new
`validation-job start full --rust-input /absolute/package/rust-inputs.tar` operand
passes the exact path into its frozen frontend invocation and records it in
`job.json`. All other required ordinary operands remain unchanged. This document
is preparation guidance; it does not authorize a launch.

Read-only inspection of `/etc/eqemu-validator/config.json` on 2026-11-03 selected
`/srv/eqemu-validator-code`. Installed `runtime.py` SHA256 is
`56a34d3e3b7f3c384dcae1f9f769d6c772b6404a3aa3c819e9a8028579eb1185`;
installed `build_guest.py` SHA256 is
`1d4ad202e0424551615db1330323b268cceda65618a8e798e081b5f4950f7b1d`.
The installed ordinary runtime accepts the full-build request's exact payload
size/hash, verifies received ISO bytes, and mounts that payload in the guest.
Guest `provision` checks each identity file's size/hash, including Rust inputs.
Guest `prepare_rust` reads the payload archive, installs its five unchanged
components inside the disposable guest, and uses the unchanged vendor config.
Its extraction uses the data filter, 3 GiB and 50000 member bounds. There is no
separate top-level Rust bundle digest check on that full-build path. Quick/format
checks are separate. This is static interface evidence, not readiness or run
qualification. The worker need not read the package path; the frontend sends the
ISO bytes. No worker/config/AppArmor/installed frontend mutation is needed for
this interface. Do not substitute this inference for a fresh enforcing readiness
and quiescence check by the parent.

Minimum delta is this reviewed source frontend and durable-job snapshot, plus
the user-owned pinned package. No root-owned publication/install is proposed.
If the operator requires a root-owned destination, stop for root decision
`2f10d806`; no privileged publishing commands or bypass are provided here.
PR29 identity fixes at `75cb6f9696cb653d8c312f59d1d52c4d5b895dc4` are merged
into this branch without rewriting the original preparation commit. Historical
installed-selection rules remain strict and independent of the frontend identity
closure, which R1 intentionally expanded. Fresh complete-delta reviews must cover
the combined successor. The parent owns two independent final
reviews, root decision,
admission and the sole ordinary launch. Recheck the final source lock if the
selected Server changes. Existing runtime routes, staging and bundles stay intact.

R1 source findings and the sequential frontend-closure/input-capture fixes are
documented in [OFFLINE-R1-FIXES.md](OFFLINE-R1-FIXES.md). That follow-up preserves
the original sealed package and records new evidence separately.
