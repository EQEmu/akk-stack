# Durable CLI imports

`central-avop`, 2026-11-04. The durable entry point is
`scripts/validation-job`. It adds `validation/worker` first, then `jobs.main`
adds `validation` at the end to import the source-only `inputs.GitTree` API.
Worker precedence must survive that addition because both directories contain
`prepare.py` with different APIs. `identity` uses `record` from worker prepare.
Do not add that API to `validation/prepare.py` to hide an import-order error.

The former prepend reproduced exit 2 from the real CLI before `job.json` or
runner creation. `start` had already allocated an empty private job directory.
That failure supplies neither a durable job ID nor a validator result or VM
cleanup receipt. Local process status cannot establish VM cleanup. This repair
does not authorize a retry of any consumed execution intent.

Run the regression with:

```sh
python3 -B -m unittest discover -s tests/worker -p test_jobs_cli.py -v
```

It invokes the real script in fresh isolated interpreters against an empty Git
fixture. A test-only Python audit hook permits Git metadata subprocesses and
stops at the first runner spawn with exit 73 and a `before-runner-spawn` receipt.
It rejects socket operations and unexpected subprocesses. The tests check exact
command operands, source identity, the frozen client bytes and hashes, and the
loaded prepare/identity/inputs paths. Fresh `--help` processes then import the
copied frontend. No test-only option or execution bypass exists in production.

## Adjacent import audit

- Entry point: `scripts/validation-job` imports only stdlib and worker `jobs`.
  `jobs` top-level imports are stdlib. Its start command imports `inputs.GitTree`
  for metadata and, for sanitizer selection only, worker `sanitizers.PROFILE`.
- Snapshot: `start` imports worker `identity.FRONTEND_FILES`. Identity imports
  worker `prepare.record`; prepare imports `inputs` after adding `validation`.
  At that point worker prepare is already in `sys.modules`. There is no import
  of `validation/prepare.py`. Fresh-process regressions cover all three paths:
  ordinary default Rust, ordinary explicit Rust, sanitizer explicit Rust.
- Copied frontend: `validate-worker-candidate` imports worker `client`, worker
  `prepare`, worker `identity`, and worker `normal_world`. The prepare import
  adds `validation`; identity reuses the same worker prepare. Each copied
  frontend's `--help` reaches argparse successfully in a second fresh process.
- Deferred frontend imports: identity selects `runtime.IMPLEMENTATION_FILES`,
  `profile_contract.SOURCE_FILES`, and `sanitizers.policy_name`; prepare uses
  `profiling`, `profile_inputs`, and `sanitizers`. Normal-world code uses
  `profiling`, `sanitizers`, and `actor_runtime`, which imports `actor`.
  These module names have no competing file in the two search directories.
  They are included in the existing conservative frontend identity and snapshot
  closure. The identity tests check transitive import coverage, mutation and
  missing-file rejection independently of installed historical inventories.
- Detached runner: its `runner.py` is a byte copy of `jobs.py`, imports stdlib,
  and dispatches `--run`, `--notify`, or `--cancel-owned` without the CLI source
  imports. Its own hash remains recorded in `job.json`. Existing host fixture
  tests cover process ownership, capture, cancellation and notification.

The repair changes only the durable CLI's path precedence. No helper is added,
no finite inventory needs expansion, and neither approved input binding/staging
nor worker admission, installed identities, execution or cleanup APIs change.
