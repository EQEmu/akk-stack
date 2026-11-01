# Stack validation

Use central Beads at `/home/bump/Projects/beads` with `project:bump-akk-stack`.
Candidate native/Cargo execution belongs only in the disposable worker. Keep
ordinary installed client/profile selection unchanged when preparing diagnostics.
Operations documentation and Server source have separate owners.

The foreground full validator remains `scripts/validate-worker-candidate`.
It packages a clean checkout at the exact selected commit. Dirty edits are
rejected, never silently committed or claimed as tested.

Start a durable host job with explicit source and callback destination:

```sh
scripts/validation-job start full --repo /absolute/server-checkout \
  --commit FULL_40_CHARACTER_SHA --websocketpp /absolute/websocketpp \
  --thread EXACT_T3_THREAD_ID --t3-base-dir /absolute/current-t3-data-directory
scripts/validation-job status JOB_ID
scripts/validation-job cancel JOB_ID
scripts/validation-job retry-notification JOB_ID
```

Start returns the job ID and private artifact directory immediately. Optional
`--jobs-dir /private/job-root` precedes the subcommand and must be reused for
status/cancel/retry. Only `full` is exposed. It snapshots the trusted client
helpers, records the source commit/tree/observed HEAD, and leaves candidate source
selection and cleanliness checks to the full validator. It captures no dirty
working-copy snapshot. `job.json` contains exact invocation and helper hashes.
`result.json` records raw process exit separately from `validator-result.json`.
Both raw logs are capped at 64 MiB with byte counts/truncation in the result.
Cancellation requests SIGINT for the owned validator and allows 780 seconds
before killing it. Local process death does not confirm VM cleanup. Only an
explicit final validator receipt can set `cleanup_complete`; otherwise it is
unknown. Interrupted jobs are never automatically restarted.

`notification.json` records callback status separately. Retrying notification
never launches validation. CLI acknowledgement can be uncertain; consumers must
recognize duplicate job IDs. A successful callback retry is a no-op afterward.
Callbacks contain bounded identity/outcome/path metadata, never candidate logs.
`scripts/t3-validation-notify` contains the package-specific supported T3 CLI
invocation. `--notify-adapter` selects another trusted host adapter with the same
`--base-dir DIR --thread ID`/stdin interface. Its optional host-only
`T3_VALIDATION_CLI_CONFIG` names a JSON object with `command` argv and `env`
string map. No adapter, T3 configuration, or credentials enter the candidate VM.
Never use `--wait` or guess a newest thread/data directory.

Run source regressions with
`python3 -B -m unittest discover -s tests/worker -v`. Wrapper tests use harmless
trusted processes and real pipes/adapters, without candidate execution.
