# Detached recorded runs

Recorded runs can execute in an independent local process on macOS and Linux:

```sh
pensar agent-runs start --spec run.json --detach
pensar agent-runs list
pensar agent-runs show run_example --control
pensar agent-runs pause run_example
pensar agent-runs resume run_example --detach
pensar agent-runs stop run_example
```

Use the same `--store /absolute/path/runs.sqlite` on each command when selecting a custom database. The JSON specification and supported recovery cases are described in [recorded runs](./recorded-runs.md).

`--detach` returns after connecting to a worker and requesting execution. The returned snapshot distinguishes worker phase from the last saved run status. Closing that command's terminal leaves the worker executing. A disconnected observer never requests pause or stop. Existing commands without `--detach` retain foreground execution.

Pause and stop are cooperative durable requests. Accepted work can finish before the next dispatch boundary applies them. A paused worker exits after saving its state; explicit resume starts a new execution attempt subject to the existing recovery checks. Repeating start with an identical run ID does not restart a completed or interrupted assessment, and changed specifications are rejected.

The worker serves a private Unix socket, with no TCP listener or mandatory daemon. Endpoint discovery uses the canonical database path and run ID. Independent runs have independent workers. Multiple clients can observe one run; concurrent controls retain their existing revision and approval checks.

The internal versioned protocol offers atomic replacement snapshots and bounded change notifications. Snapshots contain committed conversation state, controls and approvals. They are not a live token transcript. Clients replace their view when a worker changes; the worker cursor is not a durable database revision or replay log. CLI/TUI attach views are a separate client slice.

## Worker loss and startup errors

A worker dying does not prove its last tool failed. Inspect the record, then use explicit resume. All existing blockers still apply, including unknown tool effects, shell state, missing evidence and unsupported provider continuity. Detached hosting does not make a previously unsupported recovery case safe.

If a start/resume connection fails after sending a command, its outcome may be unknown. Inspect the run before taking further action. The launcher does not automatically resend mutations or kill a process based on a PID hint. An incompatible live worker is reported rather than overwritten.

Idle workers expire if no execution is requested. Settled workers briefly expose their final state and then exit; the database remains available to `list` and `show`. An immediate detached resume waits for that retiring host before launching a fresh one. Worker output goes to a private local log whose path is returned by the launcher. These logs can contain assessment data.

## Requirements and limits

- Bun or Node 22.13+ for recorded-run storage.
- macOS or Linux with a local filesystem and working SQLite locks.
- The original database, workspace, session files and credentials for recovery.
- Matching protocol/runtime versions; incompatible state is not silently migrated into a fresh run.

There is no automatic supervision or restart policy. Terminal independence does not imply survival of host shutdown, operating-system session cleanup, or loss of the underlying files. Execution remains the same opted-in recorded path; existing interactive workflows are not silently moved into workers.
