# Recorded local runs

Recorded runs are an opt-in path for inspecting a local agent's admission, saved context, referenced evidence, model attempts, tool outcomes, and last saved execution status after its process exits. They support durable pause/stop requests and optional tool approvals. Resume, detached execution, and managed workers are not enabled yet.

This path requires Bun or Node 22.13+. It uses the runtime's built-in SQLite implementation and adds no native package dependency. Existing commands retain their current runtime requirements. Run the commands through `bun src/cli.ts` during development or `pensar` after building/installing.

## Start and inspect

Create an explicit JSON spec. The working directory must be absolute and already exist. Choose a built-in catalog model with credentials configured in Apex and a target you are authorized to test. Custom-provider and dynamic Hoonify model IDs are not supported on this initial path.

```json
{
  "schemaVersion": 1,
  "configVersion": 1,
  "runId": "run_local_smoke_01",
  "prompt": "Request the target homepage once and summarize the response.",
  "target": "http://127.0.0.1:8080",
  "model": "claude-sonnet-5-5",
  "activeTools": ["http_request"],
  "environment": { "kind": "local", "cwd": "/absolute/path/to/workspace" },
  "scope": {
    "version": 1,
    "allowedHosts": ["127.0.0.1"],
    "allowedPorts": [8080],
    "strictScope": true,
    "allowDestructiveActions": false,
    "allowRateLimitTesting": false
  },
  "credentialRefs": []
}
```

```sh
bun src/cli.ts agent-runs start --spec run.json
bun src/cli.ts agent-runs list
bun src/cli.ts agent-runs show run_local_smoke_01
bun src/cli.ts agent-runs show run_local_smoke_01 --context --evidence --models --tools
```

Repeating the same spec returns the existing run without starting another agent. Reusing its ID with changed inputs fails. Use a new ID only when you intend a new execution. This also applies to an admitted run whose process died before it could begin execution.

The database defaults to `$PENSAR_DATA_DIR/runtime/runs.sqlite`, or `~/.pensar/runtime/runs.sqlite` when the variable is unset. `--store /absolute/path/runs.sqlite` selects a different local database. Keep the database and its SQLite sidecar files together; do not place this local store on a network filesystem.

## What the records mean

Admission commits before session creation or model execution. It fixes the input, scope, model, environment reference, session ID, and execution attempt ID. Concurrent callers with the same ID cannot both win admission. Status transitions belong to that attempt and cannot restart a terminal run.

`running` means the last committed status was running. It is not a heartbeat or proof that the process is alive. A killed process can leave an `admitted` or `running` record. No command automatically reclaims or retries that execution. `cancelled` likewise does not prove that all external effects were undone.

The store rejects unsupported versions, invalid records, and incompatible existing databases. A failed critical write is an execution error; the API does not silently switch to the legacy path. Provider credentials are supplied at runtime; the record stores credential references rather than copying credential objects. Prompts and tool outputs can still contain sensitive assessment content, so treat the run database like other session evidence.

## Context and evidence

The database holds canonical context at model-turn boundaries. It commits the input before dispatch, then commits the cumulative conversation after a completed step. New messages append within a context epoch; a rewritten or compacted conversation opens a new epoch. The next turn cannot select that context until its commit succeeds. Provider cache markers added for an individual request remain derived transport options.

`--context` prints the selected epoch, revision, system text, and ordered messages. A partial stream is not a completed context checkpoint. Existing `messages.json` and trace exports stay readable, but are compatibility projections rather than recovery authority; interrupted transcripts may contain synthetic tool closures that are not committed tool outcomes.

Context commits also retain SHA-256 references to the session's findings, informational notes, POC files, plan, tasks, and tool-output spill files. Those domain files remain authoritative. `--evidence` checks their persisted location and reports `match`, `modified`, `missing`, or a read error. Deleted references remain visible. A hash reference detects loss or change; it is not an independent backup. Files created by an interrupted step before its checkpoint may exist without a committed reference.

The local schema upgrades version 1 stores transactionally. Older binaries reject the newer schema; there is no downgrade fallback. Runs admitted before context recording was available can have no saved context. Neither that absence nor a corrupt checkpoint permits a fresh execution under the same run ID.

The supported path is a fresh local solo agent using the explicitly supported tool set. Existing sessions, TUI workflows, child agents, custom tool backends, browser sessions, and Daytona workers are not migrated by this feature. Session files remain the authority for assessment artifacts; recorded runs do not reconstruct those artifacts after environment loss.

## Model attempts, retries, and limits

`--models` prints physical model attempts, observed model tool-call IDs, retry decisions, and the remaining request allowance. Attempts use the same identities as native inference evidence. They reference the latest canonical agent context; a compaction or repair call has a different auxiliary prompt and does not claim that checkpoint is its exact request.

An attempt commits before provider dispatch. `started` can therefore mean the process died before sending, or after sending without saving a result. `partial` can include observed tool calls whose effects have not been journaled. Neither state permits replay. Tool-call observations are model metadata, not accepted tool intents or committed tool results.

Known token usage is retained per attempt; unreported fields stay `null`. These records are not a billing ledger. Native raw request/response capture remains a separate opt-in feature and is not enabled by recorded runs.

The optional spec field `limits` accepts:

```json
{ "maxModelAttempts": 100, "deadlineAt": "2026-12-01T18:00:00Z" }
```

The request allowance counts all physical dispatch reservations, including SDK retries, compaction, and tool repair. Reservation and the limit check share one transaction. A crash between reservation and dispatch conservatively consumes one slot. The absolute deadline rejects late dispatch and cooperatively cancels active execution; it cannot undo external effects. If the deadline expires after the agent returns but before status settlement, the record is conservatively `cancelled` even when a result is available. Omit either field for no corresponding limit. The remaining allowance shown by the CLI is derived from committed reservations, never from transient process counters.

Retry records retain the count, maximum, delay, and due time computed by Apex's existing retry loop. Counts belong to that loop or context-restart depth, not a new global retry controller. SDK-internal retries retain their attempt lineage; their internal backoff due time is not exposed and is not fabricated. Restarting this command still returns the saved run without re-executing it or resetting any allowance. A future recovery implementation must honor these records before it can resume.

Schema version 3 introduced model history; upgrades remain transactional. Missing model history on older runs means unavailable history, not zero historical usage. Completed status requires the critical inference recorder to drain successfully; persistence errors fail the invocation even when a model callback would otherwise swallow them.

## Tool outcomes

`--tools` shows whether the run has a tool journal and lists accepted calls in order. Each operation binds its tool-call ID, validated input, execution owner, and context checkpoint. The start record commits before the existing tool executes. A successful settlement commits the exact model-visible output and evidence references before the SDK can use it; retained output under `logs/tool-output` is included in evidence inspection.

- `settled`: the returned output is saved. Repeating the same call ID and input reuses that output without executing again. A returned error remains an observed result, not proof that an external effect was undone.
- `started`: dispatch was reserved, but no result committed. The tool might still be active, might not have started, or might have already affected the target. This state is not permission to retry.
- `outcome_unknown`: execution or result conversion threw after intent committed. Its effects remain uncertain; the call is not automatically repeated.

Conflicting inputs for the same call ID fail explicitly. Read-only, external-effect, local-mutation, and shell-dependent classifications are diagnostic; none enables automatic retries in this version. A journal write failure blocks dependent model dispatch and canonical context writes even when the SDK converts the exception into a tool error.

Schema version 4 adds journal enrollment and operation records transactionally. Existing runs remain readable with `journaled: false`; migration does not manufacture missing tool history. These records support inspection and later recovery work. They do not enable resume or restore a lost environment.

## Pause, stop, and approvals

New runs enroll durable controls before execution. Inspect them from another terminal:

```sh
bun src/cli.ts agent-runs show run_local_smoke_01 --control --tools
bun src/cli.ts agent-runs pause run_local_smoke_01
bun src/cli.ts agent-runs stop run_local_smoke_01
```

Commands acknowledge a saved request. `running` with pause intent means the executor has not yet acknowledged a pause; `paused` means it reached a control boundary. Already accepted work may finish. Stop also sends cooperative cancellation to the live executor and denies pending approvals. Neither command proves that external effects were undone. Older runs without control enrollment reject these commands rather than pretending an old executor observes them.

Clients use revision checks to prevent stale commands from replacing newer intent. A conflict requires inspecting the current record and retrying deliberately. Detaching or losing a client does not approve work or change intent. Ctrl+C/SIGTERM on the foreground start command still means stop; the runtime persists that intent before forwarding cancellation.

To require approval, add an explicit policy to the spec before admission:

```json
{ "approval": { "requiredTools": ["http_request", "execute_command"] } }
```

Every listed tool must also be in `activeTools`. Omit the policy for the existing ungated behavior. A pending request contains its approval ID and exact validated input in `show --control`. Resolve it explicitly:

```sh
bun src/cli.ts agent-runs approve run_local_smoke_01 --approval <approvalId>
bun src/cli.ts agent-runs reject run_local_smoke_01 --approval <approvalId>
```

A decision only authorizes that call's input under the admitted scope. Conflicting decisions fail. Denial returns a blocked result without dispatching the tool. Pending decisions survive process loss; they never auto-approve or silently expire. A deadline or explicit stop cancels the wait. The current TUI approval flow is unchanged.

Schema version 5 introduces these records transactionally. Paused and interrupted runs still require the subsequent explicit recovery implementation; repeating `start` only returns their saved status.

## Smoke checks

1. Run `agent-runs --help` without provider credentials; it must not open a database or call a model.
2. Start a run against a local test target. Inspect its record from a second process while it runs, then inspect its final status.
3. Repeat the same start command. Confirm `started: false` and no second target request from that invocation.
4. Change the prompt while keeping the run ID. Confirm an input conflict and no execution.
5. Start another run with a new ID and kill its process. Inspect the original admitted/running record, then repeat the same command. It must not restart the assessment.

Crash inspection is the guarantee at this stage. Safe recovery still requires ownership and reconstruction checks in the next part of this stack.
