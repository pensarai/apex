# PDR-011: Record physical inference attempts before dispatch

## Context

Completed-step callbacks omit failed requests, provider retries, and interrupted streams. Optional native evidence capture deliberately tolerates persistence failures. Neither is sufficient to enforce a recorded run's model request allowance.

## Decision

Use the existing inference-attempt envelope and identity machinery with a separate critical recorder. Commit an attempt before provider dispatch. Persist observed tool-call identities before exposing those calls to the SDK executor. Queue terminal usage and lifecycle updates, then drain them before another dispatch or terminal run status. A persistence failure latches and prevents further execution.

Scope the recorder around the supported solo agent, including its compaction and tool-repair calls. Native evidence capture remains optional and best effort; recorded-only calls do not collect another copy of raw prompts or response bodies.

The store atomically reserves an optional maximum number of physical model requests against the admitted run. Every reservation counts, including retries and auxiliary calls. An absolute deadline rejects late dispatch and supplies cooperative cancellation to active work. These limits do not constitute a dollar or token spending cap.

Observe retry decisions where the existing retry owner computes its count and delay. Keep SDK retry lineage in attempt envelopes. Do not invent a due time for the SDK's internal backoff or introduce another retry controller.

## Tradeoffs

- A committed `started` record proves that dispatch was reserved, not that the provider received the request. A crash between reservation and dispatch can consume allowance conservatively.
- Unreported token fields remain `null`. A provider may have charged for an interrupted request whose usage is unknown.
- Context references identify the latest canonical agent checkpoint. Auxiliary inference has its own prompt; the reference does not claim to reproduce that prompt.
- Tool-call observations are model output metadata. They are not validated tool intents, outcomes, idempotency keys for external effects, or permission to replay a tool.
- Deadline cancellation is cooperative. It cannot undo external effects or force an unresponsive external service to stop.
- Forward-only SQLite migrations preserve recorded history. No resume, lease transfer, or allowance-reset behavior is introduced here.
