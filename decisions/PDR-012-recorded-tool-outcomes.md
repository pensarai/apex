# PDR-012: Commit tool intent and model-visible outcomes

## Context

Model tool-call observations precede input validation and do not prove execution. A process can also disappear after a target mutation but before the conversation checkpoint records its result. Continuing from the transcript alone could repeat that mutation.

## Decision

For recorded runs, wrap the existing tool executor after SDK input validation. Commit the accepted name, full input, execution owner, checkpoint reference, and operation identity before invoking the tool. Preserve existing tool implementations and backend selection.

Convert each result to its model-visible representation once, then commit that representation and evidence references before returning to the SDK. Reuse the saved conversion when the SDK builds messages, including retained-output references. Update the current evidence snapshot in the same transaction as settlement.

An identical repeated call ID can reuse a settled result. A conflicting input or an unsettled operation blocks execution. A thrown execution or conversion error records `outcome_unknown`; a hard crash can leave `started`, which also provides no permission to retry. Tool classification describes effects, not an automatic retry entitlement. HTTP GET remains externally observable.

Critical journal failures latch and block subsequent model dispatch, context commits, and successful run completion, including when SDK callbacks discard exceptions. Legacy callers without the recorder retain their existing path.

## Tradeoffs

- Extra transactional writes add latency at tool boundaries. They pay for a committed dispatch/result boundary; no per-token log or workflow service is introduced.
- Model-visible outputs avoid storing another unbounded raw-output copy. Retained files and assessment artifacts still require their actual local files; hashes are not backups.
- A settled output records what the tool returned. It does not prove a remote service rolled back an operation when that output reports an error.
- Parallel calls retain individual identities and acceptance sequence. This does not make their external effects atomic.
- Older runs without journal enrollment remain readable and explicitly lack coverage. Schema upgrades do not invent missing tool history.

No resume command, ownership transfer, or automatic tool retry is enabled by this decision.
