# Attack Surface v2: persistent goals versus completion audits

This experimental branch combines the preserved audit implementation with Jorge's
[persistent-goals PR #1364](https://github.com/pensarai/apex/pull/1364) at
`b4c8f094e4b2577081df64905720739cfd977efb`. The two completion mechanisms are
mutually exclusive. The merge also brings upstream changes from that PR's base;
both evaluation arms run on the same merged tree to avoid attributing those
changes to the goal controller.

The original audit implementation remains at Apex `d07b62a6` and Console
`2e10deb95`, with local preservation branches named
`codex/recon-audit-baseline-2026-11-25`. Neither existing PR was overwritten.

## Integration

`runGeneralizedAttackSurface` accepts either `goal` or `completion`:

```ts
await runGeneralizedAttackSurface({
  ...input,
  goal: { objective, maxRounds: 4, workSteps: 100 },
});
```

The goal adapter uses the existing generalized agent and Jorge's `createGoal`,
file host, `update_goal` tool, prompt and `settleGoalTurn` rules. Creating a report
does not terminate a goal turn. Conversation history is retained between turns;
the original objective is reinjected into the system prompt. Citation lookup,
round and stall limits, blocked status and continuation decisions come from the
shared goal module. The adapter drains each agent before deciding what comes next.
Cancellation leaves an active goal resumable; provider errors persist a blocked
goal. A limit produces one short wrap-up turn with read access only.

The adapter retains deterministic checks for referential integrity, recommended
test-target scope and a report bound to the current topology snapshot. A missing
or stale report rejects the completion claim and becomes corrective work. It
does not run audit workers or add a second model judge. Semantic completeness,
distinct threats and evidence relevance still depend on the main agent's judgment.
A valid quotation from a successful tool result is not proof that the entire
threat model is correct.

This implementation is a **local API integration**, not a Console durable rollout.
It rejects a recorded-context host until goal storage, evidence lookup and ordered
replay scheduling are supplied through the durable host. Jorge's Console chat
host (#4188) schedules workspace chat turns; it cannot simply be reused as a
system-recon workflow. No Console feature flag, runtime deployment or workspace
data was changed by this comparison.

## Bounded source-only pilot

Use a generated customer-source repository from the
[temporary environment repository](https://github.com/pensarai/recon-eval-environments),
never the evaluator repository containing its answer keys.

```sh
export RECON_ENV_REPOS=/absolute/path/to/disposable/customer-repos
./environments/make-repo.sh segmented-corp

# From this Apex checkout, with provider credentials configured separately:
bun scripts/eval-recon-completion.ts \
  --arm goal \
  --fixture "$RECON_ENV_REPOS/segmented-corp" \
  --output /absolute/path/to/new/goal-output

bun scripts/eval-recon-completion.ts \
  --arm audit \
  --fixture "$RECON_ENV_REPOS/segmented-corp" \
  --output /absolute/path/to/new/audit-output
```

The script currently targets the segmented-corporate fixture. Both arms use
Opus 4.6, four rounds/passes, 100 work steps per turn, a 10-minute total deadline
and a $12 estimated-usage stop. Audit concurrency is six, matching the current
audit implementation. These are bounded allowances, not equal realized token
counts. Model/provider nondeterminism remains uncontrolled.

Only native source navigation and topology documentation tools are available.
The injected backend confines files to that run's source/records and denies
network, browser, shell and inbox calls. The input source is copied into each
session; evaluator answers are outside that scope. No live security tests run.
This differs from the historical lab's source-plus-network matrix and the Pensar
Console experiment, so their scores and durations are not paired comparators.

Each arm saves inputs, implementation snapshots, raw tool events, usage records,
the final map, any report, goal/audit state and a terminal result. Failed and
timed-out runs remain in the comparison. Cost is a cache-aware catalog estimate
of recorded usage, not an invoice or a strict account spending cap; in-flight
calls can overshoot the threshold.

Review supported surfaces and distinct causal threat paths, incorrect claims,
cross-section contradictions, applicable controls, explicit unknowns and third-party
scope before interpreting counts. Use the existing regex scorer only as a coarse
coverage signal. One run per arm is a pilot, not a reliable estimate of which
method is better. Before rollout, repeat on held-out fixtures and updates, use
blind source-based review, then test compaction/recovery and durable scheduling.
