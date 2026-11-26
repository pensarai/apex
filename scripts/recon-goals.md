# Goal-driven Attack Surface recon

This opt-in API integration uses the persistent-goal host and settlement
rules from [Apex #1364](https://github.com/pensarai/apex/pull/1364). It replaces the
experimental audit-worker controller as the proposed completion approach; it does
not include that controller or enable goals by default.

```ts
await runGeneralizedAttackSurface({
  ...input,
  goal: {
    objective:
      "Map every supplied service, asset and trust boundary; develop distinct, useful threat hypotheses and check coverage and depth before finishing.",
    maxRounds: 4,
    workSteps: 100,
  },
});
```

Report creation no longer ends a goal run. The original objective and saved messages
carry into subsequent turns. The agent checks the current map, fills gaps and claims
completion through `update_goal`; Jorge's shared controller checks cited tool
results and manages continuation, round/stall limits and blocked outcomes.

Small deterministic checks reject dangling record references, unauthorized report
targets and a report that no longer matches the topology. Ordered attack steps
participate in the snapshot. The report binds to the topology during report-tool
execution, including calls through code mode. Later direct or worker writes require
regeneration. A report marked incomplete cannot settle the goal. Check failures become corrective work without
launching another model or audit worker. Cancellation preserves an active goal;
provider failures block it. Update runs seed the baseline once and preserve their
brief and scope for resume. A limit gets one read-only wrap-up turn.

Coverage and useful depth remain model judgments. No component threat quota is
imposed. Conditional threat hypotheses are appropriate when they state prerequisites
and useful observations for later testing. Neither successful citations nor a goal
marked complete proves comprehensive coverage, correct impact or distinct mechanisms.

## Host boundary

Local runs use the file host. Durable callers supply `goalJournal.runStep` alongside
their ordered model/tool replay hooks. Goal initialization and settlement decisions
then live in that journal. Each executor replays from the first turn, rebuilding its
local transcript and report binding rather than trusting stale scratch files. The
host restores topology and awaits child work and record persistence before returning
each turn. A recorded context without that journal is rejected before dispatch.
Console PR [#4343](https://github.com/pensarai/console/pull/4343) wires this seam
in system recon, separately from chat goals; it has not been deployed. Replayed
completion is rejected if the host did not restore the report and binding or
the restored topology differs from that binding. This checks current consistency;
the host's ordered model/tool journal must reproduce the previously accepted map.
The adapter does not independently compare it with an archived completion snapshot.
The journal pins the update baseline by content,
so changing executor paths is safe but changing the baseline is rejected.
The no-goal API path keeps its existing behavior.

The local host searches retained root-session tool messages; it cannot retrieve
subagent evidence or evidence removed by compaction. Reinspect current state to
produce fresh evidence when needed. Concurrent controllers must not run the same
local session. Blocked goals are terminal for this adapter; start a new session for
a revised objective or budget.

## Bounded evaluation

`scripts/eval-recon-goal.ts` runs either the goal path (`--arm goal`) or ordinary
recon (`--arm baseline`) with source-only backends, an allowlist
of source-navigation/topology tools, and no target network, browser, shell or inbox
access. The default budget is ten minutes and $12 estimated usage. Provider usage
is a catalog estimate, not an invoice or a strict spending cap. All terminal outcomes
retain topology and metrics, including incomplete runs.

The baseline omits `goal` entirely and includes no audit implementation. Both arms
use the same operator objective, tools and 100-step limit per work pass; the goal
arm can perform up to four goal rounds. The baseline can also exceed 100 total
steps through its missing-report continuations. Run each arm into a fresh output directory with
identical source, model, origins and budgets. Ordinary recon retains its existing
missing-report continuation behavior. Input metadata records the selected arm,
and results retain the goal state (absent for the baseline).

Use only generated customer repositories from the
[balanced fixture](https://github.com/pensarai/recon-eval-environments/pull/1), not
its evaluator directory. The fixture has four matched services and 24 hidden
coverage opportunities. Its reviewer-based scorer measures coverage/depth per
service, the weakest service and the spread; extra records do not earn extra credit.

```sh
bun --env-file=/absolute/path/to/provider.env scripts/eval-recon-goal.ts \
  --arm goal \
  --fixture /absolute/path/to/generated/balanced-services \
  --output /absolute/path/to/new/output \
  --origin http://billing.balanced.localtest.me:18401 \
  --origin http://fulfillment.balanced.localtest.me:18402 \
  --origin http://support.balanced.localtest.me:18403 \
  --origin http://documents.balanced.localtest.me:18404 \
  --objective-file /absolute/path/to/balanced-services/agent-objective.txt
```

The first origin is the initial target; all are authorized report origins. Rotate
that first origin and repeat trials before interpreting consistency as reliability.
Keep the evaluator answer key, ratings and score files outside the agent scope.

The preserved experimental branch `codex/recon-persistent-goals` contains the
paired goal/audit runner and historical comparisons. This replacement branch keeps
only the goal/plain recon runner so closing the audit PR does not reintroduce its architecture
through the new PR. The audit baseline is preserved at Apex `d07b62a6` and Console
`2e10deb95`; no branches or evidence are deleted when their PRs close.
