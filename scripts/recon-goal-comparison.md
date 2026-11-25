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

## November 25 pilot results

Both runs used the same generated `segmented-corp` source from environment commit
`0611736ea7152c68988243b90a066646dfd99736`. The
[curated results](./recon-goal-comparison-results.json) retain terminal outcomes,
coverage scores, record IDs and manual review findings. Full inputs, events,
usage and topology artifacts are preserved locally in
`Documents/Codex/2026-11-25/recon-goal-comparison`.

| Measure                                  | Persistent goal   | Completion audit       |
| ---------------------------------------- | ----------------- | ---------------------- |
| Terminal outcome                         | Complete, round 4 | Deadline during pass 2 |
| Elapsed                                  | 7m 6s             | 10m                    |
| Estimated provider cost                  | $3.46             | $3.86                  |
| Recorded model calls                     | 35                | 42                     |
| Active components / threats              | 9 / 17            | 10 / 18                |
| Component patterns matched               | 10/10             | 10/10                  |
| Gap themes in analysis                   | 12/12             | 12/12                  |
| Gap themes matched in threats            | 11/12             | 12/12                  |
| Threats with required testability fields | 17/17             | 18/18                  |
| Final report retained                    | Yes               | No                     |

The audit's topology is an **unfinished draft**, not a successful output. Its last
18 audit assessments were all `satisfied`, but deterministic checks rejected eight
recommended targets outside the authorized origin. The subsequent correction
pass reached the deadline before producing a final report. Those assessments
describe an earlier snapshot, not the final retained draft.

The goal's first completion claim failed the retained deterministic scope guard.
The next two failed Jorge's citation check because the claimed `list_files` quote
(`count: 52`) did not exist. The fourth claim cited actual results and completed.
The scope rejection is our adapter's check; it must not be credited to native
goal citation validation. The adapter currently rejects structural failures by
substituting an empty-evidence claim, so the feedback has a misleading
"no evidence" prefix before the real scope reasons. A dedicated completion-guard
result would make that diagnostic accurate without changing Jorge's citation rules.

### Quality findings

Both outputs retained a speculative SSTI threat against
`render_template_string(PAGE, user=user, news=news)`. The supplied portal source
defines `PAGE` as a constant; the attacker-controlled value is context data, not
template source. Both records acknowledge that context values are not re-parsed,
yet still describe expression execution. The audit explicitly endorsed the
scenario as satisfactory. Relevant records are goal `thr_acd91493c4` and audit
`thr_56342a3a4f`; source is `apps/portal/app.py:13-26` in the generated fixture.
This is a substantive failure that field checks and citation matching do not catch.

The goal output also retained a PostgreSQL path through HTTP-only SSRF while its
own rationale ruled that path out (`thr_cce29c2b22`), and a file-scheme SSRF path
unsupported by the stock `requests.get` implementation (`thr_f2df0e0470`). Its
accepted summary said 15 threats while the map contained 17. Two jump-host
scenarios shared the same credential and access path, so their count should not
be treated as two independent entry mechanisms.

The audit draft overstated an HTTP GET preview, which returns at most 500
characters, as a complete network proxy and full internal compromise
(`thr_a31ec4632a`). Open Gitea registration was also extrapolated into repository
and bootstrap-admin access without establishing the deployment state
(`thr_834e354a93`). Neither arm retired a threat during this pilot.

The regex scores overstate quality. The goal's nine components matched ten
patterns because one record covered both edge and static-site concepts. Its
missing PostgreSQL threat match was a wording false negative: the scenario used
"credentials" rather than "password". Every threat met the structural testability
fields, including the unsupported scenarios above. Manual review was neither
blind nor exhaustive, so these findings are counterexamples, not measured
precision rates.

### Interpretation and next evaluation

This pilot supports keeping Jorge's smaller continuation controller as an
experimental alternative. It finished within the budget and demonstrably rejected
fabricated citations. It does **not** establish better semantic completeness or
justify replacing the audit in Console. The audit also failed to demonstrate that
its extra reviewers improve quality enough to justify their time and cost.

Before choosing a default:

1. Repeat paired runs on all three fixtures and update cases, with identical
   model, source, network permissions and budgets. Include ordinary execution as
   a third arm to isolate the value of either completion mechanism. Randomize
   order and retain timeouts and failures; do not select only successful runs.
2. Have a reviewer blind to the arm label supported, distinct causal paths,
   omissions, contradictions, invented deployment facts, justified absences and
   third-party scope. Measure unique supported paths rather than raw threat count.
   Add the constant-template and HTTP-only SSRF cases as explicit negative cases
   in the evaluator, without exposing answer keys to the agent.
3. Record time to an acceptable report, completion rate, input/output/cache usage,
   cost, correction effectiveness and errors remaining after a completion claim.
   Use at least three repeats per fixture before comparing reliability.
4. Supply a durable recon host for goal state, evidence lookup and replay-safe
   continuation; test crash recovery, compaction, cancellation/resume, stale
   reports and duplicate scheduling. Then run a bounded local Console test using
   customer URL/repository inputs, with AWS inventory still excluded.

Reject a default switch if goals lose supported coverage, increase unsupported
claims or contradictions, allow unauthorized targets, accept stale output, or
lose unresolved requirements on recovery. Reject the audit's additional cost if
blind review does not show a meaningful quality improvement. A complete goal or
a satisfied audit is not itself an evaluation success criterion.

## Implementation validation and provenance

Integration commit `4b1663cd74adc53afc63a46ffe7c13b35cbf3474` passed 6,587 tests
(63 skipped), type checking, lint, library build and all 62 export checks. The
suite used Node 22.23.4 and `TMPDIR=/private/tmp`; live-provider credentials were
unset for unit tests. Eleven new adapter tests cover completion evidence, stale
reports, limits, cancellation/resume, failed turns and tool restrictions.

The pilots began before that commit. Their archived implementation snapshots
are authoritative: the final commit additionally restricts the one-step wrap-up
to `read_file` and preserves the original kickoff/evidence window on resume.
Neither path executed in the completed goal pilot; those fixes have unit-test
coverage, not live-pilot evidence. This was a comparison of Jorge's Apex goal
module and our Apex audit controller, not a native Codex `/goal` experiment.

## Follow-up: coverage and depth rather than vulnerability confirmation

A second goal run used the same source-only fixture and model with an explicit
[coverage-and-depth objective](./recon-coverage-objective.txt). It permits conditional
threat hypotheses and asks for distinct mechanisms, attacker positions, control
bypasses, cross-boundary paths and useful testing detail. Exploit confirmation is
deferred to testing. Reproduce with the same command plus
`--objective-file scripts/recon-coverage-objective.txt` and a fresh output directory.
The objective changed, so this run is not a controlled comparison with the first
paired pilot.

The run completed in 519.503 seconds (8m 40s), four goal rounds and 43 model calls,
at an estimated $4.36. It retained nine components, four boundaries, ten flows,
eight controls and 29 threats. All ten fixture service/surface concepts are
represented; the static website is folded into the edge proxy. Seven of nine
components have multiple threats: edge 3, portal 13, intranet 2, PostgreSQL 3,
Gitea 2, VPN 1, jump host 2, backups 1 and Grafana 2.

Manual review finds useful depth in session-forgery-to-SSRF paths, jump-host
tunneling to backups, and database access progressing to tampering and a separate
privilege-escalation hypothesis. All 29 scenarios specify entry points, impact,
ordered actions and verification text, with 3–7 steps (median 5). These are
structural observations, not demonstrated quality scores. Several SSRF and
jump-host records are variants or branches of shared mechanisms; 29 records do
not imply 29 independent mechanisms.

Remaining coverage/depth questions include VPN peer isolation and key lifecycle,
the missing VPN-to-PostgreSQL graph edge despite scenarios relying on it, and
verification steps that establish reachability without establishing access to the
modeled asset. One focused backup-server scenario may be appropriate for that
narrow read-only service. Do not impose a minimum threat quota. Hosted provider
integrations and richer identity models require other fixtures.

The full unedited threats, review, objective, events and terminal result are saved
under `Documents/Codex/2026-11-25/recon-coverage-review`. The standalone
`Threat-Model-Coverage-Review.html` groups actual scenarios by component and expands
their prerequisites, steps, impact, controls and verification guidance. A matching
interactive view supports component filtering and search. No live security tests
or Console runtime changes were made.
