# Local recon CSV tracker comparison

This experiment runs generalized recon from fresh local sessions with an optional
CSV tracker and native goal controller. It changes no Console code, product prompts,
or shared goal implementation. All arms receive the same deduplicated domain
inventory, operator objective, model and standard recon workers. The goal arm adds
the native goal lifecycle through a local adapter; the older goal adapter and
audit-worker implementation are not included.

- **Baseline:** `scope.csv` contains stable IDs and domains, without statuses. The
  agent is free to organize its work normally, including creating its own notes.
- **Tracker:** the same inventory plus a seeded `coverage.csv` and instructions to
  maintain per-domain progress, references, shared-model mappings and limitations.
  The orchestrator owns updates; workers return results rather than concurrently
  rewriting the CSV.
- **Goal + tracker:** identical tracker instructions, with the existing Apex goal
  controller maintaining the objective and deciding whether another turn is needed.

This first experiment tests **prompt-guided tracking**, not an enforced completion
gate. The ordinary recon utility stops on report creation; the goal arm stops through
native goal settlement. Post-run checks expose forgotten rows and invalid
component references but do not restart or correct the
agent. A successful return is not evidence that every domain was assessed.

## Run

Use a private, authorized scope CSV with one populated column (an optional
`domain`, `hostname`, or `url` header is supported). Blank rows and trailing empty
columns are accepted; unexpected populated columns and non-origin URLs fail.
Hosts are deduplicated case-insensitively while preserving first-seen order. The
utility uses HTTPS as the initial origin. Apex retains its normal probing tools.

```sh
bun --env-file=/absolute/path/to/provider.env scripts/eval-recon-tracker.ts \
  --arm baseline --scope /private/scope.csv --output /private/runs/baseline-01

bun --env-file=/absolute/path/to/provider.env scripts/eval-recon-tracker.ts \
  --arm tracker --scope /private/scope.csv --output /private/runs/tracker-01

bun --env-file=/absolute/path/to/provider.env scripts/eval-recon-tracker.ts \
  --arm goal-tracker --scope /private/scope.csv --output /private/runs/goal-tracker-01

bun scripts/compare-recon-tracker.ts \
  --baseline /private/runs/baseline-01 --tracker /private/runs/tracker-01 \
  --goal-tracker /private/runs/goal-tracker-01
```

Default model: `anthropic/claude-opus-4.6`. Set `--model` identically in both runs to
change it. Run sequentially to avoid competing for local resources. There is **no
evaluation time or spending cap**; normal agent, provider and per-tool limits still
apply. Interrupting preserves partial metrics and topology when the runtime settles.
`--prepare-only` validates scope and prepares a session without making model calls.
Use a new output directory for each run. Do not feed prior results to either arm.

The baseline and tracker arms call the standard `runGeneralizedAttackSurface` API. They do not
replace the agent definition, tool roster, execution backends, file access, redirect
handling, tool protocol or scope policy. Probing, shell and browser tools remain
available with Apex's existing behavior and safeguards. The only arm-specific
intervention is the seeded tracker plus its usage instructions. Tracker edits use
the existing shell tool; no new agent tool or runtime gate is added.

The goal arm uses a local adapter around the same recon definition because native
`/goal` is wired into the interactive operator, not the recon API. It adds the native
goal prompt and `update_goal` tool, replaces report-based stopping with goal-based
stopping, and reuses `createFileGoalHost`, `settleGoalTurn`, and `scheduleGoalNext`.
Retained messages feed each continuation; the original objective and ledger
instructions return in the system prompt. Goal state is saved in `goal.json`.
Normal probing, browser, shell, file access, workers and tool protocol stay unchanged.
There are no audit workers or extra semantic completion checks.

Native defaults remain: 50 rounds, three stalled automatic rounds, and the standard
10,000-step turn limit. These are the existing controller's limits, not evaluation
time or spending caps. Provider failure blocks the goal; operator cancellation leaves
it active. A blocked limit gets the native final wrap-up. This runner only starts
fresh goals. Native citation checks establish that quoted successful tool output
exists; they do not prove the quoted output establishes substantive completion.

Interrupted pilot runs are excluded from the comparison. Run only against authorized
scope and keep customer inputs, transcripts and generated artifacts outside Git.

## Evaluation

The utility records the source hash, model, source commit, exact prompts, session
paths, tool policy, tool events, HTTP outcomes, usage estimates, final topology and report. It
retains the script snapshot and tracked patch. Cost uses the provider catalog and
recorded usage, not billing reconciliation. Unambiguous native model aliases are resolved for pricing only; an unknown price is reported as unavailable without changing model routing. Both root and worker usage is recorded.

The comparison produces an independent per-domain `domain-evidence.csv`, structural
`assessment.json`, and a self-contained `review.html` exposing every component and
threat. It refuses mismatched input hashes, models, runtime fingerprints (source, dependency manifest, lockfile and runtime config), protocols,
policies or start modes, and mismatched instructions between the two tracker arms.
Script-only commits can differ while runtime inputs stay identical. New runs require committed runtime inputs; archived comparisons inspect the saved tracked patch and resolve the recorded revision. Single-run review does not require Git history. It can also
inspect a running baseline without a second arm.

Compare these dimensions separately:

1. **Breadth:** explicit domain-to-component endpoint mappings; domains referenced
   elsewhere; retired dispositions; unresolved hosts. Retirement is a recorded
   claim, not proof that a host needs no further work. Record aliases, nonproduction hosts, unavailable
   services and third-party customer origins separately during manual review.
2. **Substantive coverage:** inspect whether each mapping has an applicable model or
   a supported limitation. A copied hostname, attempted request, generic shared
   model, or checked tracker row does not establish this.
3. **Depth:** inspect distinct mechanisms, prerequisites, impact, useful follow-up
   tests and service-specific differences. Counts and populated fields are review
   aids, not a quality score; no minimum threat quota applies.
4. **Tracker reliability:** intact scope, meaningful transitions, valid component
   links, supported evidence references and honest blocked/excluded dispositions.
5. **Latency and cost:** wall time, calls, tokens and estimated usage. Longer is
   acceptable when it yields materially more complete work.

The tracker fails this hypothesis if it is ignored, loses rows, bulk-marks sampled
services complete, cites unrelated evidence, or improves only record counts rather
than coverage and useful depth. A single live pair is exploratory: changing target
responses, provider load and model randomness can affect results. Repeat with
alternating arm order before claiming a reliable effect. Console integration and a
deterministic completion gate are follow-up decisions based on those results.

Structured HTTP coverage credits valid starting URLs with recorded transport results, including failed attempts. Redirect destinations are not automatically credited; browser and shell probes require separate review. Malformed tracker files remain visible as errors without hiding topology output.
