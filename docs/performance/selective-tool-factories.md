# PR03 — Selective tool-factory construction

The OffensiveSecurityAgent previously constructed its entire ~74-tool
catalog for every agent — including FindingJudge-style specialists that
need 7 — because `activeTools` filtering happened only at the AI-SDK layer
after `createAllTools` had already run every factory. PR02 resolves the
effective name set once, before context fitting; this change makes
construction follow that selection: `createToolsForNames(ctx, names)` runs
only the selected factories, in registry order, and inactive factories
never run.

## What the benchmark measures (and what it does not)

`scripts/performance/selective-tool-factories.ts` runs the **real
production constructors** in one fresh process per invocation, with the
same runner dynamically importing either this repo or the exact PR02
parent (`8c5b46c8`, unmodified source):

- `all` mode — `createAllTools(ctx)`. The parent's stream closure retains
  the full map, so comparing retained full sets against retained selected
  sets is a defensible **retention fixture**, not an end-to-end or startup
  gain claim.
- `selected` mode — `createToolsForNames(ctx, JUDGE_TOOLS)`: the
  specialist 7-tool fixture (FindingJudge's built-ins) through the
  candidate agent path. On the parent this entry point does not exist; the
  runner throws (after fixture cleanup), so the harness pairs parent-all
  vs candidate-selected plus the **matched control** candidate-all.

Each record carries the exact root, git revision, git status entries,
SHA-256 of the seven count-relevant source files, runtime, mode, set
count, retained-tool-key total (keys, not constructions), wall time, a
single `process.cpuUsage()` delta, observed post-GC heap and RSS
differences, and schema-parity SHA-256 digests over the **real canonical
JSON schemas** produced by the production SDK converter
(`asSchema(...).jsonSchema`):

- `fullMapSchemaSha256` — the whole constructed map, emitted by all-mode
  runs (candidate and parent) for the matched control.
- `selectedProjectionSchemaSha256` — the selected seven tools in the
  toolset's actual registry-relative order (never the hardcoded fixture
  order), emitted by both modes so parent-all and candidate-selected can
  be compared on identical schema content.

Warmups and the eager module imports (identical in both designs) run
outside the timed and memory windows. Every retained set is observably
read after the post-construction GC (feeding `retainedToolKeysTotal`), so
retention extends through collection. Temporary fixtures are cleaned in
`finally`, including the throw path. Schema-conversion failures throw —
they invalidate parity and are never coerced into digests.

## Construction and retention accounting

- Retained keys ≠ constructions. On the parent, a full construction
  retains 74 tool definitions but performs **78 `tool()` constructions**:
  the email toolset's four inbox members are constructed twice — once
  inside `createEmailToolset` and once as the direct duplicate calls whose
  results override — so four objects are built and discarded. The
  candidate's full construction performs exactly 74 constructions with
  the email members as direct registry factories; the duplication is gone.
- These counts are asserted deterministically in the vitest gate
  (`selectiveFactories.test.ts`) and independently by the review probes;
  the benchmark deliberately reports **cost only, no forgeable counters**.
- Complexity: name resolution is an O(T + A) registry scan — T registry
  entries plus A requested names — and `listToolRegistryNames` invokes no
  factory at all, unlike the whole-map helper. Construction cost is the
  **sum of the selected factories' individual costs** (O(S) only under the
  assumption that each factory's cost is bounded); storage is
  O(A + S + selected objects) for the selected set.
- Construction avoidance applies to **selection** only. A builtin
  overridden by `extraTools` is still constructed and then replaced by the
  extra; the overwrite is not an avoided construction.

## Measurement protocol

Final numbers come from five counterbalanced fresh-process pairs run
under the shared validation lock, only after root approves the exact
commit; raw records and exit codes land under the coordination evidence
directory (`evidence/pr-03/`). Before that, the script is exercised only
by small locked smoke runs that verify plumbing (mode routing, throw-path
cleanup, digest agreement across modes), with no numerical claims shipped.

## Limitations

- Local, single-process measurement; `process.cpuUsage()` is one coarse
  snapshot.
- Heap and RSS deltas are **observed post-GC differences**: background
  activity and GC timing mean they can drift in either direction, so they
  are reported as observations, not bounds on allocation or retention.
- Module imports — and their eager schemas — are unchanged by this PR and
  excluded from all claims; this is not a startup improvement.
- No end-to-end, billing, token-cost, or deployed-performance claim is
  made from this fixture; token overhead is covered separately by PR02's
  effective-set budgeting.
