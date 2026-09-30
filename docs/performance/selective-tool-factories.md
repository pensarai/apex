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
- Browser selection still creates one shared group state plus a fixed set
  of 8 lazy member closures; only the selected member's `tool()` object
  builds. Sibling **construction** is zero, but this is not a global
  zero-sibling-memory claim — module-level schemas remain eager in both
  designs.
- Construction avoidance applies to **selection** only. A builtin
  overridden by `extraTools` is still constructed and then replaced by the
  extra; the overwrite is not an avoided construction.

## Measurement protocol and results

Final numbers: five counterbalanced blocks (odd blocks parent-first, even
blocks candidate-first — net 3 parent-first / 2 candidate-first), 15 fresh
processes total, 32 sets each, run under the shared validation lock with a
clean environment. Measured at candidate commit
`0f44b116b74dc551fb586cdde2213ca9c98f1cac` (clean tree
`fd23bda3d99cd1e177cbf4059f7fccf7e9936305`) against the exact PR02 parent
`8c5b46c88063455af3f837b254ba1351a7574177` (tracked-clean); runner
`scripts/performance/selective-tool-factories.ts`
(SHA-256 `8eec4b33…73f27f9`, verified before, per-record, and after);
runtime bun 1.3.14 on macOS arm64. Raw records, exit codes, and per-run
stdout/stderr are unchanged under the coordination evidence directory
(`evidence/pr-03/final-pairs/`).

Medians (n = 5 per class) and observed ranges (all runs retained; ranges
varied substantially within classes and the cause is undetermined):

| Class                                |                     Wall |       CPU | Heap (post-GC observed) | RSS (observed) |
| ------------------------------------ | -----------------------: | --------: | ----------------------: | -------------: |
| parent all-mode                      | 115.12 ms (97.13–380.90) | 166.66 ms |  50.68 MB (47.23–53.47) |       78.68 MB |
| candidate all-mode (matched control) | 120.64 ms (79.56–655.93) | 177.95 ms |  54.35 MB (42.77–71.75) |       80.08 MB |
| candidate selected-7                 |      0.55 ms (0.50–0.74) |   0.65 ms |                 0.00 MB |        0.08 MB |

Schema parity held across the batch: the full-map digest
(`c0284e0c5e22…a9b1cee`) is identical for every all-mode record on both
trees, and the selected-7 projection digest
(`13364626f076…4d353317d0`) is identical across all 15 records. Tool
counts pinned: 74/74 keys per set for the all-mode classes, 7 for the
selected fixture, with retained-key totals (2368/2368/224) proving every
set stayed live through the post-construction GC.

Reading: the primary result is the specialist path — the candidate's
selected-7 construction (median 0.55 ms) replaces a construction that
cost the parent 115.12 ms (median) for the full catalog, a large
reduction in construction work for agents that run with small tool
selections. The matched all-mode control medians differ by +4.8 % wall,
+6.8 % CPU, and +7.2 % observed heap in the candidate's direction, and
within-class ranges varied substantially (single runs of 380.90 ms and
655.93 ms against class medians of 115.12 ms and 120.64 ms); the cause of
the variance is undetermined and this sample does not demonstrate
statistical equivalence or a regression between the all-mode controls —
only that both construct the full 74-tool catalog. The all-mode control
does not establish equivalence or isolate a regression; no all-mode
performance improvement is claimed. The selected mode's observed net heap
change was 0.00 MB despite 224 retained tool definitions; this is not an
allocation count or proof of zero retained memory. All 15 recorded runs
are kept; none were excluded or re-run. This is a constructor-level
retention fixture — no startup, end-to-end, billing, or
deployed-performance claim.

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
