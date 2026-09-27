# PR08 — Stop recursive listing after its result limit

`list_files` capped its output (200 recursive / 500 flat entries) but still
walked the entire tree to compute an exact `total`, and mapped every entry of
a directory to full path strings before slicing. On a pentest target with a
large tree, most of that work was discarded. This change stops the recursive
walk at the first overflow witness — the 201st collected path — and slices
flat listings before mapping. It does **not** make listing memory strictly
bounded; see the limitation below.

## Contract changes

- Recursive results now report `truncated: true` with
  `totalFound: 201, totalFoundLowerBound: true` — an explicit lower bound,
  never a fake exact total. Untruncated recursive listings are unchanged
  (no extra fields, empty `error`).
- Non-recursive listings keep the exact `totalFound` they already paid for
  (readdir enumerated the whole directory) and add `truncated: true`.
- The TUI summary (`result-registry.ts`) displays lower-bound counts as
  "at least N files" and a bare truncation flag as "N+ files", instead of
  presenting them as exact counts.
- `ctx.abortSignal` is honored before the walk starts and between work units;
  an aborted walk stops and surfaces the abort reason.

## Order

The first 200 paths are byte-identical to the previous unbounded walk on the
same runtime because both consume the same `readdir` order. Directory
enumeration order is OS/runtime-defined and unspecified across runtimes
(reviewer-verified: Node readdir and opendir prefixes differ); no cross-
runtime order equality is claimed. Parity tests compare against an in-test
reference implementing the old unbounded walk in the same process.

## Bounds and the remaining O(width) cost

- JS work is O(L + D): at most L = 201 processed entries (entry construction,
  path joins, isDirectory checks after the loop guard) and at most
  D = 201 directory attempts (the root plus up to 200 accepted directories)
  per recursive call, regardless of tree size. The for-of iterator can pull
  one extra value per unwinding directory before its guard returns — an
  independent probe measures 203 pulls for the 10×25 tree fixture and 202
  for the flat fixture — so the passthrough spy measures pulls, not exactly
  201; both bounds are deterministic CI assertions on the public execute
  path (readdir calls, native enumeration, consumed pulls).
- **Memory is not globally bounded.** Every visited directory still pays its
  full `readdir` enumeration — the runtime materializes each directory's
  entire width before the JS loop reads its prefix, so native enumeration
  work is O(sum of visited directory widths) and retained arrays depend on
  the widths along the active recursive ancestry, not O(201). A hostile huge
  flat directory retains its existing O(width) allocation on every runtime
  this code runs on; the public-path passthrough counter measures it
  (2,000 materialized entries for the 2,000-file fixture, 20,000 in the
  benchmark) alongside the bounded JS consumption. This is a deliberate
  limitation: streaming directory access (`opendir`) was prototyped and
  rejected because Bun 1.3.10 and 1.3.14 implement `Dir.read()` as an eager
  full `readdir` (retaining ~507 KB after the first entry of a 20k-entry
  directory in the reviewer's probe), so it would not bound Bun deployments.
  Native per-directory streaming is deferred until the deployed runtime
  provides it.

## Evidence

Reproduce with the production tool over generated fixtures
(400-level deep chain, 20,000-file flat directory):

```
bun run scripts/performance/list-files-bench.ts --label candidate
```

Alternating fresh-process runs on baseline `be2e4b81` and the PR head under
the shared validation lock are recorded in
`apex-performance-stack-20260927/evidence/pr-08/`:

- Deep fixture: ~27–33 ms → ~4 ms (~7×) with identical first-200 path
  checksums; baseline walked all 800 entries for its exact total, candidate
  stops at 201.
- Huge flat recursive: ~9–10 ms → ~6 ms with identical first-200 SHA-256
  path digests — the retained per-directory readdir allocation keeps both
  sides close (measured RSS comparable, no regression).
- Flat listing: ~9–14 ms → ~6–8 ms with identical first-500 SHA-256 path
  digests (slice-before-mapping avoids building 20k path strings).
- Every record carries the exact head commit; parity claims are SHA-256 over
  the ordered JSON path array, not filename-length checksums.

Runtime: bun 1.3.14 on macOS arm64 (local evidence machine). CI asserts the
deterministic work counts and cancellation semantics, not timings. Baseline
Canary suite is green at `be2e4b81`; on exact baseline source, 15 of the 27
new focused tests fail — 2 because the exported helper is absent, 13 on the
truncation contract, cancellation, lower-bound rendering, and measured
public-path work — while the pure first-N parity tests pass on both, by
design. The reviewer's independent probe
(`reviews/pr08-final-public-resource-probe.*`) confirms the counters on
baseline, candidate, and the public-revert mutant: candidate 9 calls /
210 native / 203 pulls (tree) and 1 / 2,000 / 202 (flat); baseline and
mutant fail with 11 calls / 260 pulls (tree) and 2,000 pulls (flat).
