# Whitebox profile cache: coalescing concurrent misses

## Scope

`src/core/agents/offSecAgent/tools/queryWhiteboxCatalog.ts` only.

- The completed-profile cache is unchanged: 45-second TTL, 16-entry cap with
  oldest-first eviction.
- Added an in-flight map keyed by the existing `sessionId\0rootPath` key.
  Overlapping misses for the same key share one `profileCodebase` attempt;
  each caller awaits the same promise.
- `profileCodebase` failures keep the baseline fallback: the attempt resolves
  to `undefined` for every waiter (no new observable errors), nothing is
  retained in the completed cache, and the in-flight entry is dropped in a
  `finally` so the next miss retries. The `finally` deletes only its own
  attempt (identity check), so a replacement attempt for the same key cannot
  be swept by a stale cleanup.
- No unbounded promise retention: entries live only while an attempt is
  pending. No new cache framework, TTL, or eviction behavior.

## Regression gates

- `queryWhiteboxCatalog.test.ts` (fault semantics, mocked `profileCodebase`):
  - sixteen concurrent misses → exactly one attempt, all outputs equal, warm
    hit makes no further attempt;
  - one shared failed attempt → all sixteen callers get the fallback
    (tool success with catalog records), the next wave retries (second
    attempt), then the completed cache serves warm hits;
  - warm hit, 45s TTL expiry, session/root isolation;
  - 16-entry cap still evicts the oldest completed entry;
  - an abandoned waiter does not disturb the others' shared result.
- `queryWhiteboxCatalog.coalescing-cost.test.ts` (real filesystem fixture,
  counting wrappers around the real `profileCodebase` and `fs/promises.readdir`):
  sixteen concurrent lookups run exactly one profile attempt and one
  directory-read pass (readdir count equal to a single lookup).

On baseline `be2e4b81`: 4 of 6 fail (sixteen/four/one attempts per wave);
the TTL-isolation and 16-entry-cap tests pass on baseline because the
completed cache is unchanged by design. Log:
`evidence/pr-06/baseline-test-failures.log` in the performance-stack
evidence directory.

## Benchmark

`scripts/performance/whitebox-profile-coalescing.ts` fires 16 concurrent
`query_whitebox_catalog` lookups for the same session/root through the
production tool at a generated real filesystem fixture (120 dirs × 10
`.ts` files + `package.json`; not a git checkout so profiles carry no
`currentCommit` and outputs stay comparable across trees).

Parent CPU is measured in-process (`process.cpuUsage`, excludes the
profile's `git`/`which` subprocesses). Total CPU is captured by wrapping each
fresh child in `/usr/bin/time`, whose wait4 rusage rolls up waited-for
descendants; `childCpu = total − parent` is approximate at the host `time`
granularity (10 ms on macOS).

Environment: Bun 1.3.14, Node v26.9.0, macOS arm64, single laptop shared
with other agent panes; comparisons ran under the stack's validation lock
but idle-loop workloads were not suspended — treat numbers as indicative.
The deterministic gates above carry the regression signal; no timing
assertion gates CI.

Commands (candidate worktree; baseline is a `git archive` snapshot of
be2e4b81 with the script copied in untracked):

```sh
# single measurement (current tree), generated fixture
bun run scripts/performance/whitebox-profile-coalescing.ts --requests 16

# 5 alternating fresh-process trials, both trees
python3 …/coordination/with-validation-lock.py \
  bun run scripts/performance/whitebox-profile-coalescing.ts --compare true \
  --baseline-root <baseline-snapshot> \
  --baseline-revision be2e4b8174271189e3034efd07fa0138f18e820d \
  --trials 5
```

Medians over 5 alternating trials (raw per-trial records, each with
label/revision/root/source-hash/runtime, in the log):

| tree      | wall     | parent CPU | child CPU (approx) |
| --------- | -------- | ---------- | ------------------ |
| baseline  | 221.4 ms | 332.0 ms   | 1,289.5 ms         |
| candidate | 60.1 ms  | 28.6 ms    | 252.0 ms           |

Output hashes matched across trees on every trial (`hashesEqual=true`,
3 records per lookup). Baseline parent CPU exceeds its wall time because
sixteen concurrent walks overlap on multiple cores; the candidate collapses
the same wave into one walk. Logs: `benchmark-comparison.log` (pre-commit
working tree) and `benchmark-comparison-committed.log` (post-commit
verification, identical candidate source hash) in `evidence/pr-06/`.

## Limitations

- Work-count claims (1 attempt vs 16; one readdir pass vs sixteen) are the
  deterministic vitest gates, not the timing table.
- `childCpu` is derived from `/usr/bin/time`'s 10 ms-granularity rusage and
  excludes subprocesses the tool process never waits on; treat it as a
  coarse split, not an exact bill.
- The fixture is a generated tree, smaller than a real repository; on the
  full Apex checkout the same coalescing removes sixteen full repo walks
  per burst, which this local benchmark does not claim as a deployed
  end-to-end number.
