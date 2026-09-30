# JS endpoint extraction: linear dedup + crawler HTML reuse

## Scope

`src/core/agents/specialized/attackSurface/jsExtraction.ts` and
`src/core/agents/offSecAgent/tools/crawlAuthenticated.ts`.

- The fetching helper `extractJavascriptEndpoints` is unchanged in behavior;
  its body now delegates to a new pure parser
  `extractJavascriptEndpointsFromHtml(html, url, includeExternalJS)`.
- Deduplication replaced the `Set` + per-endpoint `Array.find` pass with a
  single insertion-ordered `Map` keeping the first record per endpoint.
  Expected time drops from O(n²) to O(n) over raw matches (n); memory is O(u)
  for u unique endpoints. Output ordering, first-record metadata, counts, and
  messages are unchanged.
- `crawl_authenticated_area` now runs the pure parser on the HTML it already
  downloaded with `targetFetch` (one request per page instead of two). The
  previous second fetch was cookie-only and bypassed the resolver entirely,
  so pages that require session-level `Authorization` headers were parsed
  from their anonymous body.

Out of scope: extraction regex fixes (e.g. the axios first-capture-group
behavior documented in tests), relative-URL handling, and any other caller of
the fetching helper.

## Regression gates

- `src/core/agents/offSecAgent/tools/crawlAuthenticated.test.ts`
  - "issues exactly one authenticated request per visited page" — work-count
    gate; the baseline made two requests per page.
  - "extracts endpoints from the Authorization+Cookie authenticated body it
    already downloaded" — the response requires both the session config's
    `Authorization` header and the caller's cookie; a cookie-only refetch
    would see the anonymous page (fails on baseline with `/api/anon`).
  - Full-crawl output parity, error-status, fetch-failure, and scope
    violations.
- `src/core/agents/specialized/attackSurface/jsExtraction.test.ts` — exact
  output for pattern families (URL/inline scripts, template literals, XHR,
  url/href/action), first-record metadata for duplicates with differing
  metadata, parameterized patterns, script types, external JS toggling,
  non-root-relative filtering, cookie header, and fetch failure. These are
  new-API unit tests and do not run on the baseline tree.

On baseline `be2e4b81` (git-archive snapshot): 11 of 16 fail, including both
crawler work-count gates and the Authorization fixture; all 16 pass on the
candidate. Log: `evidence/pr-05/baseline-test-failures.log` in the
performance-stack evidence directory.

## Benchmark

`scripts/performance/js-endpoint-dedup.ts` measures the production fetching
helper (the same parser on both sides of the change, so the only difference
is the dedup algorithm) on a fixture page where every endpoint appears
twice. Comparison runs alternate fresh baseline/candidate processes per
trial and assert output-hash equality across trees.

Environment: Bun 1.3.14, Node v26.9.0, macOS arm64, single laptop shared with
other agent panes; comparisons ran under the stack's validation lock, but
other idle-loop workloads were not suspended — treat medians as indicative,
not as deployed-harness numbers. The deterministic gates above (request
counts, output parity, exact endpoint records) carry the regression signal;
no timing assertion gates CI.

Commands (candidate worktree; baseline is a `git archive` snapshot of
be2e4b81 with the script copied in untracked):

```sh
# single measurements
bun run scripts/performance/js-endpoint-dedup.ts --mode fetched --size 20000
bun run scripts/performance/js-endpoint-dedup.ts --mode pure --size 20000

# 5 alternating fresh-process trials per size, both trees via the helper
python3 …/coordination/with-validation-lock.py \
  bun run scripts/performance/js-endpoint-dedup.ts --compare true \
  --baseline-root <baseline-snapshot> \
  --baseline-revision be2e4b8174271189e3034efd07fa0138f18e820d \
  --trials 5
```

Fetched-helper medians over 5 alternating trials (raw trials in the log;
each record carries label/revision/root/source-hash/runtime):

| distinct endpoints (each ×2) | baseline median | candidate median |
| ---------------------------- | --------------- | ---------------- |
| 5,000                        | 57.1 ms         | 4.4 ms           |
| 10,000                       | 247.2 ms        | 6.9 ms           |
| 20,000                       | 833.9 ms        | 11.8 ms          |
| 40,000                       | 3,557.1 ms      | 22.4 ms          |

Output hashes matched across all trees and trials at every size
(`hashesEqual=true`), including unique/total counts (5k/10k/20k/40k unique,
10k/20k/40k/80k total calls). Logs: `benchmark-comparison.log` (pre-commit
working tree) and `benchmark-comparison-committed.log` (post-commit
verification, identical candidate source hash) in `evidence/pr-05/`.

## Limitations

- Wall-time medians are from a shared laptop, not a quiet benchmark host; the
  40k baseline median is conservative (earlier runs under different load
  showed 31 s). The work-count and parity gates are the durable claims.
- The crawler request-count reduction is asserted per visited page; a
  deployed end-to-end crawl benefit depends on page size and network latency,
  which this PR does not claim.
- Fail-on-baseline for the new-API unit tests is an import error by design
  (the pure parser did not exist); the crawler gates fail for the right
  behavioral reasons (request count, anonymous body).
