# PR07 — Incremental artifact preview reads

`readWhiteboxArtifact` previously loaded the entire artifact with
`readFile(path, "utf8")` before slicing a 40,000-character inline preview, so
every preview paid the whole file in bytes read, decoded-string memory, and
wall time — a 32 MiB artifact read all 32 MiB from disk and retained the full
decoded string for one small prefix.

The preview now streams through a fixed 16 KiB buffer with a `StringDecoder`
and stops as soon as the decoded length is known to exceed the cap
(see `readTextPrefix` in `src/core/whitebox/artifacts.ts`). Output is
indistinguishable from the old whole-file decode + slice: the same
replacement characters for malformed or truncated byte sequences, the same
lone-surrogate halves when the limit splits an astral pair, the same
truncation marker, and unchanged path/symlink containment guards. The
complete artifact stays on disk untouched; small artifacts still return
whole. The public reader now reports its own disk I/O in `bytesRead`, which
the regression gates assert directly — reverting the public reader to a
whole-file read (helper or not) fails the suite
(`evidence/pr-07/public-revert-mutation-check.log`).

## Bounds

- Bytes read for the 32 MiB **ASCII** fixture: exactly 49,152
  (three 16 KiB chunks — one byte per UTF-16 unit is the cheapest case).
- General worst case: one chunk more than the prefix needs, where the
  per-unit cost is at most 3 UTF-8 bytes per UTF-16 unit (e.g. CJK). For the
  40,000-unit cap that is 16,384 × ceil(3 × 40,001 / 16,384) = 131,072
  bytes — measured exactly on a 30 MiB pure-CJK artifact. Anything cheaper
  per unit (ASCII, astral pairs at 2 bytes/unit) reads fewer bytes; a
  4-byte-sequence file reads the same 131,072-or-less family of bounds.
- Retained strings: decoder output plus one chunk (~131 KiB at the cap for
  CJK, ~98 KiB for ASCII), independent of file size. Before: the whole file
  buffer plus the whole decoded string, whose engine representation is
  runtime-dependent.
- Complexity: O(min(bytes the prefix can reach, file size)) disk reads and
  prefix-sized string memory, versus O(file size) before.

## Evidence

Reproduce with the production path (public `readWhiteboxArtifact` over
artifacts written by the production `writeWhiteboxArtifact`, including a
30 MiB CJK fixture):

```
bun run scripts/performance/artifact-preview-bench.ts --label candidate
```

Alternating fresh-process runs of the same script on baseline
`be2e4b81` and the PR head, under the shared validation lock, are recorded in
`apex-performance-stack-20260927/evidence/pr-07/` (median wall time, RSS, and
the public reader's `bytesRead`; baseline reports `bytesRead: null` because
the field does not exist there). Baseline Canary suite is green at
`be2e4b81`; on baseline the new byte-count and helper-contract tests fail
(undefined `bytesRead`, absent helper), while the public-output parity tests
pass on both sides by design.

Runtime: bun 1.3.14 on macOS arm64 (local evidence machine); CI asserts only
the deterministic byte counts. No deployed/harness-wide gain is claimed from
this local measurement.
