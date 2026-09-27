# PR07 — Incremental artifact preview reads

`readWhiteboxArtifact` previously loaded the entire artifact with
`readFile(path, "utf8")` before slicing a 40,000-character inline preview, so
every preview paid the full file in bytes read, decoded-string memory, and wall
time — a 32 MiB artifact cost ~32 MiB of I/O and ~64 MiB of UTF-16 string.

The preview now streams through a fixed 16 KiB buffer with a `StringDecoder`
and stops as soon as the decoded length is known to exceed the cap
(see `readTextPrefix` in `src/core/whitebox/artifacts.ts`). Output is
indistinguishable from the old whole-file decode + slice: the same
replacement characters for malformed or truncated byte sequences, the same
lone-surrogate halves when the limit splits an astral pair, the same
truncation marker, and unchanged path/symlink containment guards. The
complete artifact stays on disk untouched; small artifacts still return whole.

## Bounds

- Bytes read: 3 × 16 KiB = 49,152 for a 32 MiB ASCII artifact at the 40,000
  cap (each 16 KiB read adds at most 16,384 UTF-16 units, so the loop stops
  after three reads even in the 1 byte/char worst case; multibyte content reads
  the same or fewer). `bytesRead` is asserted deterministically in
  `src/core/whitebox/whitebox.test.ts` — 49,152 exactly — plus an
  upper-bound check, so no timing gate is involved.
- Retained strings: decoder output plus one chunk, ~98 KiB for the cap,
  independent of file size. Before: the whole file buffer plus the whole
  decoded string.
- Complexity: O(min(chars the cap needs, file size)) bytes read and string
  memory, versus O(file size) before.

## Evidence

Reproduce with the production path (public `readWhiteboxArtifact` over an
artifact written by the production `writeWhiteboxArtifact`):

```
bun run scripts/performance/artifact-preview-bench.ts --label candidate
```

Alternating fresh-process runs of the same script on baseline
`be2e4b81` and the PR head, under the shared validation lock, are recorded in
`apex-performance-stack-20260927/evidence/pr-07/` (median wall time, RSS, and
`bytesRead`; baseline reports `bytesRead: null` because the instrumentation
does not exist there). Baseline Canary suite is green at `be2e4b81`; the new
tests fail on baseline only because `readTextPrefix` is absent there — the
behavioral output parity assertions themselves are written to the shared
`readFile`-and-slice contract both sides implement.

Runtime: bun 1.3.14 on macOS arm64 (local evidence machine); CI asserts only
the deterministic byte counts. No deployed/harness-wide gain is claimed from
this local measurement.
