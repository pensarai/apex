# PR07 — Incremental artifact preview reads

`readWhiteboxArtifact` previously loaded the entire artifact with
`readFile(path, "utf8")` before slicing a 40,000-character inline preview, so
every preview paid the whole file in file bytes consumed, decoded-string
memory, and wall time — a 32 MiB artifact consumed all 33,554,432 file bytes
and retained the full decoded string for one small prefix.

The preview now streams through a fixed 16 KiB buffer with a `StringDecoder`
and stops as soon as the decoded length is known to exceed the cap
(see `readTextPrefix` in `src/core/whitebox/artifacts.ts`). Output is
indistinguishable from the old whole-file decode + slice: the same
replacement characters for malformed or truncated byte sequences, the same
lone-surrogate halves when the limit splits an astral pair, the same
truncation marker, and unchanged path/symlink containment guards. The
complete artifact stays on disk untouched; small artifacts still return
whole. The public return shape is unchanged from Canary.

## Bounds

- File bytes consumed for the 32 MiB **ASCII** fixture: exactly 49,152
  (three 16 KiB chunks — one byte per UTF-16 unit is the cheapest case).
- General worst case: one chunk more than the prefix needs, where the
  per-unit cost is at most 3 UTF-8 bytes per UTF-16 unit (e.g. CJK). For the
  40,000-unit cap that is 16,384 × ceil(3 × 40,001 / 16,384) = 131,072 file
  bytes — measured exactly on a 30 MB (30,000,000 bytes) pure-CJK artifact.
  Anything cheaper per unit (ASCII, astral pairs at 2 bytes/unit) consumes
  fewer file bytes.
- Retained storage is prefix-sized, O(cap + chunk): the decoded prefix plus
  one 16 KiB buffer and fixed decoder state, independent of file size.
  Runtime allocation bytes are not inferred from code-unit counts.
- Complexity: O(min(bytes the prefix can reach, file size)) file bytes
  consumed versus O(file size) before.

## Regression gates

The resource gates measure the **public** reader independently: the test
wraps real `node:fs/promises` `open` (patching each returned handle's `read`)
and `readFile`, arms the counters only around the `readWhiteboxArtifact`
call, and asserts the byte budget before any metadata. A whole-file
`readFile` inside the public path is counted, so reverting the public reader
— with or without the helper — fails on the actual 33,554,432 / 30,000,000
file bytes consumed, not on a missing field
(`evidence/pr-07/public-revert-mutation-check-instrumented.log`; the mutated
tree keeps the helper, and its helper-contract tests stay green).

Remaining gates: UTF-8 parity with whole-file decode (chunk boundaries,
malformed bytes, incomplete EOF flush, split surrogates), hostile-limit
rejection, exact-fit, on-disk integrity, non-caller-controlled cap, symlink
containment, and descriptor-release on read failure. "File bytes consumed"
counts bytes returned by the read API — no physical-disk-I/O counters are
collected (filesystem caching applies).

## Evidence

Reproduce the timing path (public `readWhiteboxArtifact` over artifacts
written by the production `writeWhiteboxArtifact`, uninstrumented):

```
bun run scripts/performance/artifact-preview-bench.ts --label candidate
```

Five alternating fresh-process pairs of the same script on baseline
`be2e4b81` and the PR head, under the shared validation lock, are recorded in
`apex-performance-stack-20260927/evidence/pr-07/alternating-bench-revised.jsonl`
(each record carries label, git revision, tree root, source hash, and
runtime). The earlier `alternating-bench.jsonl` trials are preserved as
originally recorded; their `bytesRead` column was the public field this
revision removed, so byte counts now come only from the instrumented gates.
The mutated-tree check (public reader reverted to the original whole-file
`readFile`, helper retained, source hashes verified against git) is recorded
in `public-revert-mutation-check-instrumented.log`. On baseline
`be2e4b81` the helper-level tests fail at import (the helper does not exist
there) while the public-output parity tests pass on both sides by design.

Runtime: bun 1.3.14 on macOS arm64 (local evidence machine); CI asserts only
the deterministic file-byte counts. No deployed/harness-wide gain is claimed
from this local measurement.
