# Effective toolset context budgeting

`streamResponse` resolves the effective toolset from `activeTools` once, before
context fitting, and uses that single map for schema budgeting, provider
exposure, execution, tool-call repair, and the recovery continuations that
spread the normalized options. Previously the proactive/reactive fits counted
every catalog schema while the AI SDK advertised only the active subset —
inactive overhead (35,676 vs 4,387 estimated tokens for the full catalog vs a
7-tool specialist on `claude-sonnet-4-5`) could force Layer-1 truncation and an
unnecessary summarization model call, and un-advertised tools remained
executable because the SDK parses and executes from the full map.

## Regression gate

`src/core/ai/ai.effective-tools.test.ts` pins, against the real catalog, real
SDK, and a mock provider model: the boundary conversation reaches the provider
with exactly the selected schemas (no summary), a genuinely over-budget
conversation still summarizes, reactive overflow recovery truncates against
the selected budget and retries with the same schemas, `undefined` advertises
all tools, `[]` advertises none and executes nothing, unknown/duplicate names
are ignored, the `response` tool stays explicitly activated (never automatic),
repair never synthesizes arguments for unselected tools, prototype-shaped ownnames (`__proto__`, `constructor`) survive as own keys, and the recorded
fitter calls prove reactive recovery ran (a `context_overflow` telemetry
trigger) with every call — proactive and reactive alike — carrying the seven
selected keys and the SAME effective map reference (runtime-verified via a
synchronous passthrough spy; identity for rate-limit/idle/summary-resume
continuations follows from the same single opts normalization and is code
reasoning, not a runtime-tested case). On baseline `be2e4b81`: 16 assertions
fail — 9 as missing-helper TypeErrors (`resolveEffectiveTools` absent) and 7
as genuine behavioral failures (boundary summary, reactive-recovery budget,
reactive-fit map identity, empty-list execution, unselected-tool execution,
response-explicitness, repair gating); the 4 preserved-behavior assertions
pass on both revisions.

## Benchmark

This is a fitter microbenchmark plus deterministic SDK behavior tests — not an
end-to-end timing harness. Each mode runs in its own fresh process; the five
alternating (all, effective) pairs per revision were run as separate
processes on Bun 1.3.14, macOS arm64, with baseline `be2e4b81` using a probe
script identical to the committed one minus the new helper:

```sh
bun run scripts/performance/effective-tool-budget.ts all 4
bun run scripts/performance/effective-tool-budget.ts effective 4
```

The boundary conversation's final history estimates 106,756 message tokens
(the 104,968 seed plus appended tool history), between the two message
budgets (89,324 full-catalog vs 120,613 effective for the 7-tool selection):

| Mode                      | fitsBudget | modified | tool results truncated to disk | median wall |
| ------------------------- | ---------- | -------- | ------------------------------ | ----------- |
| baseline `be2e4b81` (all) | false      | true     | 6                              | 1.00 ms     |
| candidate (all)           | false      | true     | 6                              | 0.98 ms     |
| baseline (effective)      | true       | false    | 0                              | 0.005 ms    |
| candidate (effective)     | true       | false    | 0                              | 0.005 ms    |

Mode `all` reproduces the baseline `streamResponse` input; its decision,
truncation count, and timing match the baseline run, so the fitting layer
itself is untouched (the effective-mode rows are tool-selection fixtures,
identical on both revisions because the probe selects locally). Mode
`effective` is what `streamResponse` passes after this change: the
conversation fits without compaction, no tool results are truncated (avoiding
both the disk writes and the data loss of previews), and the escalation to a
summarization model call — the dominant cost, a full extra LLM round trip —
is avoided. Raw logs:
`apex-performance-stack-20260927/evidence/pr-02/`.

## Limitations

- Fitting-layer timings exclude the provider round trip; the avoided summary
  is evidenced by the deterministic gate, not timed here.
- The `[]` selection is semantically no-tools (nothing advertised, nothing
  executable); the SDK normalizes empty tools plus automatic choice to absent
  tools/choice, so no byte-identical wire claim is made for that edge.
- Reactive recovery re-fits the step-generated response messages; when the
  Layer-1+2 retry fires it retries without the original prompt messages.
  This pre-existing behavior is unchanged and out of scope.

## Integration overlap

- #1023 (`fix/tool-schema-and-activetools-gating`) restricts the SDK tool map
  after fitting and auto-activates `response`. This change restricts the same
  executable map (intentional overlap — do not merge both without
  reconciliation) but resolves it before fitting and never activates tools
  automatically; its "empty means all" comments do not match SDK behavior.
- #1107 (`codex/apex-context-compaction`) adds a second
  `estimateToolsOverheadTokens(tools)` read for its proactive compaction
  threshold inside `streamResponseWithinOperation`; after this change that
  call site reads the already-effective map, so its threshold inherits the
  selected budget with no additional work.
