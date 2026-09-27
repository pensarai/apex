# Effective toolset context budgeting

`streamResponse` resolves the effective toolset from `activeTools` once, before
context fitting, and uses that single map for schema budgeting, provider
exposure, execution, tool-call repair, and every recovery continuation.
Previously the proactive/reactive fits counted every catalog schema while the
AI SDK advertised only the active subset — inactive overhead (35,676 vs 4,387
estimated tokens for the full catalog vs a 7-tool specialist on
`claude-sonnet-4-5`) could force Layer-1 truncation and an unnecessary
summarization model call, and un-advertised tools remained executable because
the SDK parses and executes from the full map.

## Regression gate

`src/core/ai/ai.effective-tools.test.ts` pins, against the real catalog, real
SDK, and a mock provider model: the boundary conversation reaches the provider
with exactly the selected schemas (no summary), a genuinely over-budget
conversation still summarizes, reactive overflow recovery truncates against
the selected budget and retries with the same schemas, `undefined` advertises
all tools, `[]` advertises none and executes nothing, unknown/duplicate names
are ignored, the `response` tool stays explicitly activated (never automatic),
and repair never synthesizes arguments for unselected tools. On baseline
`be2e4b81` the 14 wiring/gating assertions fail; 3 preserved-behavior
assertions pass on both revisions.

## Benchmark

```sh
bun run scripts/performance/effective-tool-budget.ts all 4
bun run scripts/performance/effective-tool-budget.ts effective 4
```

Alternating fresh-process trials, Bun 1.3.14, macOS arm64. Boundary
conversation (104,968 message tokens) between the two message budgets
(89,324 full-catalog vs 120,613 effective for the 7-tool selection):

| Mode                      | fitsBudget | modified | tool results truncated to disk | median wall |
| ------------------------- | ---------- | -------- | ------------------------------ | ----------- |
| baseline `be2e4b81` (all) | false      | true     | 6                              | 0.67 ms     |
| candidate (all)           | false      | true     | 6                              | 0.72 ms     |
| candidate (effective)     | true       | false    | 0                              | 0.005 ms    |

Mode `all` reproduces the baseline `streamResponse` input; its decision,
truncation count, and timing are unchanged on the candidate, so the fitting
layer itself is untouched. Mode `effective` is what `streamResponse` passes
after this change: the conversation fits without compaction, no tool results
are truncated (avoiding both the disk writes and the data loss of previews),
and the escalation to a summarization model call — the dominant cost, a full
extra LLM round trip — is avoided. Raw logs:
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
