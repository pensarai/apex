# Operator context growth

## Evidence that motivated the benchmark

A read-only snapshot of one active operator run at 2026-10-12 23:24:52 UTC
contained 474 root steps across 14 streams. The step-level usage records summed
to 106.77M input tokens, including 104.73M cache-read tokens; cache reads are
part of input tokens, not additional tokens. Of those steps, 350 reported more
than the configured 128K context length, with a maximum of 453,842. Four steps
were marked as summarized. Two `list_memories` results were 103,412 characters
each. These are aggregate counts and lengths only; the run's prompts, tool
content, target, and model are not included here.

The trace establishes the symptom, not provider billing or a causal attribution
for every token. The code path gives a testable explanation: `streamResponse`
fits the starting messages once, while the SDK may execute many tool steps in
the same stream. Its `prepareStep` does not fit the growing messages. A provider
that accepts oversized prompts never triggers reactive recovery. The memory
tool also returns every summary in one result.

## Reproducible harness

Run from the repository root:

```sh
APEX_CONTEXT_BENCH=1 bun run test src/core/ai/ai.operator-context.bench.test.ts --reporter=verbose
```

The test uses the real `streamResponse` and AI SDK tool loop with a synthetic
provider. It makes 72 successful tool calls and one final response, with fixed
1,400-character tool arguments and 4,000-character tool results. The configured
window is 32K tokens with 4K reserved for output. The provider records the
prompt at every dispatch. No API key, external target, or network call is used.

| Revision            | Provider calls | Summary calls | Peak estimated input | Cumulative estimated input |
| ------------------- | -------------: | ------------: | -------------------: | -------------------------: |
| `6bd9a0eb` baseline |             73 |             0 |               97,835 |                  3,571,835 |

The benchmark's input figures use Apex's `estimateMessageTokens` heuristic on
the provider-visible prompt, not provider-reported usage. The synthetic model
does not enforce its context limit; that makes the unbounded growth observable
without a provider error. Later changes should preserve all 72 tool executions
and the final response while reducing the peak and cumulative input.
