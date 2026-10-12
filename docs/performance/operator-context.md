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
| In-stream fit       |             73 |             1 |               16,902 |                    785,758 |

In-stream fitting reduces the peak estimate by 82.7% and the cumulative
estimate by 78.0% in this fixture. All 72 tool calls still execute and the
final response completes. One summary model call is added when truncating and
snipping tool history can no longer fit the configured budget. The benchmark
asserts an 18K peak and 1.3M cumulative ceiling to catch a return to
unbounded growth without requiring an exact output from the tokenizer
heuristic.

The benchmark's input figures use Apex's `estimateMessageTokens` heuristic on
the provider-visible prompt, not provider-reported usage. The synthetic model
does not enforce its context limit; that makes the unbounded growth observable
without a provider error. Later changes should preserve all 72 tool executions
and the final response while reducing the peak and cumulative input.

## Live provider replay

`scripts/performance/operator-context-live.ts` runs the production
`streamResponse` path against Anthropic's Claude Haiku 4.5 with a forced,
one-at-a-time synthetic tool. The tool returns the same 8,000-character record
sequence on every run; only its ordinal changes. No external target, user data,
or prior session content is sent. The script reports usage from completed model
steps, including any summarization call, and stops before its 1M-input-token
limit. Run it in a fresh process from each revision:

```sh
bun --no-env-file scripts/performance/operator-context-live.ts 30 8000 96000
```

The key is read from `ANTHROPIC_API_KEY`. The third argument changes Apex's
_local_ catalog window for this isolated process. The 96K setting leaves about
21K estimated message tokens after Apex's 64K output reservation, 10K safety
margin, and tool overhead. Haiku's catalog window remains 200K in normal runs;
the smaller test window makes the in-stream threshold reachable before the
1M-token spend cap. These are real provider calls with provider-reported usage,
but a controlled stress fixture rather than a full operator session at the
model's default window.

| Revision            | Tool calls | Summary calls | Provider input | Peak step input | Provider output | Cache-read input |
| ------------------- | ---------: | ------------: | -------------: | --------------: | --------------: | ---------------: |
| `79788062` baseline |         30 |             0 |        769,080 |          50,576 |             480 |          714,744 |

Input includes cache-read tokens; the cache-read column is a subset, not an
additional charge or token count. The first 30 per-step input figures are saved
in `operator-context-live.json`. The baseline rose from 696 on the first step
to 50,576 on the thirtieth, with no in-stream fit or summary. Provider output
and the completed tool count are also recorded so later revisions can be
compared on the same work.
