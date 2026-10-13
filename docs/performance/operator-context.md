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
1M-input-token cap. These are real provider calls with provider-reported usage,
but a controlled stress fixture rather than a full operator session at the
model's default window.

| Revision            | Tool calls | Summary calls | Provider input | Peak step input | Provider output | Cache-read input |
| ------------------- | ---------: | ------------: | -------------: | --------------: | --------------: | ---------------: |
| `79788062` baseline |         30 |             0 |        769,080 |          50,576 |             480 |          714,744 |
| `66c01d97` fit      |         30 |             0 |        248,378 |          17,896 |             480 |          233,776 |
| `66c01d97` repeat   |         30 |             0 |        248,360 |          17,896 |             480 |          233,760 |

Input includes cache-read tokens; the cache-read column is a subset, not an
additional charge or token count. All three 30-step input series are saved in
`operator-context-live.json`. The first 11 provider steps have identical usage;
the twelfth drops from 19,616 baseline input tokens to about 4,540 after
fitting. Provider input falls 67.7% across the full workload and peak step
input falls 64.6%, while all 30 tool calls and 480 output tokens remain. The
two fixed runs differ by 18 input tokens in total. No summarization model call
was needed in this fixture; the improvement comes from fitting old tool
results during the stream.

A longer fixed run with 60 tool calls used 738,484 provider-reported input
tokens, peaked at 21,412 in one step, and produced 960 output tokens with no
summary or provider context error. The script enforces the same per-run cap.

As a threshold check, the fixed 30-step workload was also run with Haiku's
normal 200K catalog window (`30 8000 200000`). It used 769,080 input tokens,
matching the baseline: the conversation did not reach that larger local fit
threshold. The 67.7% figure therefore applies to the stated 96K stress budget,
not every session using Haiku's default configuration. Actual agent tasks,
tool mixes, and provider cache pricing can change the end-to-end savings.

## Fitted transcript handoff

The same test file also replays a new stream with 40 synthetic prior tool
exchanges and one final response. The entry fit shortens old tool results, then
the benchmark reconstructs the legacy `messages.json` snapshot both ways:

| Transcript source                           | Messages | Estimated tokens |
| ------------------------------------------- | -------: | ---------------: |
| Original input plus generated response      |       82 |           41,352 |
| Prepared context plus new response messages |       82 |            6,870 |

Using the prepared context reduces the persisted estimate by 83.4% in this
fixture while retaining the conversation structure and the persisted tool-result
references. This measures transcript size, not provider billing. The earlier
writer could restore a fitted-away prefix at the end of a stream and force the
next stream to compact it again.

## Memory listing output

`list_memories` now returns at most 20 summaries per call with a 12K-character
page budget. The response retains the total match count and supplies
`nextOffset` until every summary has been listed. Long titles and tags are
marked as abbreviated; their full values remain available through
`get_memory` by category and id.

In a network-free fixture with 200 memories, the previous single result was
122,432 characters. The first page is 6,018 characters, 95.1% smaller. Ten
pages recover all 200 ids, and the oldest memory remains retrievable. This
measures one tool response, not total cost if the agent chooses to read every
page. The improvement comes from letting the agent stop after the relevant
page or use category/tag filters.
