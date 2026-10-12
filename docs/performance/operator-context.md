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

The provider input figures use Apex's `estimateMessageTokens` heuristic, not
provider-reported usage. The synthetic model does not enforce its context
limit; that makes the baseline's unbounded growth observable without a provider
error.

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
