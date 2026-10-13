# Opus 4.8 1M context: usage-calibrated fitting

The [earlier native-window replay](operator-context-workflow-opus-native-stress.md)
accumulated about 64.18M provider-reported input tokens across 120 calls, while
one call peaked at 990,634 tokens. Cumulative input and single-call context
occupancy are different measures. In-stream fitting made no material difference
in that replay because Apex's four-character token estimate understated the
code-heavy prompt. This comparison measures a follow-up change that uses
completed provider usage to adjust the safety margin for later steps.

## Method

Three fresh-process pairs ran the same fixed source-inspection sequence against
the direct Anthropic provider. Each pair ran the exact #1208 parent runtime
`d7df56abea6edb8fb971ebb794fe402998a87f72` first, followed by the
usage-calibrated runtime `014a837d21366fb9a0b1e52ea5b455f37fe391ce`.
Both checkouts used benchmark script SHA-256
`529f9a4a116d1958cd0d0a4de2fa778687ae01b3cd67313bc4ccfe66c8dc4ccd`.
The only runtime behavior change in this comparison is the in-stream fitter's
safety margin: after a completed main provider step, it retains the largest
observed gap between provider input and the prepared-message estimate, plus a
10K-token reserve, for subsequent fits in that stream.

Each run forced 120 `inspect_next` calls: 12 directory listings, 12 source
searches, and 96 bounded file reads from the same 12 public Apex files at
commit `6bd9a0ebe859eb724b3f7261a9ba3ffc685174a7`. The local Apex window
was 1,000,000 tokens, matching the model catalog entry for `claude-opus-4-8`;
the output reservation was 128,000 tokens. Read and search results were capped
at 64,000 characters. The ordered tool results totaled 2,438,652 characters
and had SHA-256
`a8119582605ada030878ba8b8f1ecf2a7fd590ab3590719f98f65b1e892e0ba4`
in all six runs. The file snapshot SHA-256 was
`41558c6a89fd803c3b3df35b5ad5cdb71b7c6098c0bdb2a47460acc26342bf7a`.
The 100M input-token cap was a cumulative run stop guard, not a context-window
setting; no run reached it.

## Provider-reported results

Input totals include cache-read tokens on completed calls. Saved tokens are
parent minus calibrated, and each percentage uses its own pair's parent total.
The ± values are mean ± **sample standard deviation** over three pairs;
percentage spread is in percentage points (pp), not a confidence interval.

|          Pair | Parent cumulative input | Calibrated cumulative input |                  Saved |              Paired decrease | Peak single-call input, parent → calibrated | Summaries, parent → calibrated |
| ------------: | ----------------------: | --------------------------: | ---------------------: | ---------------------------: | ------------------------------------------: | -----------------------------: |
|             1 |              64,180,363 |                  47,729,017 |             16,451,346 |                   25.632990% |                           990,634 → 849,895 |                          1 → 0 |
|             2 |              64,180,431 |                  47,726,973 |             16,453,458 |                   25.636254% |                           990,634 → 849,895 |                          1 → 0 |
|             3 |              64,180,057 |                  47,728,927 |             16,451,130 |                   25.632776% |                           990,634 → 849,895 |                          1 → 0 |
| **Mean ± SD** |    **64,180,284 ± 199** |      **47,728,306 ± 1,155** | **16,451,978 ± 1,286** | **25.634006% ± 0.001949 pp** |               **990,634 ± 0 → 849,895 ± 0** |              **1 ± 0 → 0 ± 0** |

All six runs completed 120/120 provider steps and 120/120 file operations.
Within each pair, provider input was identical through step 97 and first
changed at step 98. The calibrated runs then fit history sooner, stayed below
850K input on every call, and needed no summary. All three parents reached
990,634 input tokens in one call and summarized after step 118. This is a
**25.634% mean reduction in cumulative provider-reported input** for this
fixed workload at Opus's actual 1M Apex setting.

## Reproduce and limits

The [raw numeric traces](operator-context-workflow-opus-usage-calibrated.json)
contain per-step provider input, summary usage, operation counts, elapsed
times, runtime and script SHAs, and matching result hashes. They contain no
file contents, session data, or credentials. In each exact-parent and
usage-calibrated checkout, run this command in a fresh process, with
`ANTHROPIC_API_KEY` set, in parent-then-calibrated order for three pairs:

    bun --no-env-file scripts/performance/operator-context-workflow-live.ts 120 1000000 claude-opus-4-8 100000000 64000

A network-free [regression test](../../src/core/ai/ai.operator-context.bench.test.ts)
uses a mock provider whose reported input is twice Apex's estimate and rejects
prompts above 90K tokens. The prior code made two rejected over-limit calls;
the calibrated code completed 60 tool calls and the final response with zero
rejections and zero summaries. The focused test is run with:

    bun run test src/core/ai/ai.operator-context.bench.test.ts src/core/ai/ai.durability-hooks.test.ts

The live fixture forces tool selection and measures token usage and completion
of that fixed sequence. It does not establish autonomous task quality or that
all evidence omitted from a fitted prompt remains useful to the model. The
script does not count rejected provider attempts; these totals are not billed
token or dollar-cost measurements. Elapsed times are recorded in the raw
traces but are not used as latency evidence because provider response times
varied across pairs.
