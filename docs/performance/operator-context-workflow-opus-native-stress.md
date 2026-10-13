# Opus 4.8 at its 1M context window

The earlier Opus 1M control used 8,000-character file results. It accumulated
21,044,504 input tokens over 120 provider calls, but its largest **single**
call used 337,458 input tokens. The cumulative total is not context-window
occupancy. This replay increases the bounded file results until an individual
Opus call approaches the native 1M window.

## Method

Each run forces 120 `inspect_next` calls: 12 directory listings, 12 source
searches, and 96 file reads from the same 12 public Apex files at commit
`6bd9a0ebe859eb724b3f7261a9ba3ffc685174a7`. Each read or search result
is capped at 64,000 characters. The ordered tool results contain 2,438,652
characters and have SHA-256
`a8119582605ada030878ba8b8f1ecf2a7fd590ab3590719f98f65b1e892e0ba4`
in all six runs. The file snapshot SHA-256 is
`41558c6a89fd803c3b3df35b5ad5cdb71b7c6098c0bdb2a47460acc26342bf7a`.

The model is `claude-opus-4-8` via the direct Anthropic provider. Apex's local
context window is 1,000,000 tokens, matching its catalog entry, and the
configured output reservation is 128,000 tokens. The 100M input-token cap is
a **cumulative run stop guard**, not a context-window setting. Every trial
starts a fresh process. Each baseline at runtime `79788062` precedes its
fitted counterpart at runtime `043eaeaf`. Both checkouts use script SHA-256
`529f9a4a116d1958cd0d0a4de2fa778687ae01b3cd67313bc4ccfe66c8dc4ccd`.
Only the script's accepted result-size bound changed for this case.

## Provider-reported results

Input totals include cache-read input on completed calls. Saved tokens are
baseline minus fitted; a negative value means fitted used more. Percentages
use each pair's baseline total. The ± values are mean ± sample standard
deviation over three pairs; percentage spread is in percentage points (pp).

|          Pair | Baseline cumulative input | Fitted cumulative input |        Saved |              Paired decrease | Peak single-call input, both | Summaries, each |
| ------------: | ------------------------: | ----------------------: | -----------: | ---------------------------: | ---------------------------: | --------------: |
|             1 |                64,180,055 |              64,180,067 |          −12 |                   −0.000019% |                      990,634 |               1 |
|             2 |                64,180,017 |              64,180,083 |          −66 |                   −0.000103% |                      990,634 |               1 |
|             3 |                64,180,173 |              64,180,257 |          −84 |                   −0.000131% |                      990,634 |               1 |
| **Mean ± SD** |       **64,180,082 ± 81** |    **64,180,136 ± 105** | **−54 ± 37** | **−0.000084% ± 0.000058 pp** |              **990,634 ± 0** |       **1 ± 0** |

All six runs completed 120/120 provider steps and 120/120 file operations.
Within every pair, provider input is identical through step 118. Both
variants then summarize and resume; the first input difference occurs at
step 119, after that transition. The script does not count rejected provider
attempts, so these totals are not billed-token or dollar-cost measurements.
This fixture shows **no material input reduction** from in-stream fitting at
Opus's actual 1M setting.

The source estimator counts roughly four characters per token, while the
provider reports substantially more tokens for this code-heavy history. The
gap is a plausible reason that proactive fitting did not affect the first
118 steps; the trace does not directly record the fit decision or prove the
summary trigger. The summarizer also excludes tool-call and tool-result
blocks from its summary prompt. Completing this forced tool sequence does not
establish that an autonomous operator retained the discarded file evidence.

## Reproduce and limits

The [raw numeric traces](operator-context-workflow-opus-native-stress.json)
include per-step provider input, summary usage, operation counts, elapsed
time, runtime SHAs, and matching result hashes. They contain no file contents,
session data, or credentials. Run the same script in the clean baseline and
fitted checkouts, three fresh-process pairs, with `ANTHROPIC_API_KEY` set:

    bun --no-env-file scripts/performance/operator-context-workflow-live.ts 120 1000000 claude-opus-4-8 100000000 64000

This is a controlled file-inspection loop with forced tool selection. It
measures provider input and whether the run completes; it does not measure
autonomous task quality or generalize the near-zero result to other tool
mixes. The earlier [matched model comparison](operator-context-workflow-model-parity.md)
used 96K and 200K local windows to expose fitting behavior; its Opus 200K
percentage does not represent the native 1M configuration.
