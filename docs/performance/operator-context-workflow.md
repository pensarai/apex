# Operator file-workflow replay

This replay measures the in-stream context fitting change in PR #1206 with a
stable sequence of repository inspection operations. It uses the production
`streamResponse` path and Anthropic's provider-reported usage. The model is
forced to call one tool per step; the tool executes a predetermined directory
listing, source search, or file read. The fixture isolates context growth and
tool-result handling, rather than measuring autonomous task quality.

## Workload and controls

The script loads 12 public Apex TypeScript files from the fixed canary commit
`6bd9a0ebe859eb724b3f7261a9ba3ffc685174a7` into a temporary directory.
It reads those temporary files during the tool loop. Each ten-step block has
one directory listing, one bounded search across the files, and eight bounded
source reads. The 15-, 30-, 60-, and 120-step workloads are prefixes of this
same action sequence. The main comparison bounds reads and searches to 1,500
content characters per step. A separate 120-step normal-window comparison
allows up to 8,000 content characters per read/search to cross the default
fit threshold. Paths, line numbers, and action labels are included in the
tool result. No external target, customer data, or prior session content is
part of the fixture.

The snapshot SHA-256 and ordered tool-result SHA-256 are saved per run. A pair
is included only if both variants complete every requested tool call and both
hashes match. Each included trial runs in a fresh process. The baseline runtime
is `79788062d2ea93e1fa3e9c5ab27f43bcc97b3b36`; the fitted runtime is
`d510b8fc124d3f78e04668317089bf2ab118f945`. The same script is copied
unchanged into the baseline checkout for each comparison. Each record saves
the script SHA-256 for its exact version.

The main 15-, 30-, 60-, and 120-step trials use Claude Haiku 4.5 and a 96K
**local** catalog window, reserving 64K tokens for output and Apex's 10K
safety margin. Anthropic's native context window is not changed. The 15-,
30-, and 60-step runs each enforce a 1M input-token cap; the 120-step runs
allow up to 5M. These are controlled stress conditions. Haiku's normal Apex
catalog window is 200K, so these percentages do not predict savings for every
ordinary session.

## Results

The tables below use provider-reported input tokens, including cache reads.
Cache reads are a subset of input, not an additional token count. Each pair
uses the same model, fixture, step count, and output budget. All ± values are
the arithmetic mean ± sample standard deviation across three completed runs;
the ± on a percentage is in percentage points (pp), not a confidence interval.

| Steps | Listings / searches / reads | Tool-result characters |  Baseline input, trials 1 / 2 / 3 |    Fitted input, trials 1 / 2 / 3 |
| ----: | --------------------------: | ---------------------: | --------------------------------: | --------------------------------: |
|    15 |                  2 / 2 / 11 |                 20,009 |          61,427 / 61,427 / 61,427 |          61,427 / 61,427 / 61,427 |
|    30 |                  3 / 3 / 24 |                 41,543 |       241,687 / 241,687 / 241,687 |       241,687 / 241,687 / 241,687 |
|    60 |                  6 / 6 / 48 |                 82,668 |       941,976 / 941,976 / 941,976 |       921,674 / 921,760 / 921,741 |
|   120 |                12 / 12 / 96 |                163,178 | 3,675,731 / 3,675,731 / 3,675,731 | 1,848,025 / 1,848,441 / 1,847,404 |

| Steps | Baseline input, mean ± SD | Fitted input, mean ± SD | Tokens saved per pair, mean ± SD | Paired input decrease, mean ± SD | Baseline / fitted peak step input |
| ----: | ------------------------: | ----------------------: | -------------------------------: | -------------------------------: | --------------------------------: |
|    15 |                61,427 ± 0 |              61,427 ± 0 |                            0 ± 0 |                0.000% ± 0.000 pp |                     7,711 / 7,711 |
|    30 |               241,687 ± 0 |             241,687 ± 0 |                            0 ± 0 |                0.000% ± 0.000 pp |                   15,765 / 15,765 |
|    60 |               941,976 ± 0 |            921,725 ± 45 |                      20,251 ± 45 |                2.150% ± 0.005 pp |                   30,738 / 30,188 |
|   120 |             3,675,731 ± 0 |         1,847,957 ± 522 |                  1,827,774 ± 522 |           **49.725% ± 0.014 pp** |                   59,773 / 30,188 |

All 24 runs completed their requested tool calls: 3/3 per variant and length.
The two variants had identical provider input at every step of the 15- and
30-step workloads. In all six 60- and 120-step pairs, the first different
provider step was step 60. At 60 steps the fitter only reduced that last call;
at 120 steps it had another 60 calls over which to reduce retained history.
Every variant produced 16 output tokens per main step, and none made a summary
model call. The 120-step fitted runs reduced the peak provider input per main
step from 59,773 to 30,188 tokens (49.496%).

This is a threshold effect, not a claim that every shorter workflow saves
tokens. The 96K local budget is deliberately smaller than Haiku's usual Apex
catalog window to reach the fit threshold in this bounded replay. The separate
normal-window check below shows how the same 120-step workload behaves at the
default setting.

### Normal catalog-window control

The 1,500-character 120-step file workload was run once per variant with
Haiku's normal 200K Apex catalog window. The action-result checksum matched
the 96K runs.

| Local window | Baseline input | Fitted input | Input decrease | Baseline / fitted peak step input | Completed calls |
| -----------: | -------------: | -----------: | -------------: | --------------------------------: | --------------: |
|         200K |      3,675,731 |    3,675,731 |         **0%** |                   59,773 / 59,773 |       120 / 120 |

Neither variant made a summary call. This smaller-result workload did not
reach the normal-window fit threshold.

### Normal catalog window with larger file results

The same 120 operations were replayed at the normal 200K Apex catalog window
with an 8,000-character read/search limit. All six runs completed 12 listings,
12 searches, and 96 reads. Every run returned 793,127 tool-result characters
with the same result SHA-256, recorded 120 completed model steps, produced 1,920 output
tokens, and made no summary call. These are three fresh-process pairs with
the baseline run before the fitted run in each pair.

| Trial | Baseline input | Fitted input | Saved input | Paired decrease |
| ----: | -------------: | -----------: | ----------: | --------------: |
|     1 |     11,181,769 |    8,342,352 |   2,839,417 |         25.393% |
|     2 |     11,184,073 |    8,342,604 |   2,841,469 |         25.406% |
|     3 |     11,181,545 |    8,339,202 |   2,842,343 |         25.420% |

| Baseline input, mean ± SD | Fitted input, mean ± SD | Saved per pair, mean ± SD | Paired decrease, mean ± SD | Baseline / fitted peak step input |
| ------------------------: | ----------------------: | ------------------------: | -------------------------: | --------------------------------: |
|        11,182,462 ± 1,399 |       8,341,386 ± 1,896 |         2,841,076 ± 1,502 |     **25.407% ± 0.013 pp** |                 194,963 / 163,688 |

Step 74 was the first provider call with different input usage in every pair.
The two result sizes show the threshold effect at the normal setting: the
1,500-character run saved 0%, while the 8,000-character run saved 25.407%
on average. The 49.725% decrease at the 96K local window remains a
controlled stress result.

The replay sums provider usage from completed steps. It does not measure
tokens for any rejected provider attempts, so these figures are not billed
input totals. They also do not measure whether an autonomous agent would
choose these exact file operations or complete a real task.

## Reproduce

From clean checkouts at the two runtime commits, put the committed script at
the same relative path in both and run each command three times in a fresh
process. These commands need `ANTHROPIC_API_KEY` and make real provider calls:

```sh
bun --no-env-file scripts/performance/operator-context-workflow-live.ts 15 96000 claude-haiku-4-5
bun --no-env-file scripts/performance/operator-context-workflow-live.ts 30 96000 claude-haiku-4-5
bun --no-env-file scripts/performance/operator-context-workflow-live.ts 60 96000 claude-haiku-4-5
bun --no-env-file scripts/performance/operator-context-workflow-live.ts 120 96000 claude-haiku-4-5
bun --no-env-file scripts/performance/operator-context-workflow-live.ts 120 200000 claude-haiku-4-5 20000000 8000
```

The [1,500-character raw records](operator-context-workflow-pass3.json) and
[8,000-character normal-window records](operator-context-workflow-normal-pass3.json)
retain each step's numeric provider usage, total output and cache-read input,
operation counts, runtime and fixture SHAs, script SHA-256, and elapsed time.
They contain no prompts or file contents. The workload is a forced tool replay,
so completed calls verify that the context change preserves this tool loop;
they do not establish a general operator-task completion rate or billed cost
reduction.
