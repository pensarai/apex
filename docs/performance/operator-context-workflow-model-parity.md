# Matched Haiku 4.5 and Opus 4.8 context replay

This is the model-to-model comparison for the in-stream context fitting change
in PR #1206. It repeats the same fixed repository-inspection workflow with
both models. The earlier Haiku-only measurements remain in
[operator-context-workflow.md](operator-context-workflow.md); the figures below
come from a fresh replay using the same script revision for both models.

## Method

Each ten-step block performs one directory listing, one bounded source search,
and eight bounded source reads from 12 public Apex files at fixture commit
6bd9a0ebe859eb724b3f7261a9ba3ffc685174a7. Both models receive the same
prompt and are forced to call the next tool once per step. The repository
snapshot and ordered tool-result SHA-256 values match across both models and
both variants for each case. All 64 matched runs completed the requested
provider steps, with no summary calls. Each trial is a fresh process, and its
baseline run precedes its fitted run.

The baseline runtime is 79788062d2ea93e1fa3e9c5ab27f43bcc97b3b36 and
the fitted runtime is 0683c2bab9d271c3950169d05f6b8d5b7da76e56.
The matched runs used script SHA-256
bdf322be80b8bfa1fdc2eb906b186b2c03116579a64c7470e579b1f01fd73f9c.
The later script change only extends the allowed local window to 1M for the
Opus catalog-window control; the 96K and 200K workload logic is unchanged.
The raw records contain provider usage for every completed step, runtime and
script hashes, operation counts, and file-result hashes. They contain no file
contents, target data, or credentials.

| Model     | Apex catalog window | Output reservation at 96K local window | Output reservation at 200K local window |
| --------- | ------------------: | -------------------------------------: | --------------------------------------: |
| Haiku 4.5 |                200K |                                    64K |                                     64K |
| Opus 4.8  |                  1M |                                    48K |                                    128K |

The local-window override changes Apex's fitting budget, not the provider's
native context limit. The 96K cases are below both models' native windows.
The 200K case is Haiku's catalog window but a smaller-than-catalog Opus
window. Input caps are stop guards, not context windows: 60-step Opus required
more than 1M cumulative input tokens, so its cap was raised to 2M; 120-step
caps were high enough for every run to finish. No run stopped at its cap.

## Shared 96K local window, 1,500-character read/search limit

All values are provider-reported input tokens, including cache-read input.
The ± values are mean ± sample standard deviation across three pairs.
Percentage ± values are in percentage points (pp), not confidence intervals.
The first changed step compares provider input usage within each pair.

| Steps | Model     | Baseline input, mean ± SD | Fitted input, mean ± SD | Saved per pair, mean ± SD | Paired decrease, mean ± SD | First changed step |
| ----: | --------- | ------------------------: | ----------------------: | ------------------------: | -------------------------: | -----------------: |
|    15 | Haiku 4.5 |                61,427 ± 0 |              61,427 ± 0 |                     0 ± 0 |          0.000% ± 0.000 pp |                  — |
|    15 | Opus 4.8  |                72,148 ± 0 |              72,148 ± 0 |                     0 ± 0 |          0.000% ± 0.000 pp |                  — |
|    30 | Haiku 4.5 |               241,687 ± 0 |             241,687 ± 0 |                     0 ± 0 |          0.000% ± 0.000 pp |                  — |
|    30 | Opus 4.8  |               293,752 ± 0 |             293,752 ± 0 |                     0 ± 0 |          0.000% ± 0.000 pp |                  — |
|    60 | Haiku 4.5 |               941,976 ± 0 |            921,716 ± 34 |               20,260 ± 34 |          2.151% ± 0.004 pp |                 60 |
|    60 | Opus 4.8  |             1,161,850 ± 0 |           1,161,850 ± 0 |                     0 ± 0 |          0.000% ± 0.000 pp |                  — |
|   120 | Haiku 4.5 |             3,675,731 ± 0 |         1,847,948 ± 574 |           1,827,783 ± 574 |         49.726% ± 0.016 pp |                 60 |
|   120 | Opus 4.8  |             4,570,022 ± 0 |       3,816,455 ± 1,519 |           753,567 ± 1,519 |         16.489% ± 0.033 pp |                106 |

At 120 steps, the observed paired-reduction gap is 33.236 pp in Haiku's
favor under this shared local window. The different output reservations and
model token accounting affect when Apex starts fitting, so this is a
description of these model configurations, not an isolated model-quality
effect. In all three 120-step pairs, both baselines' per-step input usage
increased monotonically and stayed below each provider's native window.

## Shared 200K local window, 120 steps

The smaller-result control uses a 1,500-character read/search limit and one
pair per model. The threshold-crossing case uses an 8,000-character limit and
three pairs per model. Both cases run the same 120 file operations.

| Read/search limit | Model     | Pairs | Baseline input, mean ± SD | Fitted input, mean ± SD | Saved per pair, mean ± SD | Paired decrease, mean ± SD | First changed step |
| ----------------: | --------- | ----: | ------------------------: | ----------------------: | ------------------------: | -------------------------: | -----------------: |
|             1,500 | Haiku 4.5 |     1 |                 3,675,731 |               3,675,731 |                         0 |                     0.000% |                  — |
|             1,500 | Opus 4.8  |     1 |                 4,570,022 |               4,570,022 |                         0 |                     0.000% |                  — |
|             8,000 | Haiku 4.5 |     3 |        11,182,537 ± 1,216 |       8,341,871 ± 1,612 |         2,840,666 ± 2,606 |         25.403% ± 0.021 pp |                 74 |
|             8,000 | Opus 4.8  |     3 |            21,044,504 ± 0 |       5,657,955 ± 2,714 |        15,386,549 ± 2,714 |         73.114% ± 0.013 pp |                 36 |

| Trial | Haiku baseline | Haiku fitted | Haiku decrease | Opus baseline | Opus fitted | Opus decrease |
| ----: | -------------: | -----------: | -------------: | ------------: | ----------: | ------------: |
|     1 |     11,181,321 |    8,342,314 |        25.391% |    21,044,504 |   5,656,662 |       73.120% |
|     2 |     11,183,753 |    8,340,083 |        25.427% |    21,044,504 |   5,656,129 |       73.123% |
|     3 |     11,182,537 |    8,343,215 |        25.391% |    21,044,504 |   5,661,074 |       73.100% |

The 200K percentages should not be read as a controlled model-only gap.
Haiku's native window is 200K; Opus's native window is 1M. In each Haiku
8,000-character baseline, completed-step input peaks at 194,963 tokens and
drops sharply at step 89. The records do not attribute that transition or
count any rejected provider attempt. The Opus baselines rise through step
120 without such a drop. Model-specific output reservations also differ at
200K. These effects can change the baseline denominator and fitting threshold.

## Opus 1M catalog-window control

One extra Opus pair repeats the same 120 operations and 8,000-character
read/search limit at Opus's actual 1M Apex catalog window. It uses the
script revision that extends the local-window validation bound.

| Model    | Local window | Baseline input | Fitted input | Decrease | Peak step input | Completed steps |
| -------- | -----------: | -------------: | -----------: | -------: | --------------: | --------------: |
| Opus 4.8 |           1M |     21,044,504 |   21,044,504 |   0.000% |         337,458 |       120 / 120 |

Both variants had identical per-step provider usage, the same ordered tool
results as the shared 200K large-result case, and no summary calls. This
workload did not reach the fitting threshold at Opus's default window.

A later [native-window stress replay](operator-context-workflow-opus-native-stress.md)
uses larger file results and reaches 990,634 input tokens on a single Opus
call. Its pass@3 result shows no material reduction from the current fitted
runtime at the 1M setting.

## Limits and reproduction

The script forces a fixed tool loop; it does not measure autonomous task
selection or task-success probability. Zero observed spread reflects this
fixture and does not characterize real operator sessions. Provider-reported
completed-step input includes cache reads, but rejected attempts are not
included, so the totals are not billed-token or dollar-cost measurements.
The paired percentages compare each model with itself under a fixed case.

The [64 matched raw records](operator-context-workflow-model-parity.json)
and [two native-window control records](operator-context-workflow-opus-native-control.json)
contain per-step counts and checksums. Run the benchmark once per fresh
process and repeat three times per variant for each main case. Copy the same
script into a clean baseline checkout at 79788062 before running there.
These commands require ANTHROPIC_API_KEY and make real provider calls:

    bun --no-env-file scripts/performance/operator-context-workflow-live.ts 60 96000 claude-opus-4-8 2000000 1500
    bun --no-env-file scripts/performance/operator-context-workflow-live.ts 120 96000 claude-opus-4-8 10000000 1500
    bun --no-env-file scripts/performance/operator-context-workflow-live.ts 120 200000 claude-opus-4-8 30000000 8000
    bun --no-env-file scripts/performance/operator-context-workflow-live.ts 120 1000000 claude-opus-4-8 30000000 8000

Substitute claude-haiku-4-5 with caps of 1M, 5M, and 20M for the matching
60-step, 120-step stress, and 120-step large-result cases. The 15- and
30-step runs use the same 96K window, 1,500-character limit, and 1M cap.
