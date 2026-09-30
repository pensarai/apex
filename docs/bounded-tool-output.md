# Bounded command and search output

Command output can dominate subsequent model requests, especially when a failed
remote command returns a large stderr stream in both `error` and `stderr`. Apex now
projects oversized `execute_command` and `grep` results at the AI SDK's
`toModelOutput` boundary. Small results remain complete structured JSON; command
results also expose the executor's exit code and capture-completeness flags.

The preview is limited to 2,000 lines and 50 KiB of UTF-8 text, including its
status and omission notice. It preserves both ends without cutting a UTF-8
codepoint. The complete **captured** result is saved separately; executor capture
limits still apply, and incomplete captures remain explicitly marked. Tool
callbacks retain the original result, while the model transcript receives the
bounded projection. No model call, semantic summary, or duplicate-line removal
is involved.

The saved result receives an opaque `tool-output:` reference. `read_file` can
retrieve line or byte windows, and `grep` can search it. References resolve only
inside the current agent's output directory, including when command execution
uses a remote sandbox. Ordinary file paths continue through the existing
workspace and runtime checks. These references grant read access, not file
mutation access. They do not turn the helper workspace into access to target
source code. Artifact search uses the host's existing `grep` executable;
`read_file` provides a bounded fallback when it is unavailable.

Artifacts live with the existing session/agent logs and follow that lifecycle;
this change adds no independent TTL. Storage failure still returns a bounded
preview, but explicitly says the omitted evidence is unavailable. Consumers must
not treat an unavailable or producer-truncated capture as complete evidence.

## Upstream alignment

The byte/line defaults, head/tail projection, UTF-8 boundary handling, and notice
budget follow [OpenCode's ToolOutputStore at
285cff53](https://github.com/anomalyco/opencode/blob/285cff53da18b1fc234fa709236ef1e6573b7f22/packages/core/src/tool-output-store.ts).
The OpenCode snapshot was inspected on September 27, 2026. Apex uses its existing
session lifecycle and an owned reference instead of exposing a host path to a
remote worker. The reference appears first so Apex's existing cascading
tool-result truncation retains a usable recovery handle.

Codex documents the same general spill-and-preview pattern for [large hook
output](https://learn.chatgpt.com/docs/hooks#large-hook-output), with a different,
token-based default. That documentation describes hooks, not a universal shell
tool limit. These implementations support the design pattern; they do not prove
that a single threshold is optimal for every workload. This PR adopts the pinned
OpenCode defaults rather than claiming the two products have identical policies.

## Expected tradeoff and capability boundary

An oversized result contributes fewer bytes on the next request and subsequent
requests that retain it. This can reduce input tokens and postpone context
pressure. A model that needs omitted evidence must make a targeted retrieval,
which adds a tool call and can add another inference step. Actual end-to-end
latency and billed cost must therefore be measured, not inferred from preview
size alone. Results around 6.5–8.4 KB remain inline under these defaults.

The existing pressure-driven compaction and summarization policies are unchanged.
The reference survives all four cascading tool-result truncation thresholds;
later historical-step snipping and summarization remain separate information-loss
boundaries. The stable-transcript regression verifies that ordinary subsequent
SDK steps do not regenerate or rewrite an earlier preview.

Synthetic evidence-retrieval trials exercise the intended recovery path, but do
not establish overall pentest success or a universal absence of capability
regression. A broader pentest evaluation remains necessary before making that
claim.

## Reproducing the measurements

Use macOS or Linux with Bun and dependencies installed in both checkouts:

```sh
bun scripts/bench-tool-output.ts \
  --baseline /path/to/baseline --candidate /path/to/candidate \
  --output /tmp/tool-output-offline.json --reps 50

# Makes paid API calls using OPENROUTER_API_KEY from the environment.
bun scripts/bench-tool-output.ts \
  --baseline /path/to/baseline --candidate /path/to/candidate \
  --output /tmp/tool-output-live.json --reps 50 --live --repetitions 3
```

The offline pass executes real harmless fixture processes through each
checkout's `execute_command` and `PerCommandShell`. It measures the SDK output
projection separately from process execution, including artifact writes, and
checks recovery through the real read/search tools. Fifty projection samples
include the first call; there is no separate warmup. Byte counts describe the
model-visible value, before transport framing: serialized JSON for the baseline
and UTF-8 text for oversized candidate results. They are not token counts.

The live pass uses GLM-5.3 through OpenRouter, pinned to Z.AI with fallbacks
disabled, matching Apex's routing for this model. Each pair shares the fixture,
system/task prompts, model, and limits; the variant's tool descriptions and
behavior are retained. The model receives one replay of the real command capture
and can inspect it with `read_file` or `grep`. Arbitrary commands and repeat
replays are rejected. This isolates evidence retrieval, not the complete Apex
agent loop or a pentest. Fixtures include a small control and two oversized
outputs with a seeded token deliberately outside the candidate's preview.

Three repetitions alternate which variant runs first. Every run has an eight-step,
4,096-output-token-per-step, 180-second limit with SDK retries disabled. The
report includes all runs, failed/correct counts, total usage across **all**
inference steps, cached/reasoning tokens, latency, retrieval calls, generation
IDs, and provider-reported billed cost. Missing cost is unknown, not zero.
Per-run JSONL checkpoints survive interruption. Reports contain no prompts or
raw output and stay outside the source tree.

## Recorded comparison

Measured September 27, 2026 (EDT; report completed September 28 at 00:50 UTC), on
macOS arm64 / Bun 1.3.14. Both checkouts were clean: baseline
`2cd0b86c8fb676ac6343b37389400dcbddb77cd8`, candidate
`61851f6dfd1ba5cca473be5a1f159e782066c36a`.

| Fixture                  | Model-visible bytes, before → after | Reduction | Projection median / p95 ms, before → after |
| ------------------------ | ----------------------------------: | --------: | -----------------------------------------: |
| Small control            |                           189 → 250 | +61 bytes |          0.0002 / 0.0004 → 0.0095 / 0.0267 |
| ~120 KB stderr           |                    125,551 → 51,200 |     59.2% |              0.247 / 0.276 → 0.479 / 0.593 |
| 6,000 short stdout lines |                     54,203 → 16,207 |     70.1% |              0.097 / 0.111 → 0.327 / 0.487 |

Both oversized candidate artifacts recovered the omitted token through `grep`
and, independently, through two `read_file` pages. The original stack's 17 coding
contracts still pass, including the actual helper create/run/repair loop.

Live medians below use three runs per cell. **Both variants recovered the token
and correct exit status in 9/9 runs each.** All 18 runs completed successfully.

| Fixture                  | Total input tokens, before → after | Billed USD/run, before → after | End-to-end seconds, before → after | Retrieval calls, before → after |
| ------------------------ | ---------------------------------: | -----------------------------: | ---------------------------------: | ------------------------------: |
| Small control            |                      8,995 → 5,753 |          $0.006191 → $0.002602 |                       25.09 → 9.32 |                           1 → 0 |
| ~120 KB stderr           |                    24,265 → 44,950 |          $0.029198 → $0.025907 |                      11.88 → 26.79 |                           0 → 3 |
| 6,000 short stdout lines |                    37,544 → 45,168 |          $0.048348 → $0.030179 |                      11.59 → 26.55 |                           0 → 2 |

The oversized cases reduced initial output size and measured median billed cost
by **11.3% and 37.6%**, but total input tokens **increased 85.2% and 20.3%**, and
elapsed time increased about **2.3×**. Retrieval adds steps and replays context;
prompt-cache hits affect billed cost. These data do **not** demonstrate an
end-to-end speedup or fewer total tokens for evidence buried in the middle.
Small-control improvements cannot be attributed to truncation: the output stays
inline, and explicit exit metadata and stochastic model behavior also differ.

Three repetitions, one provider, selected synthetic fixtures, and shared provider
caches are insufficient for a general capability, cost, or latency guarantee.
The concrete improvement is bounded model context with recoverable evidence;
these trials demonstrate the recovery path and its measured tradeoff. A
representative pentest evaluation belongs in the separate evaluation service.

The sanitized raw report's SHA-256 is
`957c6135a1f15360ca6e273c30b1b3e2b98cc08127abb9be690999cb9d95fbad`.
OpenRouter reported $0.438330 across the 18 trials. Local validation passed 3,326
tests with 45 skipped, plus typecheck, lint, format, dead-code, and build checks.
Lint reports the same 183 warnings and 10 infos as the parent checkout, including
existing non-null assertions in the email adapters and CLI.

## Measuring longer conversations

The single-capture comparison above charges the retrieval overhead but stops
before measuring the cost of retaining that result through later tasks. The
companion scaling benchmark measures both in one continuous SDK conversation:

```sh
bun scripts/bench-tool-output-scaling.ts \
  --baseline /path/to/baseline --candidate /path/to/candidate \
  --output /tmp/tool-output-scaling.json --stages 32 --repetitions 3 \
  --budget-usd 20 --live
```

Omit `--live` for the offline capture, omission, and recovery checks. The output
path must be new, preventing checkpoints from different experiments from being
combined accidentally. The paid mode verifies the current Z.AI endpoint prices
before starting, reserves a conservative cost allowance before each request,
and stops new requests if billing becomes unknown or the budget is insufficient.
For a separately recorded replacement of an administratively interrupted pair,
use `--profile frequent --start-repetition 3 --repetitions 1` and a new output
path. Keep the interrupted report and its charges; do not replace an unfavorable
completed result with a retry.

Two workloads alternate large stderr and many-line stdout captures, with small
results between them: one oversized result every eight tasks, or every four
tasks. All oversized results deliberately bury the required evidence outside
the preview. Each baseline/candidate pair uses identical fixture bytes and task
instructions. There are three paired repetitions per workload, with both
variants running concurrently and the pair launch order alternating. Each task
executes a real harmless local process through Apex's command tool; omitted
evidence is retrieved through its real file/search tools. No delays are added
to make inference overhead appear smaller.

The same conversation persists for all 32 tasks. Each task requests its own
evidence and exit status, plus the first task's evidence, to check retention.
Both variants have a twelve-call, 2,048-output-token-per-call, 240-second limit
per task, without SDK retries. Incorrect or unfinished answers remain in the
results; later tasks continue unless the request itself fails. Exploratory
pilots used an eight-call limit. One diagnosed bounded-output pilot found the
evidence but exhausted that limit while verifying it, before returning a final
answer; the main protocol increases the limit for both variants. Pilot results
are separate from the main comparison.

Per-request checkpoints record generation ID, provider, cached/uncached input,
output, actual billed cost, and timing. Per-task checkpoints record cumulative
cost, input, time, retrieval count, correctness, and first-task recall. A unique
nonce at the start of each run's system message reduces cross-run prefix reuse;
automatic caching within each run remains enabled. The report checks actual
bills against the recorded rates. `modeledNoCacheCost` prices the observed token
counts without cache discounts: it is a pricing counterfactual, not a separately
executed cold-cache latency test.

This is a controlled retained-context workload using Apex tools and the AI SDK,
not a complete Apex pentest. It does not invoke Apex's pressure compaction,
summarizer, remote sandbox, or vulnerability verifier. Fixture density, repetitive
filler, and recovery difficulty are selected experimental conditions, not a
measured distribution of production pentests. Checkpoints at 1, 4, 8, 16, and 32
tasks show observed scaling without extrapolating to longer runs. Tasks within
a trajectory are correlated; the independent repetition count is three per
workload and variant. The model knows the evidence marker's prefix; recovering
that marker is different from discovering an unknown vulnerability indicator.

## Recorded scaling comparison

Measured September 27 EDT / September 28 UTC, 2026, using GLM-5.3 through
OpenRouter's Z.AI endpoint. Both runtime checkouts were clean: baseline
`2cd0b86c8fb676ac6343b37389400dcbddb77cd8` and candidate
`07d448cbb09b85b47629b0e1ac067ea1f78a8887`. The candidate's tool behavior is
unchanged from the published `fd4d377c` implementation; the newer commit adds
the scaling runner. A later runner-only fix improves checkpoint cleanup,
sanitization, budget stopping, and selection of a replacement pair. It changes
neither the tools under test nor the model/task protocol.

The balanced comparison contains **12 trajectories, 384 scored tasks, and 847
inference calls**: three paired repetitions per workload. All rows below are
medians across those repetitions, including the trajectory with an unfinished
answer. Percentage differences compare the displayed medians; the columns do
not describe one selected run.

| Oversized output frequency | Tasks | Billed USD, baseline → bounded | Cost change | Seconds, baseline → bounded | Total input tokens, baseline → bounded |
| -------------------------- | ----: | -----------------------------: | ----------: | --------------------------: | -------------------------------------: |
| Every 8 tasks              |     1 |              $0.0302 → $0.0562 |      +86.4% |                  9.2 → 62.6 |                       26,863 → 101,131 |
| Every 8 tasks              |     4 |              $0.0880 → $0.0877 |       −0.4% |                 30.5 → 90.3 |                      157,355 → 172,993 |
| Every 8 tasks              |     8 |              $0.1374 → $0.1170 |      −14.8% |                52.2 → 115.4 |                      335,950 → 274,100 |
| Every 8 tasks              |    16 |              $0.4019 → $0.2421 |      −39.8% |                98.1 → 180.4 |                    1,188,721 → 681,341 |
| Every 8 tasks              |    32 |              $1.2255 → $0.6212 |  **−49.3%** |               200.8 → 292.2 |                  4,084,232 → 2,008,863 |
| Every 4 tasks              |     1 |              $0.0303 → $0.0242 |      −20.1% |                 15.8 → 17.4 |                        26,845 → 37,612 |
| Every 4 tasks              |     4 |              $0.0883 → $0.0573 |      −35.0% |                 30.3 → 37.3 |                      157,438 → 111,754 |
| Every 4 tasks              |     8 |              $0.2351 → $0.1276 |      −45.7% |                 62.3 → 78.8 |                      560,601 → 315,853 |
| Every 4 tasks              |    16 |              $0.6644 → $0.3292 |      −50.4% |               132.0 → 147.8 |                    1,953,570 → 978,771 |
| Every 4 tasks              |    32 |              $2.1763 → $1.0093 |  **−53.6%** |               257.9 → 265.3 |                  7,245,543 → 3,372,937 |

At 32 tasks, median input fell **50.8% and 53.4%**. Median elapsed time increased
**45.5% (91.4 seconds)** and **2.9% (7.4 seconds)**, respectively. Every completed
pair cost less with bounded output, with savings from **25.9% to 55.8%**.
Individual paired time differences ranged from **12.8 seconds faster to 119.9
seconds slower**. The first task after which cumulative billed cost remained
lower through task 32 ranged from task **1 to 15** across pairs. There is no
single proven crossover point for pentests.

| Frequency     | Variant  | 32-task cost range | Elapsed seconds range | Fully correct trajectories | Correct evidence/exit and recall checks | Cost per fully correct trajectory |
| ------------- | -------- | -----------------: | --------------------: | -------------------------: | --------------------------------------: | --------------------------------: |
| Every 8 tasks | Baseline |    $1.2218–$1.2356 |           180.9–236.5 |                        3/3 |                                   96/96 |                           $1.2276 |
| Every 8 tasks | Bounded  |    $0.5982–$0.8471 |           209.8–299.2 |                        2/3 |                                   95/96 |                           $1.0333 |
| Every 4 tasks | Baseline |    $2.1656–$2.1933 |           196.4–285.5 |                        3/3 |                                   96/96 |                           $2.1784 |
| Every 4 tasks | Bounded  |    $0.9625–$1.6246 |           183.6–405.4 |                        3/3 |                                   96/96 |                           $1.1988 |

Cost per fully correct trajectory divides **all** selected spending, including
the unsuccessful trajectory, by the number with all 32 checks correct. It is
not cost per successful pentest. The bounded variant returned correct evidence,
exit status, and recall in **191/192 tasks**, versus **192/192** for baseline.
Its one unfinished answer was task 1 of occasional repetition 2: it reported
finding the token, made nine retrieval calls and three command attempts, and
reached the twelve-call ceiling before returning the required final answer.
The following 31 tasks passed. That result stays in both cost and accuracy
statistics; these data do not establish capability parity.

Caching is material to the bill but does not explain away the longer-run token
reduction. Cached input represented 96.9% versus 97.1% of aggregate input in
the occasional workload, and 96.7% versus 97.3% in the frequent workload.
Every recorded bill reconciled to the verified rates of $1.40/M uncached input,
$0.26/M cached input, and $4.40/M output. Pricing the observed trajectories with
zero cache discounts gives median modeled costs of **$5.7356 → $2.8451** and
**$10.1631 → $4.7474**. These are counterfactual prices, not measured cold-cache
runs. Prices were checked against the [OpenRouter Z.AI endpoint
catalog](https://openrouter.ai/api/v1/models/z-ai/glm-5.3/endpoints).

The result supports a cost/context benefit in these longer retrieval workloads:
smaller retained results reduce the recurring input paid on subsequent calls.
It does not establish a general speedup, an optimal threshold, or unchanged
pentest effectiveness. Three repetitions and variable retrieval strategies are
too little evidence to call the latency penalty negligible.

### Accounting and provenance

The initial batch's $15 reservation ceiling interrupted both members of frequent
repetition 3, after 21 baseline tasks and 16 bounded tasks. Those attempts and
all their charges remain in the raw evidence. With the collection ceiling raised
to $20, the entire pair was repeated with identical runtime commits, fixture
seed, inference settings, and concurrency. The interrupted pair is excluded
from the balanced 32-task statistics for that administrative reason; no
unfavorable completed trajectory was discarded. All recorded HTTP responses
were successful, and all request billing was present.

| Component                                      |       Actual reported USD |
| ---------------------------------------------- | ------------------------: |
| Twelve complete trajectories in the comparison |              $15.88092092 |
| Administratively interrupted pair              |               $1.43743336 |
| Exploratory eight-call pilots                  |               $0.38869276 |
| **Total collection spend / approved ceiling**  | **$17.70704704 / $20.00** |

The original and replacement reports, their per-request JSONL ledgers, and the
exploratory pilots are retained separately. Generated raw artifacts stay outside
the repository. Digests identify the exact reports:

| Report                  | SHA-256                                                            |
| ----------------------- | ------------------------------------------------------------------ |
| Main batch              | `c42372959737e92f8568e59dcdbd2ed0c59b91ef3751bf947f380ffcc3edda48` |
| Replacement pair        | `a6b06a6276c03183acf6f96b0e119276e456c96ca28bb8e5e12bb5ebea396159` |
| First exploratory pilot | `b570814ba8d7eb0252cfd5bf347e679d8c86c62a594726c0a57f12495d2d8ce7` |
| Diagnostic pilot        | `0f12a02a9615b6071cfa9aafeb752bda8627aa6a58fcb8fd030e1f7e996ad943` |

The runner's regression tests use a mocked transport to verify bare-prefix
sanitization, safe sibling completion after a checkpoint failure, scoped pair
selection, and stopping before paid requests when the budget is insufficient.
The full suite passes **3,329 tests, with 45 skipped**; typecheck, lint, and format
checks pass with the same pre-existing lint diagnostics as the parent.
