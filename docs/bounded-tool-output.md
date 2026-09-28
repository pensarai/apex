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
