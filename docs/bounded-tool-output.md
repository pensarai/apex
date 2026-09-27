# Bounded command and search output

Command output can dominate subsequent model requests, especially when a failed
command returns a large stderr stream in both `error` and `stderr`. Apex now
projects oversized `execute_command` and `grep` results at the AI SDK's
`toModelOutput` boundary. Small results keep their existing JSON representation.

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
source code.

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
