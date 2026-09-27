# SDK request-body retention (streaming steps)

`src/core/ai/ai.ts` sets `experimental_include: { requestBody: false }` on its
`streamText` options. The SDK would otherwise copy every provider request
body into step history; later steps re-send the whole conversation, so
retained bodies accumulate with each step. Wire requests, outputs, usage,
tool execution, callbacks, and native rollout capture are unchanged — native
capture reads the request from the provider stream result, which this SDK
filter never touches.

## Regression gate

`src/core/ai/ai.request-retention.test.ts` runs the production
`streamResponse` path against a mocked HTTP endpoint (no network, no keys)
with a tool loop of five steps and 8 KiB tool results. It asserts:

- zero serialized request-body bytes in step history (SDK result and every
  callback view of each step),
- wire requests still grow with the conversation and carry the tool results,
- tool runs, finish reasons, text, per-step usage, `usageRecorder` calls
  (100/10 per step, `stepSeq` 0–4), `onFinish` aggregate (500/50/550), and
  awaited callback ordering between requests,
- native capture emits one completed envelope per request whose recorded
  input equals each wire body.

The same test against baseline `be2e4b81` fails on the retained-body
assertion.

## Benchmarks

Both report the retained request-body JSON byte sum (deterministic, zero
after the change), heap/RSS deltas (separate measures — they include other
fixture state), wall time, and wire/result hashes for parity:

```sh
bun --no-env-file scripts/performance/request-retention.ts 64
bun --no-env-file scripts/performance/request-retention.ts 128
```

Production path: real `streamResponse` + `@ai-sdk/openai-compatible` custom
provider adapter, mocked fetch, 8 KiB tool results.

```sh
bun --no-env-file scripts/performance/request-retention-openai.ts exclude 64
bun --no-env-file scripts/performance/request-retention-openai.ts include 128
```

SDK/adapter path: real `@ai-sdk/openai` chat adapter with raw `streamText`;
`exclude` mirrors the production option, `include` shows default retention.

Raw before/after logs live outside the repo in the coordinating audit's
evidence directory (see `apex-performance-stack-20260927/evidence/pr-01`).
Local numbers are fixture measurements: they establish the waste and its
removal, not a whole-session speedup.
