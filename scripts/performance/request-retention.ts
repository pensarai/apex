#!/usr/bin/env bun

// Measures retained SDK request bodies in `streamResponse` step history.
// Drives the production streaming path with a synthetic custom provider and
// a mocked fetch (no network, no API keys): `steps` tool round trips plus a
// final text step, each tool result carrying `payloadBytes` bytes.
//
// Reports the JSON byte sum of retained step-history request bodies (a
// deterministic work-count, zero after request-body exclusion), heap and RSS
// deltas (separate measures, include fixture state), wall time, and wire /
// result hashes for output parity across revisions.
//
// Usage: bun --no-env-file scripts/performance/request-retention.ts [steps] [payloadBytes]

import { createHash } from "node:crypto";
import { stepCountIs, tool } from "ai";
import { z } from "zod";
import type { AIAuthConfig } from "../../src/core/ai";
import { streamResponse } from "../../src/core/ai";
import type { CustomProviders } from "../../src/core/config/customProviders";

const steps = Number(process.argv[2] ?? 64);
const payloadBytes = Number(process.argv[3] ?? 8192);
if (!Number.isSafeInteger(steps) || steps < 1 || steps > 1024) {
  throw new Error("steps must be an integer in 1..1024");
}
if (!Number.isSafeInteger(payloadBytes) || payloadBytes < 1) {
  throw new Error("payloadBytes must be a positive integer");
}

const customProviders: CustomProviders = {
  retention: {
    baseUrl: "https://retention.invalid/api",
    apiKeyEnv: "APEX_REQUEST_RETENTION_BENCH_KEY",
    models: [
      { id: "fixture", contextLength: 200_000, maxOutputTokens: 32_000 },
    ],
  },
};
const authConfig: AIAuthConfig = { customProviders };
const MODEL = "custom:retention:fixture";
const PAYLOAD = "x".repeat(payloadBytes);
const totalSteps = steps + 1;

function chunk(delta: Record<string, unknown>, finishReason: string | null) {
  return JSON.stringify({
    id: "fixture",
    object: "chat.completion.chunk",
    created: 0,
    model: "fixture",
    choices: [{ index: 0, delta, finish_reason: finishReason }],
    ...(finishReason
      ? {
          usage: {
            prompt_tokens: 100,
            completion_tokens: 10,
            total_tokens: 110,
          },
        }
      : {}),
  });
}

function sseResponse(index: number): Response {
  const toolStep = index < steps;
  const delta = toolStep
    ? {
        tool_calls: [
          {
            index: 0,
            id: `call-${index}`,
            type: "function",
            function: {
              name: "fixture",
              arguments: JSON.stringify({ i: index }),
            },
          },
        ],
      }
    : { content: "done" };
  const finishReason = toolStep ? "tool_calls" : "stop";
  return new Response(
    `data: ${chunk(delta, null)}\n\ndata: ${chunk({}, finishReason)}\n\ndata: [DONE]\n\n`,
    { headers: { "content-type": "text/event-stream" } },
  );
}

process.env.APEX_REQUEST_RETENTION_BENCH_KEY = "fixture-key";
let calls = 0;
const wireHash = createHash("sha256");
const resultHash = createHash("sha256");
const originalFetch = globalThis.fetch;
globalThis.fetch = (async (_url: unknown, init?: RequestInit) => {
  wireHash.update(String(init?.body));
  return sseResponse(calls++);
}) as typeof fetch;

try {
  Bun.gc(true);
  const initial = process.memoryUsage();
  const started = performance.now();
  const run = streamResponse({
    model: MODEL,
    authConfig,
    prompt: "fixture",
    tools: {
      fixture: tool({
        inputSchema: z.object({ i: z.number() }),
        execute: async ({ i }) => ({ i, output: PAYLOAD }),
      }),
    },
    stopWhen: stepCountIs(totalSteps),
    silent: true,
    onStepFinish: (step) => {
      resultHash.update(
        JSON.stringify({
          content: step.content,
          usage: step.usage,
          toolCalls: step.toolCalls.map((call) => ({
            toolCallId: call.toolCallId,
            toolName: call.toolName,
            input: call.input,
          })),
          toolResults: step.toolResults.map((result) => result.output),
        }),
      );
    },
  });
  for await (const part of run.fullStream) {
    if (part.type === "error") throw part.error;
  }
  const finishedSteps = await run.steps;
  const wallMs = performance.now() - started;
  Bun.gc(true);
  const final = process.memoryUsage();
  const retainedBodyJsonBytes = finishedSteps.reduce(
    (n, step) =>
      n +
      (step.request.body
        ? Buffer.byteLength(JSON.stringify(step.request.body))
        : 0),
    0,
  );
  console.log(
    "REQUEST_RETENTION",
    JSON.stringify({
      steps,
      payloadBytes,
      calls,
      retainedBodyJsonBytes,
      heapDelta: final.heapUsed - initial.heapUsed,
      rssDelta: final.rss - initial.rss,
      wallMs,
      wireHash: wireHash.digest("hex"),
      resultHash: resultHash.digest("hex"),
    }),
  );
} finally {
  globalThis.fetch = originalFetch;
}
