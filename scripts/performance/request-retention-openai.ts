#!/usr/bin/env bun

// Measures retained SDK request bodies with the real `@ai-sdk/openai` chat
// adapter and raw `streamText` (no Apex wiring). `exclude` mirrors the
// production option this repo sets on its streaming steps; `include` shows
// the default retention. Wire bodies are hashed for parity between modes.
//
// Usage: bun --no-env-file scripts/performance/request-retention-openai.ts [include|exclude] [steps] [payloadBytes]

import { createHash } from "node:crypto";
import { createOpenAI } from "@ai-sdk/openai";
import { stepCountIs, streamText, tool } from "ai";
import { z } from "zod";

const retain = process.argv[2] !== "exclude";
if (process.argv[2] !== "include" && process.argv[2] !== "exclude") {
  throw new Error("first argument must be include or exclude");
}
const steps = Number(process.argv[3] ?? 64);
const payloadBytes = Number(process.argv[4] ?? 8192);
if (!Number.isSafeInteger(steps) || steps < 1 || steps > 1024) {
  throw new Error("steps must be an integer in 1..1024");
}
if (!Number.isSafeInteger(payloadBytes) || payloadBytes < 1) {
  throw new Error("payloadBytes must be a positive integer");
}

const PAYLOAD = "x".repeat(payloadBytes);
const totalSteps = steps + 1;

function chunk(delta: Record<string, unknown>, finishReason: string | null) {
  return JSON.stringify({
    id: "fixture",
    object: "chat.completion.chunk",
    created: 0,
    model: "gpt-4.1",
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

let calls = 0;
const wireHash = createHash("sha256");
const resultHash = createHash("sha256");
const openai = createOpenAI({
  apiKey: "fixture",
  fetch: (async (_url: unknown, init?: RequestInit) => {
    wireHash.update(String(init?.body));
    return sseResponse(calls++);
  }) as typeof fetch,
});

Bun.gc(true);
const initial = process.memoryUsage();
const started = performance.now();
const run = streamText({
  model: openai.chat("gpt-4.1"),
  prompt: "fixture",
  tools: {
    fixture: tool({
      inputSchema: z.object({ i: z.number() }),
      execute: async ({ i }) => ({ i, output: PAYLOAD }),
    }),
  },
  stopWhen: stepCountIs(totalSteps),
  ...(!retain ? { experimental_include: { requestBody: false } } : {}),
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
  "OPENAI_REQUEST_RETENTION",
  JSON.stringify({
    retain,
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
