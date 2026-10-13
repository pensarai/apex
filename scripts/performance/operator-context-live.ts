#!/usr/bin/env bun

import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { tool } from "ai";
import { z } from "zod";
import { normalizeStepUsage, streamResponse } from "../../src/core/ai/ai";
import { AVAILABLE_MODELS, getMaxOutputTokens } from "../../src/core/ai/models";

const requestedSteps = Number(process.argv[2] ?? 25);
const payloadChars = Number(process.argv[3] ?? 7_000);
const declaredContextWindow = Number(process.argv[4] ?? 96_000);
if (
  !Number.isSafeInteger(requestedSteps) ||
  requestedSteps < 1 ||
  requestedSteps > 60 ||
  !Number.isSafeInteger(payloadChars) ||
  payloadChars < 1 ||
  payloadChars > 8_000 ||
  !Number.isSafeInteger(declaredContextWindow) ||
  declaredContextWindow < 96_000 ||
  declaredContextWindow > 200_000
) {
  throw new Error(
    "Usage: operator-context-live.ts [steps: 1..60] [payload chars: 1..8000] [local window: 96000..200000]",
  );
}
if (!process.env.ANTHROPIC_API_KEY) {
  throw new Error("Set ANTHROPIC_API_KEY before running the live benchmark");
}

const model = "claude-haiku-4-5";
const modelInfo = AVAILABLE_MODELS.find((entry) => entry.id === model);
if (!modelInfo) throw new Error("Benchmark model is missing from the catalog");
// A smaller local window reaches the fit threshold within the token cap; the provider retains its native limit.
modelInfo.contextLength = declaredContextWindow;
const maxInputTokens = 1_000_000;
const sessionPath = mkdtempSync(join(tmpdir(), "apex-context-live-"));
const line = (index: number) =>
  `Record ${index.toString().padStart(4, "0")}: synthetic component=fixture status=observed evidence=stable repeated audit sample.\n`;
let payload = "";
for (let index = 0; payload.length < payloadChars; index++) {
  payload += line(index);
}
payload = payload.slice(0, payloadChars);

let toolCalls = 0;
let totalInputTokens = 0;
let totalOutputTokens = 0;
let cacheReadTokens = 0;
let summaryCalls = 0;
let summaryEvents = 0;
let stopForBudget = false;
const mainStepInputTokens: number[] = [];
const summaryInputTokens: number[] = [];
const started = performance.now();

try {
  const stream = streamResponse({
    model,
    prompt: `Collect ${requestedSteps} synthetic audit records by calling probe once per step.`,
    system:
      "Call probe once per step. This is a synthetic context benchmark with no external target.",
    tools: {
      probe: tool({
        description: "Return the next synthetic audit record",
        inputSchema: z.object({}),
        execute: async () => {
          toolCalls++;
          return `Audit record ${toolCalls}:\n${payload}`;
        },
      }),
    },
    toolChoice: { type: "tool", toolName: "probe" },
    stopWhen: () => toolCalls >= requestedSteps || stopForBudget,
    sessionPath,
    silent: true,
    onStepFinish: (step) => {
      const usage = normalizeStepUsage(step);
      if (usage.inputTokens <= 0) {
        throw new Error(
          "Provider did not report input tokens for a completed call",
        );
      }
      totalInputTokens += usage.inputTokens;
      totalOutputTokens += usage.outputTokens;
      cacheReadTokens += usage.cacheReadTokens;
      if (step.response.id === "summarization") {
        summaryCalls++;
        summaryInputTokens.push(usage.inputTokens);
      } else {
        mainStepInputTokens.push(usage.inputTokens);
      }
      const last = mainStepInputTokens.at(-1) ?? 0;
      const previous = mainStepInputTokens.at(-2) ?? 0;
      const projectedNext = last + Math.max(0, last - previous);
      stopForBudget =
        totalInputTokens + projectedNext > maxInputTokens - 50_000;
    },
  });

  for await (const part of stream.fullStream) {
    if (
      part.type === "tool-call" &&
      part.toolName === "summarize_conversation"
    ) {
      summaryEvents++;
    }
  }

  if (
    toolCalls !== requestedSteps ||
    mainStepInputTokens.length !== requestedSteps
  ) {
    throw new Error(
      `Incomplete workload: ${toolCalls} tool calls and ${mainStepInputTokens.length} model steps`,
    );
  }
  if (summaryCalls !== summaryEvents) {
    throw new Error("Summary usage and compaction event counts differ");
  }
  if (totalInputTokens > maxInputTokens) {
    throw new Error("Live benchmark exceeded the input token budget");
  }

  console.log(
    "OPERATOR_CONTEXT_LIVE",
    JSON.stringify({
      model,
      declaredContextWindow,
      maxOutputTokens: getMaxOutputTokens(model),
      requestedSteps,
      payloadChars,
      toolCalls,
      mainProviderCalls: mainStepInputTokens.length,
      summaryCalls,
      totalInputTokens,
      totalOutputTokens,
      cacheReadTokens,
      peakMainStepInputTokens: Math.max(...mainStepInputTokens),
      firstMainStepInputTokens: mainStepInputTokens[0],
      lastMainStepInputTokens: mainStepInputTokens.at(-1),
      mainStepInputTokens,
      summaryInputTokens,
      elapsedMs: Math.round(performance.now() - started),
    }),
  );
} finally {
  rmSync(sessionPath, { recursive: true, force: true });
}
