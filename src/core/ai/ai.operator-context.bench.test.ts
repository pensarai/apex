import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { LanguageModelV3StreamPart } from "@ai-sdk/provider";
import {
  type ModelMessage,
  simulateReadableStream,
  stepCountIs,
  tool,
} from "ai";
import { MockLanguageModelV3 } from "ai/test";
import { expect, it, vi } from "vitest";
import { z } from "zod";
import { estimateMessageTokens } from "./contextManagement";

const state: { model: MockLanguageModelV3 | null } = vi.hoisted(() => ({
  model: null,
}));

vi.mock("./utils", async () => ({
  ...(await vi.importActual<typeof import("./utils")>("./utils")),
  getProviderModel: () => {
    if (!state.model) throw new Error("synthetic model is unavailable");
    return state.model;
  },
}));

const { streamResponse } = await import("./ai");

const MODEL = "custom:fixture:synthetic";
const TOOL_STEPS = 72;
const TOOL_INPUT = "q".repeat(1_400);
const TOOL_OUTPUT = "e".repeat(4_000);
const usage = {
  inputTokens: { total: 10, noCache: 10, cacheRead: 0, cacheWrite: 0 },
  outputTokens: { total: 5, text: 5, reasoning: undefined },
};

it("measures a synthetic long tool loop through the real stream and context paths", async () => {
  const sessionPath = mkdtempSync(join(tmpdir(), "apex-context-bench-"));
  const providerInputTokens: number[] = [];
  let providerCalls = 0;
  let summaryCalls = 0;
  let compactionEvents = 0;
  const probe = tool({
    description: "Return synthetic evidence",
    inputSchema: z.object({ q: z.string() }),
    execute: async () => TOOL_OUTPUT,
  });

  state.model = new MockLanguageModelV3({
    doStream: async (options) => {
      providerInputTokens.push(
        estimateMessageTokens(options.prompt as ModelMessage[]),
      );
      const call = providerCalls++;
      const toolStep = call < TOOL_STEPS;
      const chunks: unknown[] = toolStep
        ? [
            {
              type: "tool-call",
              toolCallId: `probe-${call}`,
              toolName: "probe",
              input: JSON.stringify({ q: TOOL_INPUT }),
            },
          ]
        : [
            { type: "text-start", id: "done" },
            { type: "text-delta", id: "done", delta: "done" },
            { type: "text-end", id: "done" },
          ];
      chunks.push({
        type: "finish",
        finishReason: {
          unified: toolStep ? "tool-calls" : "stop",
          raw: toolStep ? "tool_calls" : "stop",
        },
        usage,
      });
      return {
        stream: simulateReadableStream({
          chunks: chunks as LanguageModelV3StreamPart[],
        }),
      };
    },
    doGenerate: async () => {
      summaryCalls++;
      return {
        content: [
          { type: "text" as const, text: "Synthetic progress: continue." },
        ],
        finishReason: { unified: "stop" as const, raw: "stop" },
        usage,
        warnings: [],
      };
    },
  });

  try {
    const stream = streamResponse({
      model: MODEL,
      prompt: "Run the synthetic probes and finish.",
      system: "Synthetic benchmark; no external target.",
      tools: { probe },
      stopWhen: stepCountIs(1_000),
      sessionPath,
      silent: true,
      authConfig: {
        customProviders: {
          fixture: {
            baseUrl: "https://example.invalid/v1",
            models: [
              {
                id: "synthetic",
                contextLength: 32_000,
                maxOutputTokens: 4_000,
              },
            ],
          },
        },
      },
    });
    const seen: string[] = [];
    for await (const part of stream.fullStream) {
      if (part.type === "text-delta") seen.push(part.text);
      if (
        part.type === "tool-call" &&
        part.toolName === "summarize_conversation"
      ) {
        compactionEvents++;
      }
    }

    expect(providerCalls).toBe(TOOL_STEPS + 1);
    expect(seen.at(-1)).toBe("done");
    expect(summaryCalls).toBeGreaterThan(0);
    expect(compactionEvents).toBe(summaryCalls);
    expect(Math.max(...providerInputTokens)).toBeLessThan(18_000);
    expect(
      providerInputTokens.reduce((total, value) => total + value, 0),
    ).toBeLessThan(1_300_000);
    if (process.env.APEX_CONTEXT_BENCH === "1") {
      console.log(
        "OPERATOR_CONTEXT_BENCH",
        JSON.stringify({
          toolSteps: TOOL_STEPS,
          providerCalls,
          summaryCalls,
          compactionEvents,
          peakEstimatedInputTokens: Math.max(...providerInputTokens),
          cumulativeEstimatedInputTokens: providerInputTokens.reduce(
            (total, value) => total + value,
            0,
          ),
          firstEstimatedInputTokens: providerInputTokens[0],
          lastEstimatedInputTokens: providerInputTokens.at(-1),
        }),
      );
    }
  } finally {
    state.model = null;
    rmSync(sessionPath, { recursive: true, force: true });
  }
});
