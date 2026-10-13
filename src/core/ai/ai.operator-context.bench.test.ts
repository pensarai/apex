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
import {
  estimateMessageTokens,
  estimateToolsOverheadTokens,
} from "./contextManagement";

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

const { streamResponse, ContextLengthExhaustedError } = await import("./ai");

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

it("fits code-heavy tool history before reported provider usage reaches the context limit", async () => {
  const sessionPath = mkdtempSync(join(tmpdir(), "apex-context-calibration-"));
  const contextLimit = 90_000;
  const requestedToolCalls = 60;
  const toolOutput = "x=foo.bar();\n".repeat(650);
  let providerCalls = 0;
  let toolCalls = 0;
  let rejectedCalls = 0;
  let summaryCalls = 0;
  const observedInputTokens: number[] = [];

  state.model = new MockLanguageModelV3({
    doStream: async (options) => {
      const estimated = estimateMessageTokens(options.prompt as ModelMessage[]);
      const observed = estimated * 2 + 500;
      if (observed > contextLimit) {
        rejectedCalls++;
        throw new Error(
          `prompt is too long: ${observed} tokens > ${contextLimit} maximum`,
        );
      }
      observedInputTokens.push(observed);
      const call = providerCalls++;
      const hasToolCall = call < requestedToolCalls;
      const chunks: unknown[] = hasToolCall
        ? [
            {
              type: "tool-call",
              toolCallId: `probe-${call}`,
              toolName: "probe",
              input: "{}",
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
          unified: hasToolCall ? "tool-calls" : "stop",
          raw: hasToolCall ? "tool_calls" : "stop",
        },
        usage: {
          ...usage,
          inputTokens: {
            total: observed,
            noCache: observed,
            cacheRead: 0,
            cacheWrite: 0,
          },
        },
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
        content: [{ type: "text" as const, text: "Continue inspection." }],
        finishReason: { unified: "stop" as const, raw: "stop" },
        usage,
        warnings: [],
      };
    },
  });

  try {
    const stream = streamResponse({
      model: MODEL,
      prompt: "Inspect the fixed files and finish.",
      tools: {
        probe: tool({
          description: "Read the next source excerpt",
          inputSchema: z.object({}),
          execute: async () => {
            toolCalls++;
            return toolOutput;
          },
        }),
      },
      stopWhen: stepCountIs(100),
      sessionPath,
      silent: true,
      authConfig: {
        customProviders: {
          fixture: {
            baseUrl: "https://example.invalid/v1",
            models: [
              {
                id: "synthetic",
                contextLength: 100_000,
                maxOutputTokens: 10_000,
              },
            ],
          },
        },
      },
    });
    const text: string[] = [];
    for await (const part of stream.fullStream) {
      if (part.type === "text-delta") text.push(part.text);
    }
    expect(toolCalls).toBe(requestedToolCalls);
    expect(providerCalls).toBe(requestedToolCalls + 1);
    expect(rejectedCalls).toBe(0);
    expect(summaryCalls).toBe(0);
    expect(Math.max(...observedInputTokens)).toBeLessThanOrEqual(contextLimit);
    expect(text.at(-1)).toBe("done");
  } finally {
    state.model = null;
    rmSync(sessionPath, { recursive: true, force: true });
  }
});

it("does not count system and tool overhead twice when calibrating", async () => {
  const sessionPath = mkdtempSync(join(tmpdir(), "apex-context-overhead-"));
  const system = "s".repeat(32_000);
  const toolOutput = "e".repeat(140_000);
  const tools = {
    probe: tool({
      description: "d".repeat(32_000),
      inputSchema: z.object({}),
      execute: async () => toolOutput,
    }),
  };
  const preparedInputTokens: number[] = [];
  const reportedInputTokens: number[] = [];
  let providerCalls = 0;
  let summaryCalls = 0;

  state.model = new MockLanguageModelV3({
    doStream: async (options) => {
      const observed =
        estimateMessageTokens(options.prompt as ModelMessage[]) +
        estimateToolsOverheadTokens(tools) +
        1_000;
      reportedInputTokens.push(observed);
      const hasToolCall = providerCalls++ === 0;
      const chunks: unknown[] = hasToolCall
        ? [
            {
              type: "tool-call",
              toolCallId: "probe-0",
              toolName: "probe",
              input: "{}",
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
          unified: hasToolCall ? "tool-calls" : "stop",
          raw: hasToolCall ? "tool_calls" : "stop",
        },
        usage: {
          ...usage,
          inputTokens: {
            total: observed,
            noCache: observed,
            cacheRead: 0,
            cacheWrite: 0,
          },
        },
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
        content: [{ type: "text" as const, text: "Continue." }],
        finishReason: { unified: "stop" as const, raw: "stop" },
        usage,
        warnings: [],
      };
    },
  });

  try {
    const stream = streamResponse({
      model: MODEL,
      prompt: "Inspect the fixed source excerpt.",
      system,
      tools,
      stopWhen: stepCountIs(3),
      sessionPath,
      silent: true,
      onContextPrepared: ({ messages }) => {
        preparedInputTokens.push(estimateMessageTokens(messages));
      },
      authConfig: {
        customProviders: {
          fixture: {
            baseUrl: "https://example.invalid/v1",
            models: [
              {
                id: "synthetic",
                contextLength: 80_000,
                maxOutputTokens: 10_000,
              },
            ],
          },
        },
      },
    });
    for await (const _part of stream.fullStream) {
      void _part;
    }
    expect(providerCalls).toBe(2);
    expect(summaryCalls).toBe(0);
    expect(preparedInputTokens).toHaveLength(2);
    expect(preparedInputTokens[1]).toBeGreaterThan(30_000);
    expect(Math.max(...reportedInputTokens)).toBeLessThan(80_000);
  } finally {
    state.model = null;
    rmSync(sessionPath, { recursive: true, force: true });
  }
});

it("contains a context error from an in-stream summary", async () => {
  let providerCalls = 0;
  state.model = new MockLanguageModelV3({
    doStream: async () => ({
      stream: simulateReadableStream({
        chunks: [
          {
            type: "tool-call",
            toolCallId: `probe-${providerCalls++}`,
            toolName: "probe",
            input: JSON.stringify({ q: TOOL_INPUT }),
          },
          {
            type: "finish",
            finishReason: { unified: "tool-calls", raw: "tool_calls" },
            usage,
          },
        ] as LanguageModelV3StreamPart[],
      }),
    }),
    doGenerate: async () => {
      throw new Error("prompt is too long: 999999 tokens > 20000 maximum");
    },
  });

  try {
    const stream = streamResponse({
      model: MODEL,
      prompt: "Run synthetic probes.",
      tools: {
        probe: tool({
          description: "Return synthetic evidence",
          inputSchema: z.object({ q: z.string() }),
          execute: async () => TOOL_OUTPUT,
        }),
      },
      stopWhen: stepCountIs(100),
      silent: true,
      _restartDepth: 3,
      authConfig: {
        customProviders: {
          fixture: {
            baseUrl: "https://example.invalid/v1",
            models: [
              {
                id: "synthetic",
                contextLength: 20_000,
                maxOutputTokens: 2_000,
              },
            ],
          },
        },
      },
    });
    let caught: unknown;
    try {
      for await (const part of stream.fullStream) void part;
    } catch (error) {
      caught = error;
    }
    expect(providerCalls).toBeGreaterThan(1);
    expect(caught).toBeInstanceOf(ContextLengthExhaustedError);
  } finally {
    state.model = null;
  }
});

it("measures the fitted history handed to legacy transcript persistence", async () => {
  const sessionPath = mkdtempSync(join(tmpdir(), "apex-history-bench-"));
  const priorMessages: ModelMessage[] = [
    { role: "user", content: "Continue the synthetic task." },
    ...Array.from({ length: 40 }, (_, index): ModelMessage[] => [
      {
        role: "assistant",
        content: [
          {
            type: "tool-call",
            toolCallId: `prior-${index}`,
            toolName: "probe",
            input: { q: "q".repeat(100) },
          },
        ],
      },
      {
        role: "tool",
        content: [
          {
            type: "tool-result",
            toolCallId: `prior-${index}`,
            toolName: "probe",
            output: { type: "text", value: "e".repeat(4_000) },
          },
        ],
      },
    ]).flat(),
  ];
  let prepared:
    | { messages: ModelMessage[]; responseMessageOffset: number }
    | undefined;
  let responseMessages: ModelMessage[] = [];
  state.model = new MockLanguageModelV3({
    doStream: async () => ({
      stream: simulateReadableStream({
        chunks: [
          { type: "text-start", id: "done" },
          { type: "text-delta", id: "done", delta: "done" },
          { type: "text-end", id: "done" },
          {
            type: "finish",
            finishReason: { unified: "stop", raw: "stop" },
            usage,
          },
        ] as LanguageModelV3StreamPart[],
      }),
    }),
  });

  try {
    const stream = streamResponse({
      model: MODEL,
      prompt: "Continue the synthetic task.",
      messages: priorMessages,
      sessionPath,
      silent: true,
      onContextPrepared: (context) => {
        prepared = context;
      },
      onStepFinish: (step) => {
        responseMessages = step.response.messages;
      },
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
    for await (const _part of stream.fullStream) {
      void _part;
    }

    expect(prepared).toBeDefined();
    const previousTranscript = [...priorMessages, ...responseMessages];
    const fittedTranscript = [
      ...(prepared?.messages ?? []),
      ...responseMessages.slice(prepared?.responseMessageOffset ?? 0),
    ];
    const previousEstimate = estimateMessageTokens(previousTranscript);
    const fittedEstimate = estimateMessageTokens(fittedTranscript);
    expect(fittedEstimate).toBeLessThan(previousEstimate / 2);
    expect(JSON.stringify(fittedTranscript)).toContain("full output saved to");
    expect(responseMessages).toHaveLength(1);
    if (process.env.APEX_CONTEXT_BENCH === "1") {
      console.log(
        "OPERATOR_HISTORY_BENCH",
        JSON.stringify({
          previousTranscriptEstimatedTokens: previousEstimate,
          fittedTranscriptEstimatedTokens: fittedEstimate,
          previousTranscriptMessages: previousTranscript.length,
          fittedTranscriptMessages: fittedTranscript.length,
        }),
      );
    }
  } finally {
    state.model = null;
    rmSync(sessionPath, { recursive: true, force: true });
  }
});
