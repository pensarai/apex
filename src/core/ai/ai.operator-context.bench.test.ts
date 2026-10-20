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
  fitMessagesToContext,
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
const { createSummarizationStream } = await import("./utils");

const MODEL = "custom:fixture:synthetic";
const TOOL_STEPS = 72;
const TOOL_INPUT = "q".repeat(1_400);
const TOOL_OUTPUT = "e".repeat(4_000);
const usage = {
  inputTokens: { total: 10, noCache: 10, cacheRead: 0, cacheWrite: 0 },
  outputTokens: { total: 5, text: 5, reasoning: undefined },
};

// Compaction streams now, so the summarizer answers on doStream alongside the
// resumed agent turn; its request carries the compaction instruction.
function isSummaryCall(options: { prompt: unknown }): boolean {
  return JSON.stringify(options.prompt).includes("Compact this conversation");
}

function summaryStream(text: string) {
  return {
    stream: simulateReadableStream({
      chunks: [
        ...(text
          ? [
              { type: "text-start", id: "s" },
              { type: "text-delta", id: "s", delta: text },
              { type: "text-end", id: "s" },
            ]
          : []),
        {
          type: "finish",
          finishReason: { unified: "stop", raw: "stop" },
          usage,
        },
      ] as LanguageModelV3StreamPart[],
    }),
  };
}

it("measures a synthetic long tool loop through the real stream and context paths", async () => {
  const sessionPath = mkdtempSync(join(tmpdir(), "apex-context-bench-"));
  const providerInputTokens: number[] = [];
  let providerCalls = 0;
  let summaryCalls = 0;
  let compactionEvents = 0;
  const summaryPrompts: string[] = [];
  const probe = tool({
    description: "Return synthetic evidence",
    inputSchema: z.object({ q: z.string() }),
    execute: async () => TOOL_OUTPUT,
  });

  state.model = new MockLanguageModelV3({
    doStream: async (options) => {
      if (isSummaryCall(options)) {
        summaryCalls++;
        summaryPrompts.push(JSON.stringify(options.prompt));
        return summaryStream("Synthetic progress: continue.");
      }
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
    expect(summaryPrompts[0]).toContain("probe-0");
    expect(summaryPrompts[0]).toContain(
      "Synthetic benchmark; no external target.",
    );
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

it.each([
  "auto",
  "required",
] as const)("preserves early tool evidence with %s tool choice", async (toolChoice) => {
  const priorMessages: ModelMessage[] = [
    { role: "user", content: "Inspect the fixed sources." },
    ...Array.from({ length: 32 }, (_, index): ModelMessage[] => [
      {
        role: "assistant",
        content: [
          {
            type: "tool-call",
            toolCallId: `read-${index}`,
            toolName: "probe",
            input: {},
          },
        ],
      },
      {
        role: "tool",
        content: [
          {
            type: "tool-result",
            toolCallId: `read-${index}`,
            toolName: "probe",
            output: {
              type: "text",
              value: `source-${index}:${"x".repeat(20_000)}`,
            },
          },
        ],
      },
    ]).flat(),
  ];
  let summaryPrompt = "";
  let resumedPrompt = "";
  let summaryCount = 0;
  state.model = new MockLanguageModelV3({
    doStream: async (options) => {
      if (isSummaryCall(options)) {
        summaryCount++;
        summaryPrompt = JSON.stringify(options.prompt);
        return summaryStream("The first source is source-0.");
      }
      resumedPrompt = JSON.stringify(options.prompt);
      return {
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
      };
    },
  });

  try {
    const stream = streamResponse({
      model: MODEL,
      prompt: "Continue the inspection.",
      system: "Keep all source evidence available.",
      messages: priorMessages,
      toolChoice,
      silent: true,
      authConfig: {
        customProviders: {
          fixture: {
            baseUrl: "https://example.invalid/v1",
            models: [
              {
                id: "synthetic",
                contextLength: 200_000,
                maxOutputTokens: 20_000,
              },
            ],
          },
        },
      },
    });
    for await (const _part of stream.fullStream) void _part;
    expect(summaryCount).toBe(toolChoice === "auto" ? 1 : 0);
    if (toolChoice === "auto") {
      expect(summaryPrompt.includes("source-0:")).toBe(true);
      expect(summaryPrompt.includes("source-31:")).toBe(true);
      expect(
        summaryPrompt.includes("Keep all source evidence available."),
      ).toBe(true);
      expect(resumedPrompt.includes("The first source is source-0.")).toBe(
        true,
      );
    } else {
      expect(resumedPrompt.includes("source-0:")).toBe(true);
    }
  } finally {
    state.model = null;
  }
});

it.each([
  "empty",
  "ineffective",
])("keeps fitting history after an %s proactive summary", async (summaryKind) => {
  const messages: ModelMessage[] = [
    { role: "user", content: "Inspect the fixed sources." },
    ...Array.from({ length: 32 }, (_, index): ModelMessage[] => [
      {
        role: "assistant",
        content: [
          {
            type: "tool-call",
            toolCallId: `read-${index}`,
            toolName: "probe",
            input: {},
          },
        ],
      },
      {
        role: "tool",
        content: [
          {
            type: "tool-result",
            toolCallId: `read-${index}`,
            toolName: "probe",
            output: {
              type: "text",
              value: `source-${index}:${"x".repeat(20_000)}`,
            },
          },
        ],
      },
    ]).flat(),
  ];
  let summaryCalls = 0;
  let resumedPrompt = "";
  let skipped = false;
  const onSummarized = vi.fn();
  state.model = new MockLanguageModelV3({
    doStream: async (options) => {
      if (isSummaryCall(options)) {
        summaryCalls++;
        return summaryStream(
          summaryKind === "empty" ? "" : "s".repeat(540_000),
        );
      }
      resumedPrompt = JSON.stringify(options.prompt);
      return {
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
      };
    },
  });

  try {
    const stream = streamResponse({
      model: MODEL,
      prompt: "Continue the inspection.",
      messages,
      onSummarized,
      silent: true,
      authConfig: {
        customProviders: {
          fixture: {
            baseUrl: "https://example.invalid/v1",
            models: [
              {
                id: "synthetic",
                contextLength: 200_000,
                maxOutputTokens: 20_000,
              },
            ],
          },
        },
      },
    });
    for await (const part of stream.fullStream) {
      if (
        part.type === "tool-result" &&
        JSON.stringify(part).includes("Compaction skipped")
      ) {
        skipped = true;
      }
    }
    expect(summaryCalls).toBe(summaryKind === "empty" ? 2 : 1);
    expect(skipped).toBe(true);
    expect(resumedPrompt).toContain("source-0:");
    expect(resumedPrompt).toContain("source-31:");
    expect(onSummarized).not.toHaveBeenCalled();
  } finally {
    state.model = null;
  }
});

it("retries proactive compaction after a new tool result", async () => {
  const messages: ModelMessage[] = [
    { role: "user", content: "Keep the first source." },
    ...Array.from({ length: 2 }, (_, index): ModelMessage[] => [
      {
        role: "assistant",
        content: [
          {
            type: "tool-call",
            toolCallId: `old-${index}`,
            toolName: "probe",
            input: {},
          },
        ],
      },
      {
        role: "tool",
        content: [
          {
            type: "tool-result",
            toolCallId: `old-${index}`,
            toolName: "probe",
            output: {
              type: "text",
              value: `source-${index}:${"x".repeat(300_000)}`,
            },
          },
        ],
      },
    ]).flat(),
  ];
  let summaryCalls = 0;
  let providerCalls = 0;
  let retryPrompt = "";
  const onSummarized = vi.fn();
  state.model = new MockLanguageModelV3({
    doStream: async (options) => {
      if (isSummaryCall(options)) {
        summaryCalls++;
        if (summaryCalls === 3) retryPrompt = JSON.stringify(options.prompt);
        return summaryStream(
          summaryCalls < 3 ? "" : "The first source is source-0.",
        );
      }
      const call = providerCalls++;
      return {
        stream: simulateReadableStream({
          chunks:
            call === 0
              ? ([
                  {
                    type: "tool-call",
                    toolCallId: "new-source",
                    toolName: "probe",
                    input: "{}",
                  },
                  {
                    type: "finish",
                    finishReason: { unified: "tool-calls", raw: "tool_calls" },
                    usage,
                  },
                ] as LanguageModelV3StreamPart[])
              : ([
                  { type: "text-start", id: "done" },
                  { type: "text-delta", id: "done", delta: "done" },
                  { type: "text-end", id: "done" },
                  {
                    type: "finish",
                    finishReason: { unified: "stop", raw: "stop" },
                    usage,
                  },
                ] as LanguageModelV3StreamPart[]),
        }),
      };
    },
  });

  try {
    const stream = streamResponse({
      model: MODEL,
      prompt: "Continue.",
      messages,
      tools: {
        probe: tool({
          description: "Return the next source",
          inputSchema: z.object({}),
          execute: async () => "new-evidence",
        }),
      },
      stopWhen: stepCountIs(2),
      onSummarized,
      silent: true,
      authConfig: {
        customProviders: {
          fixture: {
            baseUrl: "https://example.invalid/v1",
            models: [
              {
                id: "synthetic",
                contextLength: 200_000,
                maxOutputTokens: 20_000,
              },
            ],
          },
        },
      },
    });
    for await (const _part of stream.fullStream) void _part;
    expect(summaryCalls).toBe(3);
    expect(providerCalls).toBe(2);
    expect(retryPrompt).toContain("source-0:");
    expect(retryPrompt).toContain("new-evidence");
    expect(onSummarized).toHaveBeenCalledWith("The first source is source-0.");
  } finally {
    state.model = null;
  }
});

it("retries an oversized summary with fitted history", async () => {
  const messages: ModelMessage[] = [
    { role: "user", content: "Preserve the original task." },
    ...Array.from({ length: 10 }, (_, index): ModelMessage[] => [
      {
        role: "assistant",
        content: [
          {
            type: "tool-call",
            toolCallId: `read-${index}`,
            toolName: "probe",
            input: {},
          },
        ],
      },
      {
        role: "tool",
        content: [
          {
            type: "tool-result",
            toolCallId: `read-${index}`,
            toolName: "probe",
            output: {
              type: "text",
              value: `source-${index}:${"x".repeat(80_000)}`,
            },
          },
        ],
      },
    ]).flat(),
  ];
  const summaryInputs: number[] = [];
  state.model = new MockLanguageModelV3({
    doStream: async (options) => {
      if (isSummaryCall(options)) {
        const input = estimateMessageTokens(options.prompt as ModelMessage[]);
        summaryInputs.push(input);
        if (input > 140_000 || summaryInputs.length === 2) {
          throw new Error(
            `prompt is too long: ${input} tokens > 140000 maximum`,
          );
        }
        return summaryStream("Bounded summary.");
      }
      return {
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
      };
    },
  });

  try {
    const stream = createSummarizationStream(
      messages,
      {
        model: MODEL,
        prompt: "Continue.",
        authConfig: {
          customProviders: {
            fixture: {
              baseUrl: "https://example.invalid/v1",
              models: [
                {
                  id: "synthetic",
                  contextLength: 200_000,
                  maxOutputTokens: 20_000,
                },
              ],
            },
          },
        },
      },
      state.model,
    );
    for await (const _part of stream.fullStream) void _part;
    expect(summaryInputs).toHaveLength(3);
    expect(summaryInputs[0]).toBeGreaterThan(140_000);
    expect(summaryInputs[1]).toBeLessThan(140_000);
    expect(summaryInputs[2]).toBeLessThan(summaryInputs[1]!);
  } finally {
    state.model = null;
  }
});

it("tries shortened summary history even when the retry budget is too small", async () => {
  const messages: ModelMessage[] = [
    { role: "user", content: `Keep this request: ${"p".repeat(550_000)}` },
    ...Array.from({ length: 8 }, (_, index): ModelMessage[] => [
      {
        role: "assistant",
        content: [
          {
            type: "tool-call",
            toolCallId: `source-${index}`,
            toolName: "probe",
            input: {},
          },
        ],
      },
      {
        role: "tool",
        content: [
          {
            type: "tool-result",
            toolCallId: `source-${index}`,
            toolName: "probe",
            output: { type: "text", value: `source:${"e".repeat(10_000)}` },
          },
        ],
      },
    ]).flat(),
  ];
  const fitted = fitMessagesToContext(messages, {
    contextWindow: 150_000,
    maxOutputTokens: 20_000,
    overheadTokens: 1_000,
  });
  expect(fitted.modified).toBe(true);
  expect(fitted.fitsBudget).toBe(false);

  const summaryInputs: number[] = [];
  state.model = new MockLanguageModelV3({
    doStream: async (options) => {
      if (isSummaryCall(options)) {
        summaryInputs.push(
          estimateMessageTokens(options.prompt as ModelMessage[]),
        );
        if (summaryInputs.length === 1) {
          throw new Error(
            "prompt is too long: maximum context length exceeded",
          );
        }
        return summaryStream("Kept the request.");
      }
      return {
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
      };
    },
  });

  try {
    const stream = createSummarizationStream(
      messages,
      {
        model: MODEL,
        prompt: "Continue.",
        authConfig: {
          customProviders: {
            fixture: {
              baseUrl: "https://example.invalid/v1",
              models: [
                {
                  id: "synthetic",
                  contextLength: 200_000,
                  maxOutputTokens: 20_000,
                },
              ],
            },
          },
        },
      },
      state.model,
    );
    for await (const _part of stream.fullStream) void _part;
    expect(summaryInputs).toHaveLength(2);
    expect(summaryInputs[1]).toBeLessThan(summaryInputs[0] ?? 0);
  } finally {
    state.model = null;
  }
});

it.each([
  "tool-only",
  "partial-text",
])("retries a %s compaction response without executing the tool", async (firstResponse) => {
  let summaryAttempts = 0;
  let usageEvents = 0;
  let toolExecutions = 0;
  let resumedPrompt = "";
  state.model = new MockLanguageModelV3({
    doStream: async (options) => {
      if (isSummaryCall(options)) {
        summaryAttempts++;
        if (summaryAttempts > 1) return summaryStream("Continue safely.");
        return {
          stream: simulateReadableStream({
            chunks: [
              ...(firstResponse === "partial-text"
                ? [
                    { type: "text-start", id: "s" },
                    {
                      type: "text-delta",
                      id: "s",
                      delta: "Incomplete summary.",
                    },
                    { type: "text-end", id: "s" },
                  ]
                : []),
              {
                type: "tool-call",
                toolCallId: "summary-probe",
                toolName: "probe",
                input: "{}",
              },
              {
                type: "finish",
                finishReason: { unified: "tool-calls", raw: "tool_calls" },
                usage,
              },
            ] as LanguageModelV3StreamPart[],
          }),
        };
      }
      resumedPrompt = JSON.stringify(options.prompt);
      return {
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
      };
    },
  });

  try {
    const stream = createSummarizationStream(
      [{ role: "user", content: "Preserve the task." }],
      {
        model: MODEL,
        prompt: "Continue.",
        tools: {
          probe: tool({
            description: "Must not execute during compaction",
            inputSchema: z.object({}),
            execute: async () => {
              toolExecutions++;
              return "unexpected";
            },
          }),
        },
        onStepFinish: (step) => {
          if (step.response.id === "summarization") usageEvents++;
        },
        authConfig: {
          customProviders: {
            fixture: {
              baseUrl: "https://example.invalid/v1",
              models: [
                {
                  id: "synthetic",
                  contextLength: 200_000,
                  maxOutputTokens: 20_000,
                },
              ],
            },
          },
        },
      },
      state.model,
    );
    for await (const _part of stream.fullStream) void _part;
    expect(summaryAttempts).toBe(2);
    expect(usageEvents).toBe(2);
    expect(toolExecutions).toBe(0);
    expect(resumedPrompt).toContain("Continue safely.");
    expect(resumedPrompt).not.toContain("Incomplete summary.");
  } finally {
    state.model = null;
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
      if (isSummaryCall(options)) {
        summaryCalls++;
        return summaryStream("Continue inspection.");
      }
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
      if (isSummaryCall(options)) {
        summaryCalls++;
        return summaryStream("Continue.");
      }
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

it("continues an in-stream turn when its proactive summary is rejected", async () => {
  let providerCalls = 0;
  let summaryCalls = 0;
  let resumedPrompt = "";
  state.model = new MockLanguageModelV3({
    doStream: async (options) => {
      if (isSummaryCall(options)) {
        summaryCalls++;
        return summaryStream("");
      }
      const call = providerCalls++;
      if (call > 0) resumedPrompt = JSON.stringify(options.prompt);
      return {
        stream: simulateReadableStream({
          chunks:
            call === 0
              ? ([
                  {
                    type: "tool-call",
                    toolCallId: "source",
                    toolName: "probe",
                    input: "{}",
                  },
                  {
                    type: "finish",
                    finishReason: { unified: "tool-calls", raw: "tool_calls" },
                    usage,
                  },
                ] as LanguageModelV3StreamPart[])
              : ([
                  { type: "text-start", id: "done" },
                  { type: "text-delta", id: "done", delta: "done" },
                  { type: "text-end", id: "done" },
                  {
                    type: "finish",
                    finishReason: { unified: "stop", raw: "stop" },
                    usage,
                  },
                ] as LanguageModelV3StreamPart[]),
        }),
      };
    },
  });

  try {
    const stream = streamResponse({
      model: MODEL,
      prompt: "Read the source.",
      tools: {
        probe: tool({
          description: "Return synthetic evidence",
          inputSchema: z.object({}),
          execute: async () => `source-evidence:${"e".repeat(620_000)}`,
        }),
      },
      stopWhen: stepCountIs(2),
      silent: true,
      authConfig: {
        customProviders: {
          fixture: {
            baseUrl: "https://example.invalid/v1",
            models: [
              {
                id: "synthetic",
                contextLength: 200_000,
                maxOutputTokens: 20_000,
              },
            ],
          },
        },
      },
    });
    for await (const _part of stream.fullStream) void _part;
    expect(providerCalls).toBe(2);
    expect(summaryCalls).toBe(2);
    expect(resumedPrompt).toContain("source-evidence:");
  } finally {
    state.model = null;
  }
});

it("uses minimal recovery when a reactive summary is rejected", async () => {
  let providerCalls = 0;
  let summaryCalls = 0;
  let resumedPrompt = "";
  let syntheticCalls = 0;
  let syntheticResults = 0;
  const onSummarized = vi.fn();
  state.model = new MockLanguageModelV3({
    doStream: async (options) => {
      if (isSummaryCall(options)) {
        summaryCalls++;
        return summaryStream("");
      }
      const call = providerCalls++;
      if (call > 0) resumedPrompt = JSON.stringify(options.prompt);
      return {
        stream: simulateReadableStream({
          chunks:
            call === 0
              ? ([
                  {
                    type: "error",
                    error: new Error(
                      "prompt is too long: context length exceeded",
                    ),
                  },
                ] as LanguageModelV3StreamPart[])
              : ([
                  { type: "text-start", id: "done" },
                  { type: "text-delta", id: "done", delta: "done" },
                  { type: "text-end", id: "done" },
                  {
                    type: "finish",
                    finishReason: { unified: "stop", raw: "stop" },
                    usage,
                  },
                ] as LanguageModelV3StreamPart[]),
        }),
      };
    },
  });

  try {
    const stream = streamResponse({
      model: MODEL,
      prompt: "Continue the task.",
      messages: [{ role: "user", content: "Old synthetic evidence." }],
      onSummarized,
      silent: true,
      authConfig: {
        customProviders: {
          fixture: {
            baseUrl: "https://example.invalid/v1",
            models: [
              {
                id: "synthetic",
                contextLength: 200_000,
                maxOutputTokens: 20_000,
              },
            ],
          },
        },
      },
    });
    for await (const part of stream.fullStream) {
      if (
        part.type === "tool-call" &&
        part.toolName === "summarize_conversation"
      ) {
        syntheticCalls++;
      }
      if (
        part.type === "tool-result" &&
        part.toolName === "summarize_conversation"
      ) {
        syntheticResults++;
      }
    }
    expect(providerCalls).toBe(2);
    expect(summaryCalls).toBe(2);
    expect(syntheticCalls).toBe(1);
    expect(syntheticResults).toBe(1);
    expect(onSummarized).toHaveBeenCalledWith("");
    expect(resumedPrompt).not.toContain("Old synthetic evidence.");
  } finally {
    state.model = null;
  }
});

it("contains a context error from an in-stream summary", async () => {
  let providerCalls = 0;
  state.model = new MockLanguageModelV3({
    doStream: async (options) => {
      if (isSummaryCall(options)) {
        throw new Error("prompt is too long: 999999 tokens > 20000 maximum");
      }
      return {
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
      };
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
