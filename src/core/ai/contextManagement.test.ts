import { describe, it, expect } from "vitest";
import type { ModelMessage, ToolSet } from "ai";
import { mkdtempSync } from "fs";
import { tmpdir } from "os";
import { join } from "path";
import { z } from "zod";
import {
  estimateTokens,
  estimateMessageTokens,
  estimateToolsOverheadTokens,
  fitMessagesToContext,
  applyToolResultBudget,
} from "./contextManagement";

function makeAssistantWithToolResult(
  toolName: string,
  resultText: string,
  toolCallId = `${toolName}-${Math.random().toString(36).slice(2, 8)}`,
): ModelMessage[] {
  return [
    {
      role: "assistant",
      content: [
        {
          type: "tool-call",
          toolCallId,
          toolName,
          input: {},
        },
      ],
    },
    {
      role: "tool",
      content: [
        {
          type: "tool-result",
          toolCallId,
          toolName,
          output: { type: "text", value: resultText },
        },
      ],
    },
  ] as unknown as ModelMessage[];
}

describe("estimateTokens", () => {
  it("returns 0 for empty input", () => {
    expect(estimateTokens("")).toBe(0);
  });

  it("scales linearly with chars/4", () => {
    expect(estimateTokens("a".repeat(100))).toBe(25);
    expect(estimateTokens("a".repeat(1000))).toBe(250);
  });
});

describe("estimateMessageTokens", () => {
  it("counts string content", () => {
    const msgs: ModelMessage[] = [
      { role: "user", content: "x".repeat(400) },
    ] as unknown as ModelMessage[];
    // 400 chars + 8 structural overhead = 408 chars / 4 = 102 tokens.
    expect(estimateMessageTokens(msgs)).toBe(102);
  });

  it("counts tool-result text in array content", () => {
    const msgs = makeAssistantWithToolResult("http_request", "x".repeat(4_000));
    // Just sanity: should be on the order of 1K tokens, not zero.
    expect(estimateMessageTokens(msgs)).toBeGreaterThan(900);
  });
});

describe("estimateToolsOverheadTokens", () => {
  it("returns 0 when no tools provided", () => {
    expect(estimateToolsOverheadTokens(undefined)).toBe(0);
  });

  it("scales with tool description + schema size", () => {
    const tools: ToolSet = {
      tiny: {
        description: "x",
        inputSchema: z.object({ a: z.string() }),
      } as unknown as ToolSet[string],
      huge: {
        description: "x".repeat(2_000),
        inputSchema: z.object({ b: z.string().describe("y".repeat(2_000)) }),
      } as unknown as ToolSet[string],
    };
    const tokens = estimateToolsOverheadTokens(tools);
    // Should reflect the multi-thousand-char `huge` tool, not be a tiny constant.
    expect(tokens).toBeGreaterThan(500);
  });
});

describe("applyToolResultBudget", () => {
  it("never emits a preview larger than maxResultChars at tight thresholds", () => {
    const sessionPath = mkdtempSync(join(tmpdir(), "tool-budget-"));
    // Result sized between the smallest cascading thresholds (500 < 1200 < 2000):
    // the previous fixed 2000-char preview would have captured the entire
    // text and reported a negative truncation count.
    const msgs = makeAssistantWithToolResult(
      "http_request",
      "x".repeat(1_200),
      "tight-threshold",
    );

    const result = applyToolResultBudget(msgs, {
      sessionPath,
      maxResultChars: 500,
    });

    const toolMsg = result[1]!;
    const part = (toolMsg.content as Array<Record<string, unknown>>)[0]!;
    const value = (part.output as { value: string }).value;

    // Output must be smaller than the original — the whole point of compaction.
    expect(value.length).toBeLessThan(1_200);
    // Truncation marker must report a positive number.
    expect(value).toMatch(/truncated 700 chars/);
    expect(value).not.toMatch(/truncated -/);
  });
});

describe("fitMessagesToContext", () => {
  it("returns input array when messages already fit", () => {
    const msgs: ModelMessage[] = [
      { role: "user", content: "hello" },
    ] as unknown as ModelMessage[];

    const result = fitMessagesToContext(msgs, {
      contextWindow: 200_000,
      maxOutputTokens: 64_000,
    });

    expect(result.modified).toBe(false);
    expect(result.fitsBudget).toBe(true);
    expect(result.messages).toBe(msgs);
  });

  it("returns fitsBudget=false when budget is non-positive", () => {
    const msgs: ModelMessage[] = [
      { role: "user", content: "hello" },
    ] as unknown as ModelMessage[];

    const result = fitMessagesToContext(msgs, {
      contextWindow: 1_000,
      maxOutputTokens: 1_000,
    });

    expect(result.fitsBudget).toBe(false);
  });

  it("invokes Layer 1 when a tool result is over the per-result budget", () => {
    const sessionPath = mkdtempSync(join(tmpdir(), "fit-ctx-"));
    const msgs = makeAssistantWithToolResult(
      "http_request",
      "x".repeat(250_000),
    );

    const result = fitMessagesToContext(msgs, {
      contextWindow: 100_000,
      maxOutputTokens: 50_000,
      overheadTokens: 0,
      safetyMarginTokens: 0,
      sessionPath,
    });

    expect(result.modified).toBe(true);
    expect(result.estimatedInputTokens).toBeLessThan(60_000);
  });

  it("derives overhead from `tools` when overheadTokens is not set", () => {
    const tinyTools: ToolSet = {
      a: {
        description: "x",
        inputSchema: z.object({ a: z.string() }),
      } as unknown as ToolSet[string],
    };
    const heavyTools: ToolSet = Object.fromEntries(
      Array.from({ length: 20 }, (_, i) => [
        `tool_${i}`,
        {
          description: "x".repeat(1_500),
          inputSchema: z.object({
            arg: z.string().describe("y".repeat(1_500)),
          }),
        } as unknown as ToolSet[string],
      ]),
    );

    const msgs: ModelMessage[] = [
      { role: "user", content: "x".repeat(400_000) },
    ] as unknown as ModelMessage[];

    const tinyResult = fitMessagesToContext(msgs, {
      contextWindow: 200_000,
      maxOutputTokens: 64_000,
      tools: tinyTools,
    });
    const heavyResult = fitMessagesToContext(msgs, {
      contextWindow: 200_000,
      maxOutputTokens: 64_000,
      tools: heavyTools,
    });

    // Heavier tool surface ⇒ tighter messages budget.
    expect(heavyResult.estimatedInputTokens).toBeLessThanOrEqual(
      tinyResult.estimatedInputTokens,
    );
  });
});
