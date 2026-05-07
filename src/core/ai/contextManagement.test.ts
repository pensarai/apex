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
  truncateWithMarker,
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

describe("truncateWithMarker", () => {
  it("returns input unchanged when text fits", () => {
    expect(truncateWithMarker("hi", 10)).toBe("hi");
    expect(truncateWithMarker("hi", 10, "label")).toBe("hi");
  });

  it("treats `max` as a strict upper bound — labeled marker", () => {
    // Pinning the hard-cap contract that auxiliary-LLM input caps
    // (MAX_TOOL_INPUT_CHARS, MAX_SCHEMA_CHARS, etc.) rely on. Soft caps
    // would silently inflate budgets by ~30 chars per call.
    const out = truncateWithMarker("x".repeat(10_000), 100, "schema");
    expect(out.length).toBeLessThanOrEqual(100);
    expect(out).toMatch(/…\[schema truncated\]$/);
  });

  it("treats `max` as a strict upper bound — unlabeled marker", () => {
    const out = truncateWithMarker("x".repeat(10_000), 100);
    expect(out.length).toBeLessThanOrEqual(100);
    expect(out).toMatch(/…\[truncated \d+ chars\]$/);
  });

  it("dropped-char count reflects sliceLen (post-reservation), not max", () => {
    // sliceLen = max - widestMarker.length, so dropped = text.length - sliceLen
    // — strictly more chars are dropped than `text.length - max`. Pin the
    // exact relationship so future regressions are loud.
    const text = "x".repeat(10_000);
    const out = truncateWithMarker(text, 100);
    const m = out.match(/…\[truncated (\d+) chars\]$/);
    expect(m).not.toBeNull();
    const dropped = Number(m![1]);
    // sliceLen is at most ~75 (100 - widestMarker(~25)), so dropped ≥ 9925.
    expect(dropped).toBeGreaterThanOrEqual(10_000 - 100);
    expect(dropped).toBeLessThan(10_000);
  });

  it("degenerate max < marker length still returns just the marker", () => {
    // Better signal than a ~5-char head with no marker.
    const out = truncateWithMarker("x".repeat(100), 5);
    expect(out).toContain("truncated");
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
    // previewSize at maxChars=500 is `max(100, 500/5) = 100`, so 1200 - 100 = 1100.
    expect(value).toMatch(/truncated 1100 chars/);
    expect(value).not.toMatch(/truncated -/);
  });

  it("cascading thresholds progressively reduce already-truncated entries", () => {
    // Bugbot flagged that a fixed 2000-char preview made the 5K and
    // 2K cascading thresholds no-ops on entries the 10K pass had
    // shrunk to ~2080 chars — only the 500 threshold did anything.
    // Now `previewSize = max(100, maxChars / 5)` scales with the
    // threshold, so each pass produces a strictly smaller preview.
    const sessionPath = mkdtempSync(join(tmpdir(), "tool-budget-progressive-"));
    const msgs = makeAssistantWithToolResult(
      "execute_command",
      "y".repeat(50_000),
      "progressive-id",
    );

    const persistedIds = new Set<string>();
    let current = msgs;
    const lengths: number[] = [];
    for (const maxResultChars of [10_000, 5_000, 2_000, 500]) {
      current = applyToolResultBudget(current, {
        sessionPath,
        maxResultChars,
        persistedIds,
      });
      const value = (
        (current[1]!.content as Array<Record<string, unknown>>)[0]!.output as {
          value: string;
        }
      ).value;
      lengths.push(value.length);
    }

    // Each subsequent pass MUST yield a strictly shorter output. Pre-fix
    // the array would be e.g. [2080, 2080, 2080, 580] — three identical
    // values means three wasted iterations.
    for (let i = 1; i < lengths.length; i++) {
      expect(
        lengths[i]!,
        `pass ${i}: ${lengths[i - 1]} → ${lengths[i]} (must shrink)`,
      ).toBeLessThan(lengths[i - 1]!);
    }
  });

  it("cascading thresholds preserve the ORIGINAL dropped-char count", () => {
    // Reproduces the metadata-corruption case Bugbot flagged: 50K text
    // truncated at 10K → ~2080-char preview, then re-truncated at 2K.
    // Pre-fix the second pass reported "truncated 80 chars" (preview→
    // smaller-preview delta), hiding the true ~48K of data loss. The
    // metadata must keep referencing the ORIGINAL length and the file
    // path written on the FIRST pass.
    const sessionPath = mkdtempSync(join(tmpdir(), "tool-budget-cascade-"));
    const original = "x".repeat(50_000);
    const msgs = makeAssistantWithToolResult(
      "execute_command",
      original,
      "cascade-id",
    );

    const persistedIds = new Set<string>();
    const afterPass1 = applyToolResultBudget(msgs, {
      sessionPath,
      maxResultChars: 10_000,
      persistedIds,
    });
    const pass1Value = (
      (afterPass1[1]!.content as Array<Record<string, unknown>>)[0]!.output as {
        value: string;
      }
    ).value;
    expect(pass1Value).toMatch(/truncated 48000 chars/);
    const pass1FilePath = pass1Value.match(
      /full output saved to (.+?)\]$/,
    )![1]!;

    const afterPass2 = applyToolResultBudget(afterPass1, {
      sessionPath,
      maxResultChars: 2_000,
      persistedIds,
    });
    const pass2Value = (
      (afterPass2[1]!.content as Array<Record<string, unknown>>)[0]!.output as {
        value: string;
      }
    ).value;

    // The headline assertion: dropped-char count references the ORIGINAL
    // 50K, not the 2080-char preview. Pre-fix this would say `truncated 80
    // chars` (preview→smaller-preview delta), hiding the real ~48K of
    // data loss. With `previewSize = max(100, maxChars / 5)` the second
    // pass produces a 400-char preview, so dropped = 50000 - 400 = 49600.
    expect(pass2Value).toMatch(/truncated 49600 chars/);
    // Path must point to the FIRST pass's persisted file, not a fresh one.
    expect(pass2Value).toContain(pass1FilePath);
    // Negative-shape assertion: must NOT report the misleading delta-
    // against-preview count that the metadata-corruption bug produced.
    expect(pass2Value).not.toMatch(/truncated 80 chars/);
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
