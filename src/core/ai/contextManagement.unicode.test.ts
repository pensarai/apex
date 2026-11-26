import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createAmazonBedrock } from "@ai-sdk/amazon-bedrock";
import { generateText, type ModelMessage } from "ai";
import { afterEach, describe, expect, it } from "vitest";
import { z } from "zod";
import { applyToolResultBudget, truncateWithMarker } from "./contextManagement";

const directories: string[] = [];
function sessionDirectory() {
  const path = mkdtempSync(join(tmpdir(), "apex-unicode-"));
  directories.push(path);
  return path;
}
function toolMessages(text: string): ModelMessage[] {
  return [
    { role: "user", content: "Inspect synthetic output" },
    {
      role: "assistant",
      content: [
        {
          type: "tool-call",
          toolCallId: "synthetic",
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
          toolCallId: "synthetic",
          toolName: "probe",
          output: { type: "text", value: text },
        },
      ],
    },
  ];
}
function resultText(messages: ModelMessage[]) {
  const message = messages[2];
  if (message.role !== "tool") throw new Error("expected tool message");
  const part = message.content[0];
  if (part.type !== "tool-result" || part.output.type !== "text")
    throw new Error("expected text output");
  return part.output.value;
}
afterEach(() => {
  for (const path of directories.splice(0))
    rmSync(path, { recursive: true, force: true });
});

describe("Unicode context truncation", () => {
  it.each([
    500, 2000, 5000, 10000,
  ])("preserves valid Unicode and original output at threshold %i", (maxResultChars) => {
    const previewSize = maxResultChars / 5;
    const original = `${"a".repeat(previewSize - 1)}😀${"b".repeat(maxResultChars)}`;
    const sessionPath = sessionDirectory();
    const result = resultText(
      applyToolResultBudget(toolMessages(original), {
        sessionPath,
        maxResultChars,
      }),
    );
    expect(result.isWellFormed()).toBe(true);
    expect(result.split("\n\n")[0]).toBe("a".repeat(previewSize - 1));
    expect(result).toContain(
      `truncated ${original.length - (previewSize - 1)} chars`,
    );
    expect(
      readFileSync(
        join(
          sessionPath,
          "logs",
          "tool-output",
          `${result.match(/tool-output:([0-9a-f-]{36})/)![1]}.txt`,
        ),
        "utf8",
      ),
    ).toBe(original);
  });

  it.each([
    undefined,
    "schema",
  ])("preserves marker boundaries and counts with label %s", (label) => {
    const max = 100;
    const length = 1000;
    const marker = label
      ? `…[${label} truncated]`
      : `…[truncated ${length} chars]`;
    const cut = max - marker.length;
    const original = `${"a".repeat(cut - 1)}😀${"b".repeat(length - cut - 1)}`;
    const result = truncateWithMarker(original, max, label);
    expect(result.isWellFormed()).toBe(true);
    expect(result.length).toBeLessThanOrEqual(max);
    expect(result.startsWith(`${"a".repeat(cut - 1)}…[`)).toBe(true);
    if (!label)
      expect(result).toContain(
        `truncated ${original.length - (cut - 1)} chars`,
      );
    expect(truncateWithMarker("a😀", 3, label)).toBe("a😀");
    const fittingPair = `${"a".repeat(cut - 2)}😀${"b".repeat(length - cut)}`;
    expect(
      truncateWithMarker(fittingPair, max, label).startsWith(
        `${"a".repeat(cut - 2)}😀…[`,
      ),
    ).toBe(true);
  });

  it("sends well-formed tool-result text through the actual Bedrock SDK serializer", async () => {
    const original = `${"a".repeat(99)}😀${"b".repeat(900)}`;
    const messages = applyToolResultBudget(toolMessages(original), {
      sessionPath: sessionDirectory(),
      maxResultChars: 500,
    });
    let wireText: string | undefined;
    const model = createAmazonBedrock({
      apiKey: "synthetic-key",
      region: "us-east-1",
      fetch: Object.assign(
        async (_url: RequestInfo | URL, init?: RequestInit) => {
          const body = JSON.parse(String(init?.body));
          wireText = body.messages
            .flatMap(
              (message: {
                content: { toolResult?: { content: { text: string }[] } }[];
              }) => message.content,
            )
            .find((part: { toolResult?: unknown }) => part.toolResult)
            .toolResult.content[0].text;
          return Response.json({
            output: {
              message: { role: "assistant", content: [{ text: "ok" }] },
            },
            stopReason: "end_turn",
            usage: { inputTokens: 1, outputTokens: 1, totalTokens: 2 },
          });
        },
        { preconnect: () => {} },
      ),
    })("global.anthropic.claude-opus-4-6-v1");
    await generateText({
      model,
      messages,
      tools: { probe: { inputSchema: z.object({}) } },
      maxRetries: 0,
    });
    expect(wireText).toBeDefined();
    expect(wireText?.isWellFormed()).toBe(true);
    expect(wireText?.slice(0, 101)).toBe(`${"a".repeat(99)}\n\n`);
  });
});
