import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type {
  LanguageModelV3CallOptions,
  LanguageModelV3StreamPart,
} from "@ai-sdk/provider";
import { simulateReadableStream, stepCountIs, type ToolSet, tool } from "ai";
import { MockLanguageModelV3 } from "ai/test";
import { expect, it, vi } from "vitest";
import { z } from "zod";
import { createAllTools } from "../agents/offSecAgent/tools";

const state = vi.hoisted(() => ({
  model: undefined as MockLanguageModelV3 | undefined,
}));
vi.mock("./utils", async () => ({
  ...(await vi.importActual<typeof import("./utils")>("./utils")),
  getProviderModel: () => state.model,
}));
const { streamResponse } = await import("./ai");
const { estimateMessageTokens, estimateToolsOverheadTokens, estimateTokens } =
  await import("./contextManagement");
const authConfig = {
  customProviders: {
    fixture: {
      baseUrl: "https://example.invalid/v1",
      models: [{ id: "small", contextLength: 65_536, maxOutputTokens: 32_768 }],
    },
  },
};
const usage = {
  inputTokens: { total: 10, noCache: 10, cacheRead: 0, cacheWrite: 0 },
  outputTokens: { total: 5, text: 5, reasoning: undefined },
};

it.each([
  "messages",
  "prompt",
] as const)("runs a 64K custom model from %s with real tool schemas and compacts subsequent output without a futile summary", async (input) => {
  const root = mkdtempSync(join(tmpdir(), "apex-context-budget-"));
  try {
    const tools: ToolSet = {
      ...createAllTools({
        session: {
          id: "fixture",
          rootPath: root,
          logsPath: join(root, "logs"),
          scratchpadPath: join(root, "scratchpad"),
          findingsPath: join(root, "findings"),
          config: {},
        },
        agentCwd: root,
        sandbox: {
          type: "linux",
          execute: async () => {
            throw new Error("Unexpected command execution");
          },
        },
      } as never),
      probe: tool({
        description: "Read fixture evidence",
        inputSchema: z.object({}),
        execute: async () => "e".repeat(80_000),
      }),
    };
    const system = "s".repeat(4_334 * 4);
    const calls: LanguageModelV3CallOptions[] = [];
    state.model = new MockLanguageModelV3({
      doStream: async (options) => {
        expect(JSON.stringify(options.prompt)).not.toContain(
          "Compact this conversation",
        );
        calls.push(options);
        const chunks: LanguageModelV3StreamPart[] =
          calls.length === 1
            ? [
                {
                  type: "tool-call",
                  toolCallId: "probe-1",
                  toolName: "probe",
                  input: "{}",
                },
                {
                  type: "finish",
                  finishReason: { unified: "tool-calls", raw: "tool-calls" },
                  usage,
                },
              ]
            : [
                { type: "text-start", id: "t" },
                { type: "text-delta", id: "t", delta: "done" },
                { type: "text-end", id: "t" },
                {
                  type: "finish",
                  finishReason: { unified: "stop", raw: "stop" },
                  usage,
                },
              ];
        return { stream: simulateReadableStream({ chunks }) };
      },
    });
    const response = streamResponse({
      model: "custom:fixture:small",
      prompt: input === "prompt" ? "Inspect the fixture. ".repeat(200) : "",
      harness: "general",
      messages:
        input === "messages"
          ? [{ role: "user", content: "Inspect the fixture. ".repeat(200) }]
          : undefined,
      system,
      tools,
      authConfig,
      sessionPath: root,
      silent: true,
      stopWhen: stepCountIs(3),
    });
    const text: string[] = [];
    for await (const part of response.fullStream)
      if (part.type === "text-delta") text.push(part.text);
    expect(text.join("")).toBe("done");
    expect(calls).toHaveLength(2);
    for (const call of calls) {
      if (call.maxOutputTokens === undefined)
        throw new Error("Missing output allocation");
      expect(call.maxOutputTokens).toBeGreaterThan(0);
      expect(call.maxOutputTokens).toBeLessThan(32_768);
      expect(call.tools?.length).toBe(Object.keys(tools).length);
      expect(
        estimateMessageTokens(call.prompt as never) +
          estimateToolsOverheadTokens(tools) +
          1_000 +
          10_000 +
          call.maxOutputTokens,
      ).toBeLessThanOrEqual(65_536);
    }
    expect(calls[0].maxOutputTokens).toBe(calls[1].maxOutputTokens);
    expect(JSON.stringify(calls[1].prompt)).not.toContain("e".repeat(80_000));
    expect(estimateTokens(system)).toBe(4_334);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

it("preserves the output minimum required by budget-based thinking", async () => {
  const calls: LanguageModelV3CallOptions[] = [];
  state.model = new MockLanguageModelV3({
    doStream: async (options) => {
      calls.push(options);
      return {
        stream: simulateReadableStream({
          chunks: [
            {
              type: "finish",
              finishReason: { unified: "stop", raw: "stop" },
              usage,
            },
          ],
        }),
      };
    },
  });
  const result = streamResponse({
    model: "claude-sonnet-4-20250514",
    prompt: "",
    messages: [{ role: "user", content: "Hi" }],
    enableThinking: true,
    system: "s".repeat((200_000 - 1_000 - 10_000 - 3_000) * 4),
    silent: true,
  });
  for await (const _part of result.fullStream) {
    /* Drain the provider stream. */
  }
  expect(calls).toHaveLength(1);
  expect(calls[0].maxOutputTokens).toBe(2048);
  expect(calls[0].providerOptions?.anthropic).toMatchObject({
    thinking: { type: "enabled", budgetTokens: 1024 },
  });
});
