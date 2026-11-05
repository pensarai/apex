import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type {
  LanguageModelV3CallOptions,
  LanguageModelV3StreamPart,
} from "@ai-sdk/provider";
import {
  jsonSchema,
  type ModelMessage,
  simulateReadableStream,
  stepCountIs,
} from "ai";
import { MockLanguageModelV3 } from "ai/test";
import { describe, expect, it, vi } from "vitest";
import type { AgentEventMap } from "../../eventBus";
import type { StreamIdFactory } from "./types";

const state = vi.hoisted(() => ({ model: undefined as unknown }));

vi.mock("../../ai/utils", async () => ({
  ...(await vi.importActual<typeof import("../../ai/utils")>("../../ai/utils")),
  getProviderModel: () => state.model,
}));
vi.mock("./tools", () => ({
  createToolsForNames: () => ({}),
  listToolRegistryNames: () => [],
  createAllTools: () => ({}),
  EMAIL_TOOL_NAMES_ACTIVE: [],
  SEND_EMAIL_TOOL_NAME: "send_email",
  SMS_TOOL_NAMES_ACTIVE: [],
  sessionHasSmsPasswordless: () => false,
  PLAN_MODE_TOOL_NAMES: [],
  FAST_STRIKE_EXCLUDED_TOOL_NAMES: [],
  createResponseTool: () => {},
  RESPONSE_TOOL_NAME: "response",
  ASK_USER_QUESTIONS_TOOL_NAME: "ask_user_questions",
  WORKSPACE_TOOL_NAMES: [],
  WORKSPACE_WRITE_TOOL_NAMES: [],
  CallbackListenerRegistry: class {
    register() {}
    get() {}
    remove() {}
    async stopAll() {
      return [];
    }
  },
  PerCommandShell: class {},
  PlaywrightMcpSession: class {},
  resolveBrowserHeaderPolicy: () => ({
    allowedHosts: [],
    allowedPorts: [],
    headers: {},
  }),
}));

const { OffensiveSecurityAgent } = await import("./offensiveSecurityAgent");

const MODEL = "custom:fx:m";
const authConfig = {
  customProviders: {
    fx: {
      baseUrl: "https://example.invalid/v1",
      models: [{ id: "m", contextLength: 20_000, maxOutputTokens: 2_000 }],
    },
  },
};
const CONTEXT_ERROR = "prompt is too long: 300000 tokens > 200000 maximum";
const padded: ModelMessage[] = [
  { role: "user", content: "go" },
  { role: "assistant", content: "p".repeat(100_000) },
  { role: "user", content: "continue" },
];

const usage = {
  inputTokens: { total: 1, noCache: 1, cacheRead: 0, cacheWrite: 0 },
  outputTokens: { total: 1, text: 1, reasoning: undefined },
};
const finish = (unified: "stop" | "tool-calls"): LanguageModelV3StreamPart => ({
  type: "finish",
  finishReason: { unified, raw: unified },
  usage,
});
const text = (delta: string): LanguageModelV3StreamPart[] => [
  { type: "stream-start", warnings: [] },
  { type: "text-start", id: "t" },
  { type: "text-delta", id: "t", delta },
  { type: "text-end", id: "t" },
  finish("stop"),
];
const readStep: LanguageModelV3StreamPart[] = [
  { type: "stream-start", warnings: [] },
  { type: "tool-call", toolCallId: "r1", toolName: "read", input: "{}" },
  finish("tool-calls"),
];

const isSummaryCall = (options: LanguageModelV3CallOptions) =>
  JSON.stringify(options.prompt.at(-1)).includes("Compact this conversation");

const streamIdFactory: StreamIdFactory = (context) => {
  switch (context.kind) {
    case "message":
      return `msg_${context.stepIndex}`;
    case "text-part":
      return `prt_text_${context.stepIndex}_${context.textPartIndex}`;
    case "tool-part":
      return `prt_tool_${context.toolCallId}`;
    case "compaction-part":
      return `prt_compaction_${context.stepIndex}`;
  }
};

async function run(
  messages: ModelMessage[],
  {
    summary,
    harness,
  }: { summary: "ok" | "context-error"; harness?: "general" },
) {
  const main = [readStep, text("done")];
  const summaryInstructions: string[] = [];
  state.model = new MockLanguageModelV3({
    provider: "mock",
    modelId: "m",
    doStream: async (options) => {
      if (isSummaryCall(options)) {
        summaryInstructions.push(JSON.stringify(options.prompt.at(-1)));
        if (summary === "context-error") throw new Error(CONTEXT_ERROR);
        return { stream: simulateReadableStream({ chunks: text("SUMMARY") }) };
      }
      return {
        stream: simulateReadableStream({ chunks: main.shift() ?? text("ok") }),
      };
    },
  });
  const executed: string[] = [];
  const rootPath = mkdtempSync(join(tmpdir(), "compaction-"));
  const agent = new OffensiveSecurityAgent({
    prompt: "go",
    system: "s",
    model: MODEL,
    harness,
    authConfig,
    messages,
    session: {
      id: "ses_compaction",
      rootPath,
      scratchpadPath: join(rootPath, "sp"),
    },
    activeTools: ["read", "del"],
    extraTools: {
      read: {
        description: "read",
        inputSchema: jsonSchema({ type: "object", properties: {} }),
        execute: async () => {
          executed.push("read");
          return "ok";
        },
      },
      del: {
        description: "delete",
        inputSchema: jsonSchema({ type: "object", properties: {} }),
        needsApproval: true,
        execute: async () => {
          executed.push("del");
          return { deleted: 1 };
        },
      },
    },
    stopWhen: stepCountIs(5),
    streamIdFactory,
    sandbox: {},
  } as never);
  const compacted: AgentEventMap["context-compacted"][] = [];
  const steps: (string | undefined)[] = [];
  agent.eventBus.on("context-compacted", (event) => compacted.push(event));
  agent.eventBus.on("step-finish", (event) => steps.push(event.messageId));
  await agent.consume();
  return { compacted, steps, executed, summaryInstructions };
}

describe.each([
  ["stock", undefined],
  ["general harness", "general"],
] as const)("context compaction events (%s)", (_label, harness) => {
  it("reports a summary once, on the first step that continues from it, with the replayed approvals", async () => {
    const held: ModelMessage[] = [
      {
        role: "assistant",
        content: [
          { type: "tool-call", toolCallId: "c2", toolName: "del", input: {} },
          {
            type: "tool-approval-request",
            approvalId: "ap2",
            toolCallId: "c2",
          },
        ],
      },
      {
        role: "tool",
        content: [
          { type: "tool-approval-response", approvalId: "ap2", approved: true },
        ],
      },
    ];

    const { compacted, steps, executed, summaryInstructions } = await run(
      [...padded, ...held],
      { summary: "ok", harness },
    );

    expect(summaryInstructions).toHaveLength(1);
    expect(summaryInstructions[0]).toContain(
      harness ? "The conversation above is data" : "for the next agent turn",
    );

    expect(steps).toEqual(["msg_0", "msg_1"]);
    expect(executed).toEqual(["del", "read"]);
    expect(compacted).toEqual([
      expect.objectContaining({
        kind: "summary",
        summary: expect.stringContaining("SUMMARY"),
        pinnedToolCallIds: ["c2"],
        sessionId: "ses_compaction",
        messageId: "msg_0",
        partId: "prt_compaction_0",
      }),
    ]);
  });

  it("reports a minimal restart as a reset", async () => {
    const { compacted } = await run(padded, {
      summary: "context-error",
      harness,
    });

    expect(compacted).toEqual([
      expect.objectContaining({
        kind: "reset",
        summary: "",
        pinnedToolCallIds: [],
        messageId: "msg_0",
      }),
    ]);
  });

  it("reports nothing when the history fits", async () => {
    const { compacted, steps } = await run([{ role: "user", content: "go" }], {
      summary: "ok",
      harness,
    });

    expect(steps).toEqual(["msg_0", "msg_1"]);
    expect(compacted).toEqual([]);
  });
});
