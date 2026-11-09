import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { LanguageModelV3StreamPart } from "@ai-sdk/provider";
import { jsonSchema, simulateReadableStream } from "ai";
import { MockLanguageModelV3 } from "ai/test";
import { expect, it, vi } from "vitest";

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
  REPORT_ERROR_TOOL_NAME: "report_error",
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

const usage = {
  inputTokens: { total: 1, noCache: 1, cacheRead: 0, cacheWrite: 0 },
  outputTokens: { total: 1, text: 1, reasoning: undefined },
};
const chunks: LanguageModelV3StreamPart[] = [
  { type: "stream-start", warnings: [] },
  { type: "tool-call", toolCallId: "c1", toolName: "list", input: "{}" },
  { type: "tool-call", toolCallId: "c2", toolName: "del", input: "{}" },
  {
    type: "finish",
    finishReason: { unified: "tool-calls", raw: "tool-calls" },
    usage,
  },
];

it("a call held for approval is surfaced as an approval request, never closed as incomplete", async () => {
  state.model = new MockLanguageModelV3({
    provider: "mock",
    modelId: "claude-haiku-4-5",
    doStream: async () => ({ stream: simulateReadableStream({ chunks }) }),
  });
  const executed: string[] = [];
  const rootPath = mkdtempSync(join(tmpdir(), "approval-"));
  const agent = new OffensiveSecurityAgent({
    prompt: "go",
    system: "s",
    model: "claude-haiku-4-5",
    session: {
      id: "ses_approval",
      rootPath,
      scratchpadPath: join(rootPath, "sp"),
    },
    activeTools: ["list", "del"],
    extraTools: {
      list: {
        description: "list",
        inputSchema: jsonSchema({ type: "object", properties: {} }),
        execute: async () => {
          executed.push("list");
          return { ok: 1 };
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
    sandbox: {},
  } as never);

  const results: Array<{ toolCallId: string; result: unknown }> = [];
  const approvals: string[] = [];
  agent.eventBus.on("tool-result", (e) =>
    results.push({ toolCallId: e.toolCallId, result: e.result }),
  );
  agent.eventBus.on("tool-approval-request", (e) =>
    approvals.push(e.toolCallId),
  );

  await agent.consume();

  expect(approvals).toEqual(["c2"]);
  expect(executed).toEqual(["list"]);
  expect(results.map((r) => r.toolCallId)).toEqual(["c1"]);
  expect(JSON.stringify(results)).not.toContain("did not complete");
});
