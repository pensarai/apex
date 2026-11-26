import type { LanguageModelV3StreamPart } from "@ai-sdk/provider";
import { simulateReadableStream, stepCountIs, tool } from "ai";
import { MockLanguageModelV3 } from "ai/test";
import { describe, expect, it, vi } from "vitest";
import { z } from "zod";
import { AgentEventBus } from "../eventBus";

const state: { model?: MockLanguageModelV3 } = {};
vi.mock("./utils", async () => ({
  ...(await vi.importActual<typeof import("./utils")>("./utils")),
  getProviderModel: () => state.model,
}));
const { streamResponse } = await import("./ai");

const MODEL = "claude-haiku-4-5";
const usage = {
  inputTokens: { total: 1, noCache: 1, cacheRead: 0, cacheWrite: 0 },
  outputTokens: { total: 1, text: 1, reasoning: undefined },
};
const finish = (unified: "stop" | "tool-calls"): LanguageModelV3StreamPart => ({
  type: "finish",
  finishReason: { unified, raw: unified },
  usage,
});

const toolCallsStep: LanguageModelV3StreamPart[] = [
  { type: "stream-start", warnings: [] },
  { type: "tool-call", toolCallId: "c1", toolName: "read", input: '{"a":"x"}' },
  {
    type: "tool-call",
    toolCallId: "c2",
    toolName: "del",
    input: '{"id":"app1"}',
  },
  finish("tool-calls"),
];
const textStep: LanguageModelV3StreamPart[] = [
  { type: "stream-start", warnings: [] },
  { type: "text-start", id: "t" },
  { type: "text-delta", id: "t", delta: "done" },
  { type: "text-end", id: "t" },
  finish("stop"),
];

function setup() {
  const executed: string[] = [];
  const tools = {
    read: tool({
      description: "read",
      inputSchema: z.object({ a: z.string() }),
      execute: async () => {
        executed.push("read");
        return { ok: 1 };
      },
    }),
    del: tool({
      description: "delete",
      inputSchema: z.object({ id: z.string() }),
      needsApproval: true,
      execute: async () => {
        executed.push("del");
        return { deleted: 1 };
      },
    }),
  };
  const bus = new AgentEventBus();
  const events: Array<{
    kind: string;
    toolCallId: string;
    toolName: string;
  }> = [];
  for (const kind of [
    "tool-result",
    "tool-approval-request",
    "tool-output-denied",
  ] as const) {
    bus.on(kind, (e) =>
      events.push({ kind, toolCallId: e.toolCallId, toolName: e.toolName }),
    );
  }
  let approvalId: string | undefined;
  bus.on("tool-approval-request", (e) => {
    approvalId = e.approvalId;
  });

  const drive = async (model: MockLanguageModelV3, messages: unknown[]) => {
    state.model = model;
    events.length = 0;
    const result = streamResponse({
      prompt: "",
      messages,
      model: MODEL,
      tools,
      stopWhen: stepCountIs(5),
      silent: true,
    } as unknown as Parameters<typeof streamResponse>[0]);
    for await (const chunk of result.fullStream) bus.emitStreamPart(chunk);
    return (await result.response).messages;
  };
  const mock = (chunks: LanguageModelV3StreamPart[]) =>
    new MockLanguageModelV3({
      provider: "mock",
      modelId: MODEL,
      doStream: async () => ({ stream: simulateReadableStream({ chunks }) }),
    });
  return { executed, events, drive, mock, getApprovalId: () => approvalId };
}

const user = { role: "user", content: "go" };
const approvalResponse = (
  approvalId: string | undefined,
  approved: boolean,
) => ({
  role: "tool",
  content: [{ type: "tool-approval-response", approvalId, approved }],
});

describe("tool approval through streamResponse and the event bus", () => {
  it("runs the read tool, holds the approval tool, and stops", async () => {
    const t = setup();
    await t.drive(t.mock(toolCallsStep), [user]);
    expect(t.executed).toEqual(["read"]);
    expect(t.events).toEqual([
      { kind: "tool-result", toolCallId: "c1", toolName: "read" },
      { kind: "tool-approval-request", toolCallId: "c2", toolName: "del" },
    ]);
    expect(t.getApprovalId()).toBeTruthy();
  });

  it("executes the held tool once approved", async () => {
    const t = setup();
    const held = await t.drive(t.mock(toolCallsStep), [user]);
    t.executed.length = 0;
    await t.drive(t.mock(textStep), [
      user,
      ...held,
      approvalResponse(t.getApprovalId(), true),
    ]);
    expect(t.executed).toEqual(["del"]);
    expect(t.events).toEqual([
      { kind: "tool-result", toolCallId: "c2", toolName: "del" },
    ]);
  });

  it("emits tool-output-denied and does not execute when denied", async () => {
    const t = setup();
    const held = await t.drive(t.mock(toolCallsStep), [user]);
    t.executed.length = 0;
    await t.drive(t.mock(textStep), [
      user,
      ...held,
      approvalResponse(t.getApprovalId(), false),
    ]);
    expect(t.executed).toEqual([]);
    expect(t.events).toEqual([
      { kind: "tool-output-denied", toolCallId: "c2", toolName: "del" },
    ]);
  });
});
