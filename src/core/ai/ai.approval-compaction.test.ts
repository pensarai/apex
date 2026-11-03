import type {
  LanguageModelV3CallOptions,
  LanguageModelV3StreamPart,
} from "@ai-sdk/provider";
import {
  type ModelMessage,
  simulateReadableStream,
  stepCountIs,
  tool,
} from "ai";
import { MockLanguageModelV3 } from "ai/test";
import { describe, expect, it, vi } from "vitest";
import { z } from "zod";
import { AgentEventBus } from "../eventBus";
import { splitPendingApprovals } from "./contextManagement";

const state: { model?: MockLanguageModelV3 } = {};
vi.mock("./utils", async () => ({
  ...(await vi.importActual<typeof import("./utils")>("./utils")),
  getProviderModel: () => state.model,
}));
const { streamResponse, PendingApprovalExceedsContextError } = await import(
  "./ai"
);

const MODEL = "custom:fx:m";
const customProviders = (contextLength: number) => ({
  fx: {
    baseUrl: "https://example.invalid/v1",
    models: [{ id: "m", contextLength, maxOutputTokens: 2_000 }],
  },
});
const LARGE = 200_000;
const SMALL = 20_000;
const PADDING = "p".repeat(100_000);
const CONTEXT_ERROR = "prompt is too long: 300000 tokens > 200000 maximum";

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
const heldStep: LanguageModelV3StreamPart[] = [
  { type: "stream-start", warnings: [] },
  { type: "tool-call", toolCallId: "c1", toolName: "read", input: '{"a":"x"}' },
  { type: "tool-call", toolCallId: "c2", toolName: "del", input: '{"id":"a"}' },
  { type: "tool-call", toolCallId: "c3", toolName: "del", input: '{"id":"b"}' },
  finish("tool-calls"),
];

type Behavior = "ok" | "context-error";

function isSummaryCall(options: LanguageModelV3CallOptions): boolean {
  const last = options.prompt.at(-1);
  return (
    last?.role === "user" &&
    last.content.some(
      (part) =>
        part.type === "text" &&
        part.text.startsWith("Compact this conversation"),
    )
  );
}

function setup({ readOutput = "ok" }: { readOutput?: string } = {}) {
  const executed: string[] = [];
  const tools = {
    read: tool({
      description: "read",
      inputSchema: z.object({ a: z.string() }),
      execute: async () => {
        executed.push("read");
        return readOutput;
      },
    }),
    del: tool({
      description: "delete",
      inputSchema: z.object({ id: z.string() }),
      needsApproval: true,
      execute: async ({ id }) => {
        executed.push(`del:${id}`);
        return { deleted: id };
      },
    }),
  };
  const bus = new AgentEventBus();
  const events: Array<{ kind: string; toolCallId: string }> = [];
  for (const kind of [
    "tool-result",
    "tool-approval-request",
    "tool-output-denied",
  ] as const) {
    bus.on(kind, (e) => {
      // Compaction surfaces itself as a synthetic tool call.
      if (!e.toolCallId.startsWith("summarize-"))
        events.push({ kind, toolCallId: e.toolCallId });
    });
  }
  const approvalIds = new Map<string, string>();
  bus.on("tool-approval-request", (e) =>
    approvalIds.set(e.toolCallId, e.approvalId),
  );
  const prepared: ModelMessage[][] = [];
  const mainPrompts: LanguageModelV3CallOptions["prompt"][] = [];

  const model = ({
    main,
    summary = "ok",
  }: {
    main: Array<Behavior | LanguageModelV3StreamPart[]>;
    summary?: Behavior;
  }) => {
    const queue = [...main];
    return new MockLanguageModelV3({
      provider: "mock",
      modelId: "m",
      doStream: async (options) => {
        if (isSummaryCall(options)) {
          if (summary === "context-error") throw new Error(CONTEXT_ERROR);
          return { stream: simulateReadableStream({ chunks: text("sum") }) };
        }
        mainPrompts.push(options.prompt);
        const next = queue.shift() ?? "ok";
        if (next === "context-error") throw new Error(CONTEXT_ERROR);
        const chunks = next === "ok" ? text("done") : next;
        return { stream: simulateReadableStream({ chunks }) };
      },
    });
  };

  const drive = async (
    mock: MockLanguageModelV3,
    messages: ModelMessage[],
    { contextLength = LARGE, extra = {} } = {},
  ) => {
    state.model = mock;
    events.length = 0;
    const result = streamResponse({
      prompt: "",
      messages,
      model: MODEL,
      tools,
      stopWhen: stepCountIs(5),
      silent: true,
      authConfig: { customProviders: customProviders(contextLength) },
      onContextPrepared: ({ messages }) => prepared.push(messages),
      ...extra,
    } as unknown as Parameters<typeof streamResponse>[0]);
    for await (const chunk of result.fullStream) bus.emitStreamPart(chunk);
    return (await result.response).messages as ModelMessage[];
  };

  const hold = async (history: ModelMessage[]) => {
    const held = await drive(model({ main: [heldStep] }), history);
    executed.length = 0;
    prepared.length = 0;
    mainPrompts.length = 0;
    return held;
  };

  const responses = (decisions: Record<string, boolean>): ModelMessage => ({
    role: "tool",
    content: Object.entries(decisions).map(([toolCallId, approved]) => ({
      type: "tool-approval-response" as const,
      approvalId: approvalIds.get(toolCallId) as string,
      approved,
    })),
  });

  return {
    executed,
    events,
    prepared,
    mainPrompts,
    model,
    drive,
    hold,
    responses,
  };
}

const user: ModelMessage = { role: "user", content: "go" };
const padded: ModelMessage[] = [
  user,
  { role: "assistant", content: PADDING },
  { role: "user", content: "continue" },
];

const hasApprovalResponse = (messages: ModelMessage[]) =>
  messages.some(
    (m) =>
      m.role === "tool" &&
      m.content.some((p) => p.type === "tool-approval-response"),
  );

function expectApprovedOnce(t: ReturnType<typeof setup>) {
  expect(t.executed).toEqual(["del:a"]);
  expect(t.events.filter((e) => e.kind === "tool-result")).toEqual([
    { kind: "tool-result", toolCallId: "c2" },
  ]);
  expect(t.events.filter((e) => e.kind === "tool-output-denied")).toEqual([
    { kind: "tool-output-denied", toolCallId: "c3" },
  ]);
}

describe("pending approvals across context compaction", () => {
  it("executes the approved call once within a forced Layer 3 summary replay", async () => {
    const t = setup();
    const held = await t.hold(padded);
    await t.drive(
      t.model({ main: ["ok"] }),
      [...padded, ...held, t.responses({ c2: true, c3: false })],
      { contextLength: SMALL },
    );
    expectApprovedOnce(t);
    const resumed = t.prepared[0];
    expect(resumed[0]).toMatchObject({ role: "user" });
    expect(String(resumed[0].content)).toContain("sum");
    expect(String(resumed[0].content)).not.toContain(PADDING);
    expect(hasApprovalResponse(resumed)).toBe(true);
    expect(JSON.stringify(t.mainPrompts[0])).not.toContain(PADDING);
  });

  it("executes the approved call once within a minimal-restart replay", async () => {
    const t = setup();
    const held = await t.hold(padded);
    await t.drive(
      t.model({ main: ["ok"], summary: "context-error" }),
      [...padded, ...held, t.responses({ c2: true, c3: false })],
      { contextLength: SMALL },
    );
    expectApprovedOnce(t);
    const resumed = t.prepared[0];
    expect(String(resumed[0].content)).toContain("Continue the previous task");
    expect(hasApprovalResponse(resumed)).toBe(true);
  });

  it("does not re-execute an approved call when the model call after it overflows", async () => {
    const t = setup();
    const held = await t.hold([user]);
    await t.drive(t.model({ main: ["context-error", "ok"] }), [
      user,
      ...held,
      t.responses({ c2: true, c3: false }),
    ]);
    expectApprovedOnce(t);
    // The retry resumes from the summary alone: the executed call is history.
    const retry = t.prepared.at(-1) as ModelMessage[];
    expect(retry).toHaveLength(1);
    expect(String(retry[0].content)).toContain("sum");
  });

  it("rejects an oversized pending suffix before executing anything", async () => {
    const t = setup({ readOutput: "r".repeat(100_000) });
    const held = await t.hold(padded);
    const result = t.drive(
      t.model({ main: ["ok"] }),
      [...padded, ...held, t.responses({ c2: true, c3: false })],
      { contextLength: SMALL },
    );
    await expect(result).rejects.toBeInstanceOf(
      PendingApprovalExceedsContextError,
    );
    expect(t.executed).toEqual([]);
    expect(t.mainPrompts).toEqual([]);
  });

  it("keeps pending approvals on the primary-model-only path", async () => {
    const t = setup();
    const held = await t.hold(padded);
    await t.drive(
      t.model({ main: ["ok"] }),
      [...padded, ...held, t.responses({ c2: true, c3: false })],
      {
        contextLength: SMALL,
        extra: {
          primaryModelOnly: true,
          runContextCompaction: <T>(work: () => Promise<T>) => work(),
        },
      },
    );
    expectApprovedOnce(t);
    expect(hasApprovalResponse(t.prepared[0])).toBe(true);
  });
});

describe("splitPendingApprovals", () => {
  const call = (id: string) => ({
    type: "tool-call" as const,
    toolCallId: id,
    toolName: "del",
    input: {},
  });
  const request = (id: string) => ({
    type: "tool-approval-request" as const,
    approvalId: `ap-${id}`,
    toolCallId: id,
  });
  const result = (id: string) => ({
    type: "tool-result" as const,
    toolCallId: id,
    toolName: "del",
    output: { type: "text" as const, value: "ok" },
  });
  const response = (id: string, approved = true) => ({
    type: "tool-approval-response" as const,
    approvalId: `ap-${id}`,
    approved,
  });
  const head: ModelMessage[] = [
    { role: "user", content: "go" },
    { role: "assistant", content: "earlier" },
  ];

  it("pins the held step, intervening results and responses", () => {
    const pinned: ModelMessage[] = [
      {
        role: "assistant",
        content: [call("r"), call("a"), request("a"), call("b"), request("b")],
      },
      { role: "tool", content: [result("r")] },
      { role: "tool", content: [response("a"), response("b", false)] },
    ];
    expect(splitPendingApprovals([...head, ...pinned])).toEqual({
      head,
      pinned,
    });
  });

  it("pins from the earliest assistant message holding a pending request", () => {
    const pinned: ModelMessage[] = [
      { role: "assistant", content: [call("a"), request("a")] },
      { role: "tool", content: [response("a")] },
      { role: "assistant", content: [call("b"), request("b")] },
      { role: "tool", content: [response("a"), response("b")] },
    ];
    expect(splitPendingApprovals([...head, ...pinned]).head).toEqual(head);
  });

  it("pins nothing once every approved call has a result", () => {
    const messages: ModelMessage[] = [
      ...head,
      { role: "assistant", content: [call("a"), request("a")] },
      { role: "tool", content: [response("a"), result("a")] },
    ];
    expect(splitPendingApprovals(messages)).toEqual({
      head: messages,
      pinned: [],
    });
  });

  it("pins nothing when the last message is not a tool message", () => {
    const messages: ModelMessage[] = [
      ...head,
      { role: "assistant", content: [call("a"), request("a")] },
      { role: "tool", content: [response("a")] },
      { role: "user", content: "next" },
    ];
    expect(splitPendingApprovals(messages).pinned).toEqual([]);
  });
});
