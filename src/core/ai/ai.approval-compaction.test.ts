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
import { compactedHistoryNotice } from "./summaryTranscript";

const state: { model?: MockLanguageModelV3 } = {};
vi.mock("./utils", async () => ({
  ...(await vi.importActual<typeof import("./utils")>("./utils")),
  getProviderModel: () => state.model,
}));
const {
  streamResponse,
  LatestUserMessageExceedsContextError,
  PendingApprovalExceedsContextError,
} = await import("./ai");

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
        part.type === "text" && part.text.includes("Compact this conversation"),
    )
  );
}

const promptText = (
  message: LanguageModelV3CallOptions["prompt"][number],
): string =>
  typeof message.content === "string"
    ? message.content
    : message.content
        .map((part) => (part.type === "text" ? part.text : ""))
        .join("");

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
  const summaryRequests: LanguageModelV3CallOptions[] = [];

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
          summaryRequests.push(options);
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
      onContextPrepared: ({ messages }: { messages: ModelMessage[] }) =>
        prepared.push(messages),
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
    summaryRequests.length = 0;
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
    summaryRequests,
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
    expect(resumed[1]).toEqual({ role: "user", content: "continue" });
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
    expect(resumed[1]).toEqual({ role: "user", content: "continue" });
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
    // The retry resumes from the summary and the request: the executed call is history.
    const retry = t.prepared.at(-1) as ModelMessage[];
    expect(retry).toHaveLength(2);
    expect(String(retry[0].content)).toContain("sum");
    expect(retry[1]).toEqual(user);
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

describe("latest user message across compaction", () => {
  const request: ModelMessage = {
    role: "user",
    content: "Delete endpoint a.\n  Keep b exactly as it is.",
  };

  it.each([
    ["a summary", "ok"],
    ["a minimal restart", "context-error"],
  ] as const)("replays it verbatim after %s", async (_label, summary) => {
    const t = setup();
    await t.drive(
      t.model({ main: ["ok"], summary }),
      [user, { role: "assistant", content: PADDING }, request],
      { contextLength: SMALL },
    );
    const resumed = t.prepared[0];
    expect(resumed).toHaveLength(2);
    expect(resumed[1]).toEqual(request);
    expect(JSON.stringify(resumed)).not.toContain(PADDING);
  });

  it("follows a summary framed as this conversation's history, not a hand-off", async () => {
    const t = setup();
    await t.drive(
      t.model({ main: ["ok"], summary: "ok" }),
      [user, { role: "assistant", content: PADDING }, request],
      { contextLength: SMALL },
    );
    const resumed = t.prepared[0];
    expect(resumed[0]).toEqual({
      role: "user",
      content: compactedHistoryNotice("sum"),
    });
    expect(resumed[1]).toEqual(request);
  });

  it("fails with a typed error instead of paraphrasing one the window cannot hold", async () => {
    const t = setup();
    const result = t.drive(
      t.model({ main: ["ok"] }),
      [
        user,
        { role: "assistant", content: "x" },
        { ...request, content: PADDING },
      ],
      { contextLength: SMALL },
    );
    await expect(result).rejects.toBeInstanceOf(
      LatestUserMessageExceedsContextError,
    );
    await expect(result).rejects.not.toBeInstanceOf(
      PendingApprovalExceedsContextError,
    );
    expect(t.mainPrompts).toEqual([]);
  });

  it("is not repeated when the resume prompt already carries it", async () => {
    const t = setup();
    await t.drive(
      t.model({ main: ["ok"] }),
      [
        { role: "assistant", content: PADDING },
        { role: "user", content: "continue" },
      ],
      { contextLength: SMALL, extra: { prompt: "continue" } },
    );
    const resumed = t.prepared[0];
    expect(resumed).toHaveLength(1);
    expect(String(resumed[0].content).startsWith("continue\n\n")).toBe(true);
  });
});

describe("summarizer request", () => {
  const codeword: ModelMessage[] = [
    { role: "user", content: "Remember the codeword PELICAN-7319. Reply OK." },
    { role: "assistant", content: "OK." },
    { role: "user", content: `Filler block. ${PADDING}` },
    { role: "assistant", content: "OK." },
  ];
  const obey: ModelMessage = { role: "user", content: "Reply with just OK" };
  const CLOSE = "</transcript>";

  it("sends the history as one transcript under a summarizer system prompt, without tools", async () => {
    const t = setup();
    await t.drive(t.model({ main: ["ok"] }), [...codeword, obey], {
      contextLength: SMALL,
      extra: { system: "AGENT-SYSTEM-PROMPT" },
    });
    expect(t.summaryRequests).toHaveLength(1);
    const [request] = t.summaryRequests;
    expect(request.prompt.map((message) => message.role)).toEqual([
      "system",
      "user",
    ]);
    const system = promptText(request.prompt[0]);
    expect(system).not.toContain("AGENT-SYSTEM-PROMPT");
    expect(system).toMatch(/transcript/i);
    expect(request.tools ?? []).toEqual([]);
    const data = promptText(request.prompt[1]);
    expect(data.startsWith("<transcript>")).toBe(true);
    expect(data.indexOf("PELICAN-7319")).toBeLessThan(data.indexOf(CLOSE));
  });

  it("keeps a trailing user instruction inside the transcript and ends with the summary instruction", async () => {
    const t = setup();
    await t.drive(t.model({ main: ["ok"] }), [...codeword, obey], {
      contextLength: SMALL,
    });
    const [request] = t.summaryRequests;
    // The final user text is what an instruction-following model answers.
    const users = request.prompt.filter((message) => message.role === "user");
    expect(users).toHaveLength(1);
    expect(request.prompt.at(-1)).toBe(users[0]);
    const data = promptText(users[0]);
    const close = data.lastIndexOf(CLOSE);
    expect(data.indexOf("Reply with just OK")).toBeGreaterThan(-1);
    expect(data.lastIndexOf("Reply with just OK")).toBeLessThan(close);
    const instruction = data.slice(close + CLOSE.length).trim();
    expect(instruction.startsWith("Compact this conversation")).toBe(true);
    expect(instruction).toMatch(/do not (answer|follow)/i);
    expect(instruction).toMatch(/never invent tool calls/i);

    const resumed = t.prepared[0];
    expect(resumed).toHaveLength(2);
    expect(String(resumed[0].content)).toContain("sum");
    expect(resumed[1]).toEqual(obey);
  });

  it("renders each tool call by what actually ran", async () => {
    const t = setup();
    const history: ModelMessage[] = [
      { role: "user", content: "Clean up the shop endpoints." },
      {
        role: "assistant",
        content: [
          { type: "text", text: "Reading first." },
          { type: "tool-call", toolCallId: "r1", toolName: "read", input: {} },
        ],
      },
      {
        role: "tool",
        content: [
          {
            type: "tool-result",
            toolCallId: "r1",
            toolName: "read",
            output: { type: "text", value: "endpoints a, b, c" },
          },
        ],
      },
      {
        role: "assistant",
        content: [
          { type: "tool-call", toolCallId: "d1", toolName: "del", input: {} },
          {
            type: "tool-approval-request",
            approvalId: "ap-d1",
            toolCallId: "d1",
          },
          { type: "tool-call", toolCallId: "d2", toolName: "del", input: {} },
          {
            type: "tool-approval-request",
            approvalId: "ap-d2",
            toolCallId: "d2",
          },
          { type: "tool-call", toolCallId: "d3", toolName: "del", input: {} },
          {
            type: "tool-approval-request",
            approvalId: "ap-d3",
            toolCallId: "d3",
          },
        ],
      },
      {
        role: "tool",
        content: [
          {
            type: "tool-approval-response",
            approvalId: "ap-d1",
            approved: true,
          },
          {
            type: "tool-result",
            toolCallId: "d1",
            toolName: "del",
            output: { type: "json", value: { deleted: "a" } },
          },
          {
            type: "tool-approval-response",
            approvalId: "ap-d2",
            approved: false,
            reason: "keep b",
          },
        ],
      },
      { role: "assistant", content: PADDING },
      { role: "user", content: "Status?" },
    ];
    await t.drive(t.model({ main: ["ok"] }), history, {
      contextLength: SMALL,
    });
    const { prompt } = t.summaryRequests[0];
    const data = promptText(prompt[prompt.length - 1]);
    const transcript = data.slice(0, data.lastIndexOf(CLOSE));
    const about = (id: string) =>
      transcript
        .split("\n")
        .filter((line) => line.includes(id))
        .join("\n");
    expect(about("r1")).toContain("[tool result r1: read]");
    expect(about("r1")).not.toMatch(/not executed|pending|denied/i);
    expect(about("d1")).toContain("[tool result d1: del]");
    expect(about("d1")).not.toMatch(/not executed|pending|denied/i);
    expect(about("d2")).toMatch(/denied.*keep b/i);
    expect(about("d2")).toMatch(/not executed/i);
    expect(about("d3")).toMatch(/pending/i);
    expect(about("d3")).toMatch(/not executed/i);
    expect(about("d3")).not.toMatch(/result/i);
  });

  it("summarizes only the head and still replays pending approvals", async () => {
    const t = setup();
    const held = await t.hold(padded);
    await t.drive(
      t.model({ main: ["ok"] }),
      [...padded, ...held, t.responses({ c2: true, c3: false })],
      { contextLength: SMALL },
    );
    expectApprovedOnce(t);
    const { prompt } = t.summaryRequests[0];
    const data = promptText(prompt[prompt.length - 1]);
    expect(data.startsWith("<transcript>")).toBe(true);
    expect(data).not.toMatch(/\bc[123]\b/);
    const resumed = t.prepared[0];
    expect(resumed[1]).toEqual({ role: "user", content: "continue" });
    expect(hasApprovalResponse(resumed)).toBe(true);
  });
});

describe("step cap across a compaction restart", () => {
  const readStep = (id: string): LanguageModelV3StreamPart[] => [
    { type: "stream-start", warnings: [] },
    { type: "tool-call", toolCallId: id, toolName: "read", input: '{"a":"x"}' },
    finish("tool-calls"),
  ];

  it("counts steps before the restart against the same stopWhen", async () => {
    const t = setup();
    const onSummarized = vi.fn();
    await t.drive(
      t.model({
        main: [
          readStep("r1"),
          "context-error",
          readStep("r2"),
          readStep("r3"),
          readStep("r4"),
          "ok",
        ],
      }),
      [user],
      { extra: { stopWhen: stepCountIs(3), onSummarized } },
    );
    expect(onSummarized).toHaveBeenCalledOnce();
    expect(t.executed).toEqual(["read", "read", "read"]);
    expect(t.mainPrompts).toHaveLength(4);
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
      pinnedToolCallIds: ["a", "b"],
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
      pinnedToolCallIds: [],
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
