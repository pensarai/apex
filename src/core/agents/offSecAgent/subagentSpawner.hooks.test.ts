import type { LanguageModelMiddleware } from "ai";
import { afterEach, describe, expect, it, vi } from "vitest";

// Captured constructor/fn inputs from the mocked child entrypoints.
const mocks = vi.hoisted(() => ({
  reconInput: undefined as Record<string, unknown> | undefined,
  authInput: undefined as Record<string, unknown> | undefined,
  judgeInput: undefined as unknown,
  judgeCtx: undefined as Record<string, unknown> | undefined,
  pentestInput: undefined as Record<string, unknown> | undefined,
}));

// runSpawnedPentestWorker does: await import("../specialized/pentest/agent")
vi.mock("../specialized/pentest/agent", () => ({
  TargetedPentestAgent: vi.fn((input: Record<string, unknown>) => {
    mocks.pentestInput = input;
    return {
      consume: async () => ({ findings: [] }),
      drained: Promise.resolve(),
    };
  }),
}));

vi.mock("../specialized/reconWorker/agent", () => ({
  ReconWorkerAgent: class {
    constructor(input: Record<string, unknown>) {
      mocks.reconInput = input;
    }
    async consume() {}
  },
}));

// runAuthChild does: await import("../specialized/authenticationAgent/agent")
vi.mock("../specialized/authenticationAgent/agent", () => ({
  runAuthenticationAgent: vi.fn(async (input: Record<string, unknown>) => {
    mocks.authInput = input;
    return { success: true, summary: "ok" };
  }),
}));

// runJudgeChild does: await import("../specialized/findingJudge")
vi.mock("../specialized/findingJudge", () => ({
  judgeFinding: vi.fn(async (input: unknown, ctx: Record<string, unknown>) => {
    mocks.judgeInput = input;
    mocks.judgeCtx = ctx;
    return { verdict: "confirmed" };
  }),
}));

import type { AIModel, UsageRecorder } from "../../ai";
import { AgentEventBus } from "../../eventBus";
import type { SessionInfo } from "../../session";
import { inProcessSubagentSpawner } from "./subagentSpawner";
import type { StreamIdFactory, ToolExecutionContext } from "./types";

// Sentinels: only referential identity is asserted, so shapes are irrelevant.
const middleware = { __sentinel: "mw" } as unknown as LanguageModelMiddleware;
const usageRecorder = { __sentinel: "usage" } as unknown as UsageRecorder;
const streamIdFactory = (() => "sid") as unknown as StreamIdFactory;

const toolExecutionContext: ToolExecutionContext = {
  run: (_call, execute) => execute(),
};

const runtime = {
  session: {} as SessionInfo,
  model: "test-model" as AIModel,
  toolProtocol: "direct" as const,
  languageModelMiddleware: middleware,
  usageRecorder,
  streamIdFactory,
  toolExecutionContext,
};

afterEach(() => {
  mocks.authInput = undefined;
  mocks.judgeInput = undefined;
  mocks.judgeCtx = undefined;
  mocks.pentestInput = undefined;
  vi.clearAllMocks();
});

describe("subagentSpawner durable-hook forwarding", () => {
  it("forwards durability hooks through runAuthChild", async () => {
    await inProcessSubagentSpawner.spawn({
      spec: { type: "authentication", target: "https://example.com" },
      runtime,
      parentBus: new AgentEventBus(),
      subagentId: "auth-child",
    });

    expect(mocks.authInput?.languageModelMiddleware).toBe(middleware);
    expect(mocks.authInput?.usageRecorder).toBe(usageRecorder);
    expect(mocks.authInput?.streamIdFactory).toBe(streamIdFactory);
    expect(mocks.authInput?.toolExecutionContext).toBe(toolExecutionContext);
    expect(mocks.authInput?.toolProtocol).toBe("direct");
  });

  it("forwards the parent tool protocol through runReconWorkerChild", async () => {
    await inProcessSubagentSpawner.spawn({
      spec: { type: "recon-worker", goal: "inspect controls" },
      runtime,
      parentBus: new AgentEventBus(),
      subagentId: "recon-child",
    });
    expect(mocks.reconInput?.toolProtocol).toBe("direct");
  });

  it("forwards durability hooks through runJudgeChild", async () => {
    await inProcessSubagentSpawner.spawn({
      spec: {
        type: "finding-judge",
        // judgeFinding is mocked; its input shape is not validated here.
        judgeInput: {} as never,
        target: "https://example.com",
      },
      runtime,
      parentBus: new AgentEventBus(),
      subagentId: "judge-child",
    });

    // Judge hooks ride the SECOND arg (FindingJudgeRuntimeContext), not judgeInput.
    expect(mocks.judgeCtx?.languageModelMiddleware).toBe(middleware);
    expect(mocks.judgeCtx?.usageRecorder).toBe(usageRecorder);
    expect(mocks.judgeCtx?.streamIdFactory).toBe(streamIdFactory);
    expect(mocks.judgeCtx?.toolExecutionContext).toBe(toolExecutionContext);
    expect(mocks.judgeCtx?.toolProtocol).toBe("direct");
  });

  it("gives a spawned pentest worker the parent's callbacks reader", async () => {
    const callbacks = { domains: ["cb.example.net"], readHits: vi.fn() };
    const spawned = await inProcessSubagentSpawner.spawn({
      spec: {
        type: "pentest",
        target: "https://example.com",
        objectives: [],
        role: "worker",
      },
      runtime: { ...runtime, callbacks },
      parentBus: new AgentEventBus(),
      subagentId: "pentest-worker",
    });
    expect(spawned).toBeDefined();
    expect(mocks.pentestInput?.callbacks).toBe(callbacks);
  });

  it("gives the finding judge the parent's callbacks reader", async () => {
    const callbacks = { domains: ["cb.example.net"], readHits: vi.fn() };
    await inProcessSubagentSpawner.spawn({
      spec: {
        type: "finding-judge",
        judgeInput: {} as never,
        target: "https://example.com",
      },
      runtime: { ...runtime, callbacks },
      parentBus: new AgentEventBus(),
      subagentId: "judge-callbacks",
    });
    expect(mocks.judgeCtx?.callbacks).toBe(callbacks);
  });

  it("passes the hooks through as unset when the runtime omits them", async () => {
    await inProcessSubagentSpawner.spawn({
      spec: { type: "authentication", target: "https://example.com" },
      runtime: {
        session: {} as SessionInfo,
        model: "test-model" as AIModel,
      },
      parentBus: new AgentEventBus(),
      subagentId: "auth-child-bare",
    });

    expect(mocks.authInput?.languageModelMiddleware).toBeUndefined();
    expect(mocks.authInput?.usageRecorder).toBeUndefined();
    expect(mocks.authInput?.streamIdFactory).toBeUndefined();
    expect(mocks.authInput?.toolExecutionContext).toBeUndefined();
  });
});
