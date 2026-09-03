import type { LanguageModelMiddleware } from "ai";
import { afterEach, describe, expect, it, vi } from "vitest";

// Captured constructor/fn inputs from the mocked child entrypoints.
const mocks = vi.hoisted(() => ({
  authInput: undefined as Record<string, unknown> | undefined,
  judgeInput: undefined as unknown,
  judgeCtx: undefined as Record<string, unknown> | undefined,
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
import type { StreamIdFactory } from "./types";

// Sentinels: only referential identity is asserted, so shapes are irrelevant.
const middleware = { __sentinel: "mw" } as unknown as LanguageModelMiddleware;
const usageRecorder = { __sentinel: "usage" } as unknown as UsageRecorder;
const streamIdFactory = (() => "sid") as unknown as StreamIdFactory;

const runtime = {
  session: {} as SessionInfo,
  model: "test-model" as AIModel,
  languageModelMiddleware: middleware,
  usageRecorder,
  streamIdFactory,
};

afterEach(() => {
  mocks.authInput = undefined;
  mocks.judgeInput = undefined;
  mocks.judgeCtx = undefined;
  vi.clearAllMocks();
});

describe("subagentSpawner durable-hook forwarding", () => {
  it("forwards middleware/usageRecorder/streamIdFactory through runAuthChild", async () => {
    await inProcessSubagentSpawner.spawn({
      spec: { type: "authentication", target: "https://example.com" },
      runtime,
      parentBus: new AgentEventBus(),
      subagentId: "auth-child",
    });

    expect(mocks.authInput?.languageModelMiddleware).toBe(middleware);
    expect(mocks.authInput?.usageRecorder).toBe(usageRecorder);
    expect(mocks.authInput?.streamIdFactory).toBe(streamIdFactory);
  });

  it("forwards middleware/usageRecorder/streamIdFactory through runJudgeChild", async () => {
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
  });
});
