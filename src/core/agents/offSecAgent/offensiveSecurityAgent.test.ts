/**
 * Unit tests for OffensiveSecurityAgent.consume().
 *
 * Verifies that persistentShell.dispose() is called even when the
 * fullStream throws — the shell-leak bug described in the PR.
 *
 * Heavy transitive dependencies (tools, AI SDK, zod) are stubbed so
 * the test loads cleanly without external provider keys.
 */
import { describe, expect, it, vi } from "vitest";

// ---------------------------------------------------------------------------
// Module stubs — prevent the full tool/AI/zod import chain from loading.
//
// vi.mock factories are hoisted above all imports, so they cannot
// reference top-level variables. All helper logic must be inlined.
// ---------------------------------------------------------------------------

vi.mock("zod", () => {
  const handler: ProxyHandler<CallableFunction> = {
    get(_target, _prop) {
      return new Proxy(() => {}, handler);
    },
    apply(_target, _thisArg, _args) {
      return new Proxy(() => {}, handler);
    },
  };
  const z = new Proxy(() => {}, handler);
  return { z, default: z };
});

vi.mock("./tools", () => ({
  createAllTools: () => ({}),
  EMAIL_TOOL_NAMES_ACTIVE: [],
  SEND_EMAIL_TOOL_NAME: "send_email",
  PLAN_MODE_TOOL_NAMES: [],
  createResponseTool: () => {},
  RESPONSE_TOOL_NAME: "response",
  ASK_USER_QUESTIONS_TOOL_NAME: "ask_user_questions",
  PersistentShell: class {},
}));
vi.mock("../../ai", () => ({ streamResponse: () => {} }));
vi.mock("../../session", () => ({ create: () => {} }));
vi.mock("../specialized/utils", () => ({
  detectOSAndEnhancePrompt: (p: string) => p,
}));
vi.mock("./prompt", () => ({
  buildBaseSystemPrompt: () => "system",
  buildSessionWorkspaceSection: () => "",
}));
vi.mock("./trace", () => ({
  StepTraceWriter: class {
    onStepFinish() {}
  },
}));
vi.mock("../../operator", () => ({
  ApprovalDeniedError: class extends Error {},
}));
vi.mock("ai", () => ({ hasToolCall: () => () => false }));

import { AgentEventBus } from "../../eventBus";
import { OffensiveSecurityAgent } from "./offensiveSecurityAgent";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * Builds a minimal OffensiveSecurityAgent with mocked internals.
 *
 * Bypasses the constructor (which needs a real session, model, tools, etc.)
 * via Object.create so we can unit-test consume() in isolation.
 */
function buildStubAgent(overrides: {
  fullStream: AsyncIterable<unknown>;
  persistentShell?: { dispose: () => void };
  abortSignal?: AbortSignal;
  resolveResult?: (sr: unknown) => unknown;
}): OffensiveSecurityAgent<unknown> {
  const agent = Object.create(
    OffensiveSecurityAgent.prototype,
  ) as OffensiveSecurityAgent<unknown>;

  const bus = new AgentEventBus();
  vi.spyOn(bus, "emitStreamPart").mockImplementation(() => {});

  Object.defineProperty(agent, "eventBus", { value: bus });
  Object.defineProperty(agent, "streamResult", {
    value: { fullStream: overrides.fullStream },
  });
  Object.defineProperty(agent, "subagentId", { value: undefined });
  Object.defineProperty(agent, "persistentShell", {
    value: overrides.persistentShell,
  });
  Object.defineProperty(agent, "abortSignal", {
    value: overrides.abortSignal,
  });
  Object.defineProperty(agent, "resolveResult", {
    value: overrides.resolveResult,
  });

  return agent;
}

async function* yieldChunks(
  chunks: unknown[],
): AsyncGenerator<unknown, void, undefined> {
  for (const c of chunks) yield c;
}

async function* yieldThenThrow(
  chunks: unknown[],
  error: Error,
): AsyncGenerator<unknown, void, undefined> {
  for (const c of chunks) yield c;
  throw error;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe("OffensiveSecurityAgent.consume()", () => {
  const textDelta = { type: "text-delta", text: "hi" };

  describe("persistentShell disposal on stream error (leak fix)", () => {
    it("disposes shell after a successful stream", async () => {
      const dispose = vi.fn();
      const agent = buildStubAgent({
        fullStream: yieldChunks([textDelta]),
        persistentShell: { dispose },
      });

      await agent.consume();
      expect(dispose).toHaveBeenCalledOnce();
    });

    it("disposes shell when the stream throws mid-iteration", async () => {
      const dispose = vi.fn();
      const agent = buildStubAgent({
        fullStream: yieldThenThrow([textDelta], new Error("stream exploded")),
        persistentShell: { dispose },
      });

      await expect(agent.consume()).rejects.toThrow("stream exploded");
      expect(dispose).toHaveBeenCalledOnce();
    });

    it("disposes shell when the stream throws immediately (no chunks)", async () => {
      const dispose = vi.fn();
      const agent = buildStubAgent({
        fullStream: yieldThenThrow([], new Error("instant failure")),
        persistentShell: { dispose },
      });

      await expect(agent.consume()).rejects.toThrow("instant failure");
      expect(dispose).toHaveBeenCalledOnce();
    });

    it("disposes shell when emitStreamPart throws", async () => {
      const dispose = vi.fn();
      const agent = buildStubAgent({
        fullStream: yieldChunks([textDelta]),
        persistentShell: { dispose },
      });

      vi.spyOn(agent.eventBus, "emitStreamPart").mockImplementation(() => {
        throw new Error("bus emit failed");
      });

      await expect(agent.consume()).rejects.toThrow("bus emit failed");
      expect(dispose).toHaveBeenCalledOnce();
    });
  });

  describe("no-shell scenarios (sandbox mode)", () => {
    it("succeeds without shell when stream completes normally", async () => {
      const agent = buildStubAgent({
        fullStream: yieldChunks([textDelta]),
        persistentShell: undefined,
      });

      await expect(agent.consume()).resolves.toBeUndefined();
    });

    it("propagates stream error without shell (no dispose to call)", async () => {
      const agent = buildStubAgent({
        fullStream: yieldThenThrow([], new Error("sandbox boom")),
        persistentShell: undefined,
      });

      await expect(agent.consume()).rejects.toThrow("sandbox boom");
    });
  });

  describe("disposal ordering", () => {
    it("disposes shell before resolveResult runs", async () => {
      const callOrder: string[] = [];

      const dispose = vi.fn(() => callOrder.push("dispose"));
      const resolveResult = vi.fn(() => {
        callOrder.push("resolveResult");
        return "result";
      });

      const agent = buildStubAgent({
        fullStream: yieldChunks([textDelta]),
        persistentShell: { dispose },
        resolveResult,
      });

      const result = await agent.consume();
      expect(result).toBe("result");
      expect(dispose).toHaveBeenCalledOnce();
      expect(resolveResult).toHaveBeenCalledOnce();
      expect(callOrder).toEqual(["dispose", "resolveResult"]);
    });
  });

  describe("abort signal", () => {
    it("disposes shell even when abort signal causes throw", async () => {
      const controller = new AbortController();
      controller.abort();

      const dispose = vi.fn();
      const agent = buildStubAgent({
        fullStream: yieldChunks([textDelta]),
        persistentShell: { dispose },
        abortSignal: controller.signal,
      });

      await expect(agent.consume()).rejects.toThrow("Agent aborted by user");
      expect(dispose).toHaveBeenCalledOnce();
    });
  });

  describe("resolveResult", () => {
    it("returns resolved value when resolveResult is provided", async () => {
      const agent = buildStubAgent({
        fullStream: yieldChunks([textDelta]),
        resolveResult: () => 42,
      });

      const result = await agent.consume();
      expect(result).toBe(42);
    });

    it("returns undefined when resolveResult is absent", async () => {
      const agent = buildStubAgent({
        fullStream: yieldChunks([textDelta]),
      });

      const result = await agent.consume();
      expect(result).toBeUndefined();
    });
  });
});
