/**
 * Unit tests for OffensiveSecurityAgent.consume().
 *
 * Verifies that persistentShell.dispose() is called even when the
 * fullStream throws — the shell-leak bug described in the PR.
 *
 * Heavy transitive dependencies (tools, AI SDK, zod) are stubbed so
 * the test loads cleanly without external provider keys.
 */
import { mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
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
  messagesPath?: string | null;
  latestMessages?: unknown[] | null;
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
  Object.defineProperty(agent, "latestMessages", {
    value: overrides.latestMessages ?? null,
    writable: true,
  });
  Object.defineProperty(agent, "messagesPath", {
    value: overrides.messagesPath ?? null,
  });
  Object.defineProperty(agent, "cancelPersistTimer", { value: () => {} });
  Object.defineProperty(agent, "syntheticsPersisted", {
    value: false,
    writable: true,
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

  describe("synthetic tool-result on stream abort/error", () => {
    const toolCallChunk = {
      type: "tool-call",
      toolCallId: "tc1",
      toolName: "execute_command",
    };

    it("emits synthetic tool-result for in-flight tool when stream throws", async () => {
      const agent = buildStubAgent({
        fullStream: yieldThenThrow(
          [toolCallChunk],
          new Error("connection reset"),
        ),
      });

      const emittedResults: Array<{ toolCallId: string; result: unknown }> = [];
      agent.eventBus.on("tool-result", (e) => {
        emittedResults.push({ toolCallId: e.toolCallId, result: e.result });
      });

      await expect(agent.consume()).rejects.toThrow("connection reset");

      expect(emittedResults).toHaveLength(1);
      expect(emittedResults[0].toolCallId).toBe("tc1");
      expect(emittedResults[0].result).toMatchObject({
        type: "error-text",
        value: expect.stringContaining("connection reset"),
      });
    });

    it("does not emit synthetic when tool-result already streamed", async () => {
      const toolResultChunk = {
        type: "tool-result",
        toolCallId: "tc1",
        result: { type: "text", value: "done" },
      };
      const agent = buildStubAgent({
        fullStream: yieldChunks([toolCallChunk, toolResultChunk]),
      });

      const emittedResults: unknown[] = [];
      agent.eventBus.on("tool-result", (e) => emittedResults.push(e));

      await agent.consume();
      expect(emittedResults).toHaveLength(0);
    });

    it("closes a truncated tool-call (started, args never completed) at finish-step", async () => {
      const agent = buildStubAgent({
        fullStream: yieldChunks([
          { type: "tool-input-start", id: "tc1", toolName: "response" },
          { type: "finish-step" },
        ]),
      });

      const emittedResults: Array<{ toolCallId: string; result: unknown }> = [];
      agent.eventBus.on("tool-result", (e) => {
        emittedResults.push({ toolCallId: e.toolCallId, result: e.result });
      });

      await agent.consume();

      expect(emittedResults).toHaveLength(1);
      expect(emittedResults[0].toolCallId).toBe("tc1");
      expect(emittedResults[0].result).toMatchObject({ type: "error-text" });
    });

    it("uses 'Agent aborted by user' when abortSignal is set", async () => {
      const controller = new AbortController();
      controller.abort();

      const agent = buildStubAgent({
        fullStream: yieldThenThrow(
          [toolCallChunk],
          new DOMException("Aborted", "AbortError"),
        ),
        abortSignal: controller.signal,
      });

      const emittedResults: Array<{ result: unknown }> = [];
      agent.eventBus.on("tool-result", (e) =>
        emittedResults.push({ result: e.result }),
      );

      await expect(agent.consume()).rejects.toBeInstanceOf(DOMException);

      expect(emittedResults[0].result).toMatchObject({
        type: "error-text",
        value: expect.stringContaining("aborted by user"),
      });
    });

    it("propagates original stream error when event listener throws", async () => {
      const agent = buildStubAgent({
        fullStream: yieldThenThrow(
          [toolCallChunk],
          new Error("original error"),
        ),
      });

      agent.eventBus.on("tool-result", () => {
        throw new Error("listener explosion");
      });

      await expect(agent.consume()).rejects.toThrow("original error");
    });

    it("persists synthetic results to messages.json", async () => {
      const tmpDir = join("/tmp", `pensar-test-${Date.now()}-persist`);
      mkdirSync(tmpDir, { recursive: true });
      const messagesPath = join(tmpDir, "messages.json");

      const existingMessages = [
        { role: "user", content: [{ type: "text", text: "run nmap" }] },
      ];
      writeFileSync(messagesPath, JSON.stringify(existingMessages));

      const agent = buildStubAgent({
        fullStream: yieldThenThrow([toolCallChunk], new Error("timeout")),
        messagesPath,
        latestMessages: null,
      });

      try {
        await agent.consume();
      } catch {}
      await new Promise((r) => setTimeout(r, 50));

      const written = JSON.parse(readFileSync(messagesPath, "utf-8"));
      expect(written.length).toBeGreaterThan(1);
      expect(written[0].role).toBe("user");
      const toolMsg = written.find((m: { role: string }) => m.role === "tool");
      expect(toolMsg).toBeDefined();
      expect(toolMsg.content[0].output.type).toBe("error-text");

      rmSync(tmpDir, { recursive: true, force: true });
    });

    it("includes completed parallel tool results on abort", async () => {
      const tmpDir = join("/tmp", `pensar-test-${Date.now()}-parallel`);
      mkdirSync(tmpDir, { recursive: true });
      const messagesPath = join(tmpDir, "messages.json");
      writeFileSync(
        messagesPath,
        JSON.stringify([
          { role: "user", content: [{ type: "text", text: "scan" }] },
        ]),
      );

      const toolCallA = {
        type: "tool-call",
        toolCallId: "tcA",
        toolName: "read_file",
      };
      const toolCallB = {
        type: "tool-call",
        toolCallId: "tcB",
        toolName: "execute_command",
      };
      const toolResultA = {
        type: "tool-result",
        toolCallId: "tcA",
        toolName: "read_file",
        result: { type: "text", value: "file contents" },
      };

      const agent = buildStubAgent({
        fullStream: yieldThenThrow(
          [toolCallA, toolCallB, toolResultA],
          new Error("connection lost"),
        ),
        messagesPath,
        latestMessages: null,
      });

      try {
        await agent.consume();
      } catch {}
      await new Promise((r) => setTimeout(r, 50));

      const written = JSON.parse(readFileSync(messagesPath, "utf-8"));
      const toolMsg = written.find((m: { role: string }) => m.role === "tool");
      expect(toolMsg.content).toHaveLength(2);
      const ids = toolMsg.content
        .map((c: { toolCallId: string }) => c.toolCallId)
        .sort();
      expect(ids).toEqual(["tcA", "tcB"]);

      rmSync(tmpDir, { recursive: true, force: true });
    });
  });
});
