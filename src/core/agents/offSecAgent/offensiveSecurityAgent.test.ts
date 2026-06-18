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
  browserSession?: { disconnect: () => Promise<void> };
  ownsBrowserSession?: boolean;
  messagesPath?: string | null;
  latestMessages?: unknown[] | null;
  responseCaptured?: Promise<unknown>;
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
  // consume() races the drain against this; default never resolves so the
  // drain (the full-stream path these tests exercise) always wins.
  Object.defineProperty(agent, "responseCaptured", {
    value: overrides.responseCaptured ?? new Promise(() => {}),
  });
  // A real agent always has a session; the stub bypasses the constructor,
  // so provide a minimal one for busSessionId (used to stamp event ids).
  Object.defineProperty(agent, "_session", {
    value: { id: "ses_stub" },
  });
  Object.defineProperty(agent, "currentMessageId", {
    value: null,
    writable: true,
  });
  Object.defineProperty(agent, "persistentShell", {
    value: overrides.persistentShell,
  });
  Object.defineProperty(agent, "abortSignal", {
    value: overrides.abortSignal,
  });
  Object.defineProperty(agent, "resolveResult", {
    value: overrides.resolveResult,
  });
  Object.defineProperty(agent, "browserSession", {
    value: overrides.browserSession,
  });
  Object.defineProperty(agent, "ownsBrowserSession", {
    value: overrides.ownsBrowserSession ?? false,
  });
  Object.defineProperty(agent, "latestMessages", {
    value: overrides.latestMessages ?? null,
    writable: true,
  });
  Object.defineProperty(agent, "messagesPath", {
    value: overrides.messagesPath ?? null,
  });
  Object.defineProperty(agent, "cancelPersistTimer", {
    value: () => {},
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

  describe("browser session teardown on completion (Chromium leak fix)", () => {
    it("disconnects the owned browser session after a successful stream", async () => {
      const disconnect = vi.fn().mockResolvedValue(undefined);
      const agent = buildStubAgent({
        fullStream: yieldChunks([textDelta]),
        browserSession: { disconnect },
        ownsBrowserSession: true,
      });

      await agent.consume();
      expect(disconnect).toHaveBeenCalledOnce();
    });

    it("disconnects the owned browser session when the stream throws", async () => {
      const disconnect = vi.fn().mockResolvedValue(undefined);
      const agent = buildStubAgent({
        fullStream: yieldThenThrow([textDelta], new Error("stream exploded")),
        browserSession: { disconnect },
        ownsBrowserSession: true,
      });

      await expect(agent.consume()).rejects.toThrow("stream exploded");
      expect(disconnect).toHaveBeenCalledOnce();
    });

    it("does NOT disconnect an inherited (not-owned) browser session", async () => {
      const disconnect = vi.fn().mockResolvedValue(undefined);
      const agent = buildStubAgent({
        fullStream: yieldChunks([textDelta]),
        browserSession: { disconnect },
        ownsBrowserSession: false,
      });

      await agent.consume();
      expect(disconnect).not.toHaveBeenCalled();
    });

    it("swallows a disconnect failure so it never masks the run result", async () => {
      const disconnect = vi.fn().mockRejectedValue(new Error("kill failed"));
      const agent = buildStubAgent({
        fullStream: yieldChunks([textDelta]),
        browserSession: { disconnect },
        ownsBrowserSession: true,
        resolveResult: () => "ok",
      });

      await expect(agent.consume()).resolves.toBe("ok");
      expect(disconnect).toHaveBeenCalledOnce();
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

  describe("synthetic tool-result on stream abort/error", () => {
    const toolCallChunk = {
      type: "tool-call",
      toolCallId: "tc1",
      toolName: "execute_command",
    };
    const otherToolCallChunk = {
      type: "tool-call",
      toolCallId: "tc2",
      toolName: "read_file",
    };
    const toolResultChunk = {
      type: "tool-result",
      toolCallId: "tc1",
      result: { type: "text", value: "done" },
    };

    it("emits synthetic tool-result for an in-flight tool when stream throws", async () => {
      const agent = buildStubAgent({
        fullStream: yieldThenThrow(
          [toolCallChunk],
          new Error("connection reset"),
        ),
      });

      const emittedResults: Array<{
        toolCallId: string;
        result: unknown;
      }> = [];
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

    it("does not emit a synthetic result when the matching tool-result already streamed", async () => {
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

    it("emits one synthetic per in-flight tool when multiple are open at abort", async () => {
      const controller = new AbortController();
      controller.abort();

      const agent = buildStubAgent({
        fullStream: yieldThenThrow(
          [toolCallChunk, otherToolCallChunk],
          new DOMException("Aborted", "AbortError"),
        ),
        abortSignal: controller.signal,
      });

      const emittedResults: Array<{ toolCallId: string; result: unknown }> = [];
      agent.eventBus.on("tool-result", (e) => {
        emittedResults.push({ toolCallId: e.toolCallId, result: e.result });
      });

      await expect(agent.consume()).rejects.toBeInstanceOf(DOMException);

      expect(emittedResults).toHaveLength(2);
      const ids = emittedResults.map((r) => r.toolCallId).sort();
      expect(ids).toEqual(["tc1", "tc2"]);
      for (const r of emittedResults) {
        expect(r.result).toMatchObject({
          type: "error-text",
          value: expect.stringContaining("aborted"),
        });
      }
    });

    it("uses 'Agent aborted by user' as reason when abortSignal is set", async () => {
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

  describe("result/drain decoupling", () => {
    it("returns the captured result without waiting for the stream to drain", async () => {
      // A teardown that never completes (a wedged stream). consume() must still
      // settle from responseCaptured rather than hang on the drain.
      const neverDrains = (async function* () {
        await new Promise(() => {});
      })();
      const agent = buildStubAgent({
        fullStream: neverDrains,
        responseCaptured: Promise.resolve("captured"),
        resolveResult: () => "from-drain",
      });

      await expect(agent.consume()).resolves.toBe("captured");
    });
  });

  describe("synthetic tool-result: persist timer fallback (bugbot fix)", () => {
    const toolCallChunk = {
      type: "tool-call",
      toolCallId: "tc1",
      toolName: "execute_command",
    };

    it("reads persisted messages from disk when latestMessages is null", async () => {
      const tmpDir = join("/tmp", `pensar-test-${Date.now()}-fallback`);
      mkdirSync(tmpDir, { recursive: true });
      const messagesPath = join(tmpDir, "messages.json");

      const existingMessages = [
        { role: "user", content: [{ type: "text", text: "run nmap" }] },
        { role: "assistant", content: [{ type: "text", text: "Running..." }] },
      ];
      writeFileSync(messagesPath, JSON.stringify(existingMessages));

      // latestMessages is null — simulates persist timer having flushed
      const agent = buildStubAgent({
        fullStream: yieldThenThrow([toolCallChunk], new Error("timeout")),
        messagesPath,
        latestMessages: null,
      });

      try {
        await agent.consume();
      } catch {}

      // Wait for async writeFile
      await new Promise((r) => setTimeout(r, 50));

      const written = JSON.parse(readFileSync(messagesPath, "utf-8"));
      // original 2 + assistant (tool-call) + tool (synthetic result)
      expect(written).toHaveLength(4);
      expect(written[0].role).toBe("user");
      expect(written[1].role).toBe("assistant");
      expect(written[2].role).toBe("assistant");
      expect(written[2].content[0].type).toBe("tool-call");
      expect(written[2].content[0].toolCallId).toBe("tc1");
      expect(written[3].role).toBe("tool");
      expect(written[3].content[0].toolCallId).toBe("tc1");
      expect(written[3].content[0].output.type).toBe("error-text");

      rmSync(tmpDir, { recursive: true, force: true });
    });

    it("does not lose history when persist timer nulled latestMessages", async () => {
      const tmpDir = join("/tmp", `pensar-test-${Date.now()}-noloss`);
      mkdirSync(tmpDir, { recursive: true });
      const messagesPath = join(tmpDir, "messages.json");

      const existingMessages = [
        { role: "user", content: [{ type: "text", text: "scan target" }] },
      ];
      writeFileSync(messagesPath, JSON.stringify(existingMessages));

      const agent = buildStubAgent({
        fullStream: yieldThenThrow([toolCallChunk], new Error("network")),
        messagesPath,
        latestMessages: null,
      });

      try {
        await agent.consume();
      } catch {}

      await new Promise((r) => setTimeout(r, 50));

      const written = JSON.parse(readFileSync(messagesPath, "utf-8"));
      // Must NOT be just [{ role: "tool" ... }] — must include original messages
      expect(written.length).toBeGreaterThan(1);
      expect(written[0].role).toBe("user");

      rmSync(tmpDir, { recursive: true, force: true });
    });

    it("does not add assistant tool-call msg when base already contains them", async () => {
      const tmpDir = join("/tmp", `pensar-test-${Date.now()}-nodup`);
      mkdirSync(tmpDir, { recursive: true });
      const messagesPath = join(tmpDir, "messages.json");

      // Simulate onStepFinish having already persisted the assistant tool-call
      const existingMessages = [
        { role: "user", content: [{ type: "text", text: "scan" }] },
        {
          role: "assistant",
          content: [
            {
              type: "tool-call",
              toolCallId: "tc1",
              toolName: "execute_command",
              input: {},
            },
          ],
        },
      ];
      writeFileSync(messagesPath, JSON.stringify(existingMessages));

      const agent = buildStubAgent({
        fullStream: yieldThenThrow([toolCallChunk], new Error("abort")),
        messagesPath,
        latestMessages: null,
      });

      try {
        await agent.consume();
      } catch {}

      await new Promise((r) => setTimeout(r, 50));

      const written = JSON.parse(readFileSync(messagesPath, "utf-8"));
      // Should NOT duplicate the assistant message — just user + assistant + tool
      expect(written).toHaveLength(3);
      expect(written[0].role).toBe("user");
      expect(written[1].role).toBe("assistant");
      expect(written[2].role).toBe("tool");
      expect(written[2].content[0].output.type).toBe("error-text");

      rmSync(tmpDir, { recursive: true, force: true });
    });
  });

  describe("parallel tool abort persists completed tools (bugbot fix)", () => {
    it("includes completed tool results alongside synthetics on abort", async () => {
      const tmpDir = join("/tmp", `pensar-test-${Date.now()}-parallel`);
      mkdirSync(tmpDir, { recursive: true });
      const messagesPath = join(tmpDir, "messages.json");

      const existingMessages = [
        { role: "user", content: [{ type: "text", text: "scan" }] },
      ];
      writeFileSync(messagesPath, JSON.stringify(existingMessages));

      // Two tools called; tool A completes, tool B is still in-flight on abort.
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
      // user + assistant (with both tool-calls) + tool (with both results)
      expect(written).toHaveLength(3);
      expect(written[0].role).toBe("user");
      expect(written[1].role).toBe("assistant");
      expect(written[1].content).toHaveLength(2);
      const assistantToolIds = written[1].content.map(
        (c: { toolCallId: string }) => c.toolCallId,
      );
      expect(assistantToolIds.sort()).toEqual(["tcA", "tcB"]);

      expect(written[2].role).toBe("tool");
      expect(written[2].content).toHaveLength(2);
      const toolResultIds = written[2].content.map(
        (c: { toolCallId: string }) => c.toolCallId,
      );
      expect(toolResultIds.sort()).toEqual(["tcA", "tcB"]);

      // Tool A has real result, Tool B has synthetic error-text
      const resultA = written[2].content.find(
        (c: { toolCallId: string }) => c.toolCallId === "tcA",
      );
      const resultB = written[2].content.find(
        (c: { toolCallId: string }) => c.toolCallId === "tcB",
      );
      expect(resultA.output.type).toBe("text");
      expect(resultB.output.type).toBe("error-text");

      rmSync(tmpDir, { recursive: true, force: true });
    });
  });

  describe("multi-step abort does not duplicate prior steps (bugbot fix)", () => {
    it("clears completed results at finish-step so earlier steps aren't re-appended", async () => {
      const tmpDir = join("/tmp", `pensar-test-${Date.now()}-multistep`);
      mkdirSync(tmpDir, { recursive: true });
      const messagesPath = join(tmpDir, "messages.json");

      // Step 1 already persisted by onStepFinish: tool A called and resolved.
      const persistedAfterStep1 = [
        { role: "user", content: [{ type: "text", text: "scan" }] },
        {
          role: "assistant",
          content: [
            { type: "tool-call", toolCallId: "tcA", toolName: "read_file" },
          ],
        },
        {
          role: "tool",
          content: [
            {
              type: "tool-result",
              toolCallId: "tcA",
              toolName: "read_file",
              output: { type: "text", value: "file contents" },
            },
          ],
        },
      ];
      writeFileSync(messagesPath, JSON.stringify(persistedAfterStep1));

      // Stream replays step 1's chunks, finishes the step, then opens tool B
      // in step 2 before erroring.
      const agent = buildStubAgent({
        fullStream: yieldThenThrow(
          [
            { type: "tool-call", toolCallId: "tcA", toolName: "read_file" },
            {
              type: "tool-result",
              toolCallId: "tcA",
              toolName: "read_file",
              result: { type: "text", value: "file contents" },
            },
            { type: "finish-step" },
            {
              type: "tool-call",
              toolCallId: "tcB",
              toolName: "execute_command",
            },
          ],
          new Error("connection lost"),
        ),
        messagesPath,
        latestMessages: persistedAfterStep1,
      });

      try {
        await agent.consume();
      } catch {}
      await new Promise((r) => setTimeout(r, 50));

      const written = JSON.parse(readFileSync(messagesPath, "utf-8"));
      const toolCallIds = written
        .filter((m: { role: string }) => m.role === "assistant")
        .flatMap((m: { content: { toolCallId?: string }[] }) =>
          m.content.map((c) => c.toolCallId),
        );
      // tcA must appear exactly once — the abort snapshot must not re-append it.
      expect(toolCallIds.filter((id: string) => id === "tcA")).toHaveLength(1);
      expect(toolCallIds.filter((id: string) => id === "tcB")).toHaveLength(1);

      rmSync(tmpDir, { recursive: true, force: true });
    });
  });

  describe("failed abort write leaves flag unset (bugbot fix)", () => {
    const toolCallChunk = {
      type: "tool-call",
      toolCallId: "tc1",
      toolName: "execute_command",
    };

    it("does not mark synthetics persisted when the write fails", async () => {
      // A path inside a non-existent directory makes writeFile reject.
      const messagesPath = join(
        "/tmp",
        `pensar-test-${Date.now()}-missing`,
        "nope",
        "messages.json",
      );

      const agent = buildStubAgent({
        fullStream: yieldThenThrow([toolCallChunk], new Error("stream broke")),
        messagesPath,
        latestMessages: [
          { role: "user", content: [{ type: "text", text: "scan" }] },
        ],
      });

      try {
        await agent.consume();
      } catch {}
      await new Promise((r) => setTimeout(r, 50));

      expect(
        (agent as unknown as { syntheticsPersisted?: boolean })
          .syntheticsPersisted,
      ).toBeFalsy();
    });
  });

  describe("emitSyntheticToolResults error does not mask stream error (bugbot fix)", () => {
    const toolCallChunk = {
      type: "tool-call",
      toolCallId: "tc1",
      toolName: "execute_command",
    };

    it("propagates original stream error when event listener throws", async () => {
      const agent = buildStubAgent({
        fullStream: yieldThenThrow(
          [toolCallChunk],
          new Error("original stream error"),
        ),
      });

      // Make the event listener throw during synthetic emission
      agent.eventBus.on("tool-result", () => {
        throw new Error("listener explosion");
      });

      // The original stream error must propagate, not the listener error
      await expect(agent.consume()).rejects.toThrow("original stream error");
    });

    it("still disposes shell when emitSyntheticToolResults throws", async () => {
      const dispose = vi.fn();
      const agent = buildStubAgent({
        fullStream: yieldThenThrow([toolCallChunk], new Error("stream broke")),
        persistentShell: { dispose },
      });

      agent.eventBus.on("tool-result", () => {
        throw new Error("listener crash");
      });

      await expect(agent.consume()).rejects.toThrow("stream broke");
      expect(dispose).toHaveBeenCalledOnce();
    });
  });
});
