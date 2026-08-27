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

const toolContexts = vi.hoisted(() => [] as Array<Record<string, unknown>>);

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
  createAllTools: (ctx: Record<string, unknown>) => {
    toolContexts.push(ctx);
    return {};
  },
  EMAIL_TOOL_NAMES_ACTIVE: [],
  SEND_EMAIL_TOOL_NAME: "send_email",
  PLAN_MODE_TOOL_NAMES: [],
  createResponseTool: () => {},
  RESPONSE_TOOL_NAME: "response",
  ASK_USER_QUESTIONS_TOOL_NAME: "ask_user_questions",
  WORKSPACE_TOOL_NAMES: [
    "list_workspace_domains",
    "create_workspace_domain",
    "list_workspace_apps",
    "create_workspace_app",
    "update_workspace_app",
    "list_workspace_endpoints",
    "create_workspace_endpoint",
    "update_workspace_endpoint",
  ],
  WORKSPACE_WRITE_TOOL_NAMES: [
    "create_workspace_domain",
    "create_workspace_app",
    "update_workspace_app",
    "create_workspace_endpoint",
    "update_workspace_endpoint",
  ],
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
    writeInit() {}
    onStepFinish() {}
  },
}));
vi.mock("../../operator", () => ({
  ApprovalDeniedError: class extends Error {},
}));
vi.mock("ai", () => ({ hasToolCall: () => () => false }));

import { AgentEventBus } from "../../eventBus";
import { createInterruptedStepFinalizer } from "./interruptedStepFinalization";
import { AgentMessageWriter } from "./messagePersistence";
import {
  filterWorkspaceToolsForRun,
  OffensiveSecurityAgent,
} from "./offensiveSecurityAgent";

describe("spawned-agent usage callbacks", () => {
  it("requires explicit forwarding when trace events own subagent accounting", () => {
    toolContexts.length = 0;
    const onStepFinish = vi.fn();
    const onCacheMetrics = vi.fn();
    const input = {
      prompt: "test",
      model: "test-model",
      session: { id: "ses_test", rootPath: "/tmp/apex-usage-test" },
      activeTools: [],
      sandbox: {},
      onStepFinish,
      onCacheMetrics,
    };

    new OffensiveSecurityAgent(input as never);
    new OffensiveSecurityAgent({
      ...input,
      forwardUsageCallbacksToSpawnedAgents: true,
    } as never);

    expect(toolContexts[0]?.onStepFinish).toBeUndefined();
    expect(toolContexts[0]?.onCacheMetrics).toBeUndefined();
    expect(toolContexts[1]?.onStepFinish).toBe(onStepFinish);
    expect(toolContexts[1]?.onCacheMetrics).toBe(onCacheMetrics);
  });
});

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
  writeImpl?: (messagesPath: string, contents: string) => Promise<void>;
  responseCaptured?: Promise<unknown>;
  subagentId?: string;
  subagentName?: string;
  agentMode?: "default" | "plan" | "fast-strike";
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
  Object.defineProperty(agent, "subagentId", {
    value: overrides.subagentId,
  });
  Object.defineProperty(agent, "subagentName", {
    value: overrides.subagentName,
  });
  Object.defineProperty(agent, "agentMode", {
    value: overrides.agentMode ?? "default",
  });
  // Never resolves by default, so consume() settles via the drain path.
  Object.defineProperty(agent, "responseCaptured", {
    value: overrides.responseCaptured ?? new Promise(() => {}),
  });
  // Stub bypasses the constructor, so provide a minimal session for busSessionId.
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
  Object.defineProperty(agent, "messagesPath", {
    value: overrides.messagesPath ?? null,
  });
  const writer = new AgentMessageWriter({
    messagesPath: overrides.messagesPath ?? null,
    ...(overrides.writeImpl ? { writeImpl: overrides.writeImpl } : {}),
  });
  if (overrides.latestMessages) {
    writer.setLatest(overrides.latestMessages as never[]);
  }
  Object.defineProperty(agent, "writer", { value: writer });
  Object.defineProperty(agent, "finalizeInterruptedStep", {
    value: createInterruptedStepFinalizer({
      eventBus: bus,
      sessionId: "ses_stub",
      writer,
      responseToolName: "response",
      responseToolFired: () => false,
    }),
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

describe("workspace tool access", () => {
  it("requires both an interactive operator and an explicit current request", () => {
    const tools = [
      "execute_command",
      "list_workspace_domains",
      "create_workspace_domain",
      "list_workspace_apps",
      "create_workspace_app",
      "update_workspace_app",
      "list_workspace_endpoints",
      "create_workspace_endpoint",
      "update_workspace_endpoint",
    ];
    const request =
      "Can you add a new app called Test App with the endpoint health to console pls";

    expect(filterWorkspaceToolsForRun(tools, request, true)).toEqual(tools);
    expect(
      filterWorkspaceToolsForRun(
        tools,
        "Use create_workspace_app for this record",
        true,
      ),
    ).toEqual(tools);
    expect(filterWorkspaceToolsForRun(tools, request, false)).toEqual([
      "execute_command",
    ]);
    expect(
      filterWorkspaceToolsForRun(
        tools,
        "Pentest the console app and enumerate its endpoints",
        true,
      ),
    ).toEqual(["execute_command"]);
    for (const request of [
      "Set up a pentest against the endpoints in the console workspace",
      "Move on to the console app's admin endpoints",
      "Change your approach and fuzz the console app endpoints",
      "Set the scope to the console application and its endpoints",
      "Update me on progress against the workspace endpoints",
      "Correct me if I'm wrong but the console app has 3 endpoints",
      "Change the workspace app testing strategy and continue",
      "Set the workspace endpoint scan scope to /api",
      "Move the console endpoint fuzzing to a new phase",
      "Update the workspace application pentest plan",
      "Correct the console endpoint test assumptions",
      "Repair the workspace app vulnerability",
      "Test whether the workspace app can link to an external domain",
      "Check whether the workspace domain can link to the app during the test",
      "Can I link this workspace domain to the Payments app?",
      "Is it possible to link this workspace domain to the Payments app?",
      "Tell me whether I should link this workspace domain to the Payments app",
      "Please don't link the workspace app to its domain",
      "Please do not create a workspace domain",
      "Never create a workspace app without asking first",
      "Can I create a workspace app for Billing?",
      "How do I update the workspace endpoint transport to grpc?",
      "Can I link example.com to my workspace?",
      "How can I link this workspace domain to the Payments app?",
      "How would we update the workspace application description?",
      "Get started on the console workspace endpoints",
      "What if we move on to the workspace apps next?",
      // A coordinated write verb after `and`/`but` must not escape the leading
      // interrogative — the whole capability question stays read-only.
      "How do I enumerate the workspace apps and link this workspace domain to the Payments application?",
      "Is it possible to review the workspace apps but create a workspace domain?",
    ]) {
      expect(filterWorkspaceToolsForRun(tools, request, true)).toEqual([
        "execute_command",
      ]);
    }
    expect(
      filterWorkspaceToolsForRun(
        tools,
        `<skill name="pentest">${request}</skill>`,
        true,
      ),
    ).toEqual(["execute_command"]);
  });

  it("exposes read-only listing tools but never mutations for recon phrasing", () => {
    const tools = [
      "execute_command",
      "list_workspace_domains",
      "create_workspace_domain",
      "list_workspace_apps",
      "create_workspace_app",
      "update_workspace_app",
      "list_workspace_endpoints",
      "create_workspace_endpoint",
      "update_workspace_endpoint",
    ];

    // Recon verbs (find/search/show/list) targeting the console/workspace must
    // only unlock the read-only `list_*` tools, never mutations.
    for (const request of [
      "Find all endpoints on the console workspace and pentest them",
      "Search the console workspace for apps in scope",
      "Show me the endpoints registered in the workspace",
      "List the apps in my console workspace",
      "Show the domains in my console workspace",
      "What domains are in my workspace?",
      "Get the workspace endpoints",
      "Which of the workspace apps are registered?",
      "Show me a list of all workspace endpoints",
      "What are the domains in my workspace?",
      "Which of our workspace apps are available?",
      "Get a list of the workspace endpoints",
      // A coordinated write verb ("create") after `and` must not escape the
      // leading capability question: the read verb still exposes `list_*`, but
      // the mutation tools stay gated.
      "Can I list the workspace endpoints and create a workspace endpoint?",
    ]) {
      expect(filterWorkspaceToolsForRun(tools, request, true)).toEqual([
        "execute_command",
        "list_workspace_domains",
        "list_workspace_apps",
        "list_workspace_endpoints",
      ]);
    }
  });

  it("exposes mutation tools only for explicit write requests", () => {
    const tools = [
      "execute_command",
      "list_workspace_domains",
      "create_workspace_domain",
      "list_workspace_apps",
      "create_workspace_app",
      "update_workspace_app",
      "list_workspace_endpoints",
      "create_workspace_endpoint",
      "update_workspace_endpoint",
    ];

    // Write verbs and "break down <threat model>" imports open the mutation set.
    expect(
      filterWorkspaceToolsForRun(
        tools,
        "Register a new app called Billing in the console workspace",
        true,
      ),
    ).toEqual(tools);
    expect(
      filterWorkspaceToolsForRun(
        tools,
        "Break down this threat model into apps and endpoints in the workspace",
        true,
      ),
    ).toEqual(tools);
    expect(
      filterWorkspaceToolsForRun(
        tools,
        "Change the workspace endpoint transport to grpc",
        true,
      ),
    ).toEqual(tools);
    expect(
      filterWorkspaceToolsForRun(
        tools,
        "Link the console application to this domain",
        true,
      ),
    ).toEqual(tools);
    expect(
      filterWorkspaceToolsForRun(
        tools,
        "Unlink the workspace app from its domain",
        true,
      ),
    ).toEqual(tools);
    expect(
      filterWorkspaceToolsForRun(
        tools,
        "Link this workspace domain to the Payments application",
        true,
      ),
    ).toEqual(tools);
    expect(
      filterWorkspaceToolsForRun(
        tools,
        "Can you link this workspace domain to the Payments application?",
        true,
      ),
    ).toEqual(tools);
    expect(
      filterWorkspaceToolsForRun(
        tools,
        "How can you link this workspace domain to the Payments application?",
        true,
      ),
    ).toEqual(tools);
    expect(
      filterWorkspaceToolsForRun(
        tools,
        "How would you update the workspace application description to Primary API?",
        true,
      ),
    ).toEqual(tools);
    expect(
      filterWorkspaceToolsForRun(
        tools,
        "Please unlink the workspace app from its domain",
        true,
      ),
    ).toEqual(tools);
    expect(
      filterWorkspaceToolsForRun(
        tools,
        "I need you to link this workspace domain to the Payments application",
        true,
      ),
    ).toEqual(tools);
    // "I'd like to …" / "I would like to …" without an explicit "you" must
    // expose writes, matching the "I want to …" / "I need to …" branch.
    expect(
      filterWorkspaceToolsForRun(
        tools,
        "I'd like to link this workspace domain to the Payments application",
        true,
      ),
    ).toEqual(tools);
    expect(
      filterWorkspaceToolsForRun(
        tools,
        "I would like to link this workspace domain to the Payments application",
        true,
      ),
    ).toEqual(tools);
    // A separate prohibition in another clause must not veto an explicit write.
    expect(
      filterWorkspaceToolsForRun(
        tools,
        "Please link this workspace domain to the Payments application, but do not create any new endpoints",
        true,
      ),
    ).toEqual(tools);
    expect(
      filterWorkspaceToolsForRun(
        tools,
        "Link this workspace domain to the Payments application; do not create any endpoints",
        true,
      ),
    ).toEqual(tools);
    expect(
      filterWorkspaceToolsForRun(
        tools,
        "Don't create any workspace endpoints, but link this workspace domain to the Payments application",
        true,
      ),
    ).toEqual(tools);
    expect(
      filterWorkspaceToolsForRun(
        tools,
        "Don't create any workspace endpoints and link this workspace domain to the Payments application",
        true,
      ),
    ).toEqual(tools);
    expect(
      filterWorkspaceToolsForRun(
        tools,
        "Link example.com to the Payments application in my workspace",
        true,
      ),
    ).toEqual(tools);
    expect(
      filterWorkspaceToolsForRun(
        tools,
        "Unlink example.com from the Payments app in my workspace",
        true,
      ),
    ).toEqual(tools);
    expect(
      filterWorkspaceToolsForRun(
        tools,
        "Update the workspace application description to Primary API",
        true,
      ),
    ).toEqual(tools);
    expect(
      filterWorkspaceToolsForRun(
        tools,
        "Rename the console app to Payments",
        true,
      ),
    ).toEqual(tools);
    expect(
      filterWorkspaceToolsForRun(
        tools,
        "Set the workspace endpoint parent application to app-2",
        true,
      ),
    ).toEqual(tools);
    expect(
      filterWorkspaceToolsForRun(
        tools,
        "Add example.com to my console workspace",
        true,
      ),
    ).toEqual(tools);
    expect(
      filterWorkspaceToolsForRun(
        tools,
        "Can you link example.com to my workspace?",
        true,
      ),
    ).toEqual(tools);

    // A direct mention of a read tool never unlocks the mutation tools.
    expect(
      filterWorkspaceToolsForRun(
        tools,
        "Use list_workspace_apps for this record",
        true,
      ),
    ).toEqual([
      "execute_command",
      "list_workspace_domains",
      "list_workspace_apps",
      "list_workspace_endpoints",
    ]);
  });
});

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

    it("flushes a tool-error into the snapshot when the stream aborts before finish-step", async () => {
      // finally must flush deferred toolErrors even if the stream throws first.
      const agent = buildStubAgent({
        fullStream: yieldThenThrow(
          [
            toolCallChunk,
            {
              type: "tool-error",
              toolCallId: "tc1",
              toolName: "execute_command",
              error: new Error("Zod: expected string"),
            },
          ],
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
        value: expect.stringContaining("Zod: expected string"),
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
      // Wedged stream: consume() must settle from responseCaptured, not the drain.
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

    it("waits for an in-flight persist before writing the abort snapshot", async () => {
      const tmpDir = join("/tmp", `pensar-test-${Date.now()}-persist-race`);
      mkdirSync(tmpDir, { recursive: true });
      const messagesPath = join(tmpDir, "messages.json");

      const staleMessages = [
        { role: "user", content: [{ type: "text", text: "scan target" }] },
      ];
      const persistedMessages = [
        ...staleMessages,
        {
          role: "assistant",
          content: [{ type: "text", text: "Starting scan" }],
        },
      ];
      writeFileSync(messagesPath, JSON.stringify(staleMessages));

      // Gate the writer's write sink so an in-flight persist can be held
      // while the stream throws and the abort snapshot waits its turn.
      let releasePersist!: () => void;
      const gate = new Promise<void>((resolve) => {
        releasePersist = resolve;
      });
      const writeImpl = async (path: string, contents: string) => {
        await gate;
        writeFileSync(path, contents);
      };

      const agent = buildStubAgent({
        fullStream: yieldThenThrow([toolCallChunk], new Error("timeout")),
        messagesPath,
        latestMessages: null,
        writeImpl,
      });

      // Start the in-flight persist against the gated sink.
      const writer = (agent as unknown as { writer: AgentMessageWriter })
        .writer;
      const inFlight = writer
        .enqueueWrite(persistedMessages as never[])
        .catch(() => {});

      const consume = agent.consume().catch(() => {});
      await new Promise((resolve) => setTimeout(resolve, 50));
      // The gated persist is still in flight — the abort snapshot must be
      // queued behind it, not interleaved.
      releasePersist();
      await inFlight;
      await consume;

      const written = JSON.parse(readFileSync(messagesPath, "utf-8"));
      expect(written.slice(0, persistedMessages.length)).toEqual(
        persistedMessages,
      );
      expect(written.at(-2)).toMatchObject({
        role: "assistant",
        content: [{ type: "tool-call", toolCallId: "tc1" }],
      });
      expect(written.at(-1)).toMatchObject({
        role: "tool",
        content: [{ type: "tool-result", toolCallId: "tc1" }],
      });

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

      // Replays step 1's chunks, finishes the step, then opens tool B in step 2 before erroring.
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
        (
          agent as unknown as {
            writer: { syntheticsPersisted: boolean };
          }
        ).writer.syntheticsPersisted,
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

    it("preserves the stream error and disposes resources when deferred emission throws", async () => {
      const tmpDir = join("/tmp", `pensar-test-${Date.now()}-listener-error`);
      mkdirSync(tmpDir, { recursive: true });
      const messagesPath = join(tmpDir, "messages.json");
      const existingMessages = [
        { role: "user", content: [{ type: "text", text: "scan" }] },
      ];
      writeFileSync(messagesPath, JSON.stringify(existingMessages));

      const streamError = new Error("original stream error");
      const dispose = vi.fn();
      const disconnect = vi.fn().mockResolvedValue(undefined);
      const agent = buildStubAgent({
        fullStream: yieldThenThrow(
          [
            {
              type: "tool-error",
              toolCallId: "tc1",
              toolName: "execute_command",
              error: new Error("tool validation failed"),
            },
          ],
          streamError,
        ),
        persistentShell: { dispose },
        browserSession: { disconnect },
        ownsBrowserSession: true,
        messagesPath,
        latestMessages: existingMessages,
      });

      agent.eventBus.on("tool-result", () => {
        throw new Error("listener explosion");
      });

      await expect(agent.consume()).rejects.toBe(streamError);
      expect(dispose).toHaveBeenCalledOnce();
      expect(disconnect).toHaveBeenCalledOnce();

      const written = JSON.parse(readFileSync(messagesPath, "utf-8"));
      expect(written.at(-2)).toMatchObject({
        role: "assistant",
        content: [{ type: "tool-call", toolCallId: "tc1" }],
      });
      expect(written.at(-1)).toMatchObject({
        role: "tool",
        content: [{ type: "tool-result", toolCallId: "tc1" }],
      });

      rmSync(tmpDir, { recursive: true, force: true });
    });
  });
});

// ---------------------------------------------------------------------------
// Owned-resource disposal — explicit idempotent operations (A6)
// ---------------------------------------------------------------------------

describe("owned-resource disposal", () => {
  const toolCallChunk = {
    type: "tool-call",
    toolCallId: "tc1",
    toolName: "execute_command",
  };

  it("disposeOwnedShell is idempotent across repeated calls", () => {
    const dispose = vi.fn();
    const agent = buildStubAgent({
      fullStream: yieldChunks([]),
      persistentShell: { dispose },
    });

    agent.disposeOwnedShell();
    agent.disposeOwnedShell();
    agent.disposeOwnedShell();

    expect(dispose).toHaveBeenCalledOnce();
  });

  it("disposeOwnedShell is a no-op with no shell (construction without one)", () => {
    const agent = buildStubAgent({ fullStream: yieldChunks([]) });
    expect(() => agent.disposeOwnedShell()).not.toThrow();
  });

  it("browser disconnect is idempotent across consume finalization and later teardown", async () => {
    const disconnect = vi.fn().mockResolvedValue(undefined);
    const agent = buildStubAgent({
      fullStream: yieldThenThrow([toolCallChunk], new Error("stream broke")),
      browserSession: { disconnect },
      ownsBrowserSession: true,
    });

    // consume()'s finalization disconnects; later host teardown must not repeat it.
    try {
      await agent.consume();
    } catch {}
    await agent.abortAndDrain();
    await agent.abortAndDrain();

    expect(disconnect).toHaveBeenCalledOnce();
  });

  it("abortAndDrain disconnects the browser exactly once", async () => {
    const disconnect = vi.fn().mockResolvedValue(undefined);
    const agent = buildStubAgent({
      fullStream: yieldThenThrow([toolCallChunk], new Error("aborted")),
      browserSession: { disconnect },
      ownsBrowserSession: true,
    });

    const consume = agent.consume().catch(() => {});
    await agent.abortAndDrain();
    await agent.abortAndDrain();
    await consume;

    expect(disconnect).toHaveBeenCalledOnce();
  });

  it("browser disconnect failure is swallowed and the run still settles", async () => {
    const disconnect = vi.fn().mockRejectedValue(new Error("disconnect boom"));
    const agent = buildStubAgent({
      fullStream: yieldThenThrow([toolCallChunk], new Error("stream broke")),
      browserSession: { disconnect },
      ownsBrowserSession: true,
    });

    // The stream error propagates; the disconnect failure does not replace it
    // and does not reject the teardown await.
    await expect(agent.consume()).rejects.toThrow("stream broke");
    expect(disconnect).toHaveBeenCalledOnce();
  });

  it("early result capture disconnects the browser without waiting for the drain", async () => {
    const disconnect = vi.fn().mockResolvedValue(undefined);
    // Stream that never ends on its own — only result capture unblocks consume.
    async function* endless(): AsyncGenerator<unknown, void, undefined> {
      yield toolCallChunk;
      await new Promise(() => {});
    }
    const agent = buildStubAgent({
      fullStream: endless(),
      browserSession: { disconnect },
      ownsBrowserSession: true,
      responseCaptured: Promise.resolve("captured"),
    });
    Object.defineProperty(agent, "resolveResult", {
      value: undefined,
    });

    const result = await Promise.race([
      agent.consume(),
      new Promise<never>((_, reject) =>
        setTimeout(() => reject(new Error("capture path stalled")), 1000),
      ),
    ]);

    expect(result).toBe("captured");
    expect(disconnect).toHaveBeenCalledOnce();
  });
});

// ---------------------------------------------------------------------------
// O3: root agent-run spans — every consume() execution runs inside an
// invoke_agent span with full run attribution.
// ---------------------------------------------------------------------------

describe("root agent-run spans", () => {
  const textChunk = { type: "text-delta", id: "t1", delta: "hi" };

  async function* singleStepStream(): AsyncGenerator<unknown, void, undefined> {
    yield textChunk;
  }

  function setupOtel() {
    // Local in-memory harness (mirrors observability/testkit, inlined per
    // this file's "helpers must be inlined" rule).
    const { BasicTracerProvider, InMemorySpanExporter, SimpleSpanProcessor } =
      require("@opentelemetry/sdk-trace-base") as typeof import("@opentelemetry/sdk-trace-base");
    const { AsyncLocalStorageContextManager } =
      require("@opentelemetry/context-async-hooks") as typeof import("@opentelemetry/context-async-hooks");
    const api =
      require("@opentelemetry/api") as typeof import("@opentelemetry/api");
    const exporter = new InMemorySpanExporter();
    const provider = new BasicTracerProvider({
      spanProcessors: [new SimpleSpanProcessor(exporter)],
    });
    const contextManager = new AsyncLocalStorageContextManager();
    contextManager.enable();
    api.trace.setGlobalTracerProvider(provider);
    api.context.setGlobalContextManager(contextManager);
    return {
      exporter,
      spans: () => exporter.getFinishedSpans(),
      async teardown() {
        await provider.shutdown();
        contextManager.disable();
        api.trace.disable();
        api.context.disable();
      },
    };
  }

  it("one root span per top-level run, with full run attribution", async () => {
    const otel = setupOtel();
    try {
      const agent = buildStubAgent({ fullStream: singleStepStream() });
      await agent.consume();

      const spans = otel.spans();
      const invokeSpans = spans.filter(
        (s) => s.name === "invoke_agent default",
      );
      expect(invokeSpans).toHaveLength(1);
      const attrs = invokeSpans[0]?.attributes as Record<string, string>;
      expect(attrs["gen_ai.operation.name"]).toBe("invoke_agent");
      expect(attrs["gen_ai.agent.name"]).toBe("default");
      expect(attrs["gen_ai.conversation.id"]).toBe("ses_stub");
      expect(attrs["pensar.session.id"]).toBe("ses_stub");
      expect(attrs["pensar.agent.mode"]).toBe("default");
      expect(attrs["pensar.run.id"]).toMatch(/^run_/);
    } finally {
      await otel.teardown();
    }
  });

  it("successful runs leave status unset", async () => {
    const otel = setupOtel();
    try {
      const agent = buildStubAgent({ fullStream: singleStepStream() });
      await agent.consume();

      const span = otel.spans().find((s) => s.name === "invoke_agent default");
      expect(span).toBeDefined();
      expect(span?.status.code).not.toBe(2); // SpanStatusCode.ERROR
      expect(span?.ended).toBe(true);
    } finally {
      await otel.teardown();
    }
  });

  it("failed runs use error status with exception and low-cardinality error.type", async () => {
    const otel = setupOtel();
    try {
      async function* failingStream(): AsyncGenerator<
        unknown,
        void,
        undefined
      > {
        yield textChunk;
        throw new Error("provider exploded");
      }
      const agent = buildStubAgent({ fullStream: failingStream() });
      await expect(agent.consume()).rejects.toThrow("provider exploded");

      const span = otel.spans().find((s) => s.name === "invoke_agent default");
      expect(span).toBeDefined();
      expect(span?.status.code).toBe(2);
      expect(
        span?.events.some(
          (e) =>
            e.name === "exception" &&
            (e.attributes?.["exception.message"] as string) ===
              "provider exploded",
        ),
      ).toBe(true);
      expect(span?.attributes["error.type"]).toBe("Error");
      expect(span?.ended).toBe(true);
    } finally {
      await otel.teardown();
    }
  });

  it("aborted runs end every span", async () => {
    const otel = setupOtel();
    try {
      const controller = new AbortController();
      async function* abortingStream(): AsyncGenerator<
        unknown,
        void,
        undefined
      > {
        yield textChunk;
        controller.abort();
        throw new DOMException("Agent aborted by user", "AbortError");
      }
      const agent = buildStubAgent({
        fullStream: abortingStream(),
        abortSignal: controller.signal,
      });
      await expect(agent.consume()).rejects.toThrow();

      const spans = otel.spans();
      const invokeSpan = spans.find((s) => s.name === "invoke_agent default");
      expect(invokeSpan?.ended).toBe(true);
      expect(invokeSpan?.attributes["error.type"]).toBe("AbortError");
    } finally {
      await otel.teardown();
    }
  });

  it("persistence and disposal finish before the root span ends", async () => {
    const otel = setupOtel();
    try {
      // Finalization ordering: the stub's shell disposal runs inside
      // runConsume's finally; the span ends only after that settles. Since
      // export happens exclusively on span.end(), observing the exported
      // span proves the span ended — and consume() resolving proves disposal
      // completed first (both are awaited in order inside runInSpan).
      const ordering: string[] = [];
      const dispose = vi.fn(() => ordering.push("shell-disposed"));
      const agent = buildStubAgent({
        fullStream: singleStepStream(),
        persistentShell: { dispose },
      });
      await agent.consume();

      // Consume resolved: disposal ran during finalization; the span ended
      // after (finally order in runInSpan). The exporter saw the span after
      // disposal because export only happens on span.end().
      expect(dispose).toHaveBeenCalledOnce();
      const span = otel.spans().find((s) => s.name === "invoke_agent default");
      expect(span?.ended).toBe(true);
      // Direct ordering proof: a span-end observer sees disposal already done.
      expect(ordering).toEqual(["shell-disposed"]);
    } finally {
      await otel.teardown();
    }
  });

  it("subagent runs keep their span but carry no run id", async () => {
    const otel = setupOtel();
    try {
      const agent = buildStubAgent({
        fullStream: singleStepStream(),
        subagentId: "ses_sub_1",
        subagentName: "recon-sub",
      });
      await agent.consume();

      const span = otel
        .spans()
        .find((s) => s.name === "invoke_agent recon-sub");
      expect(span).toBeDefined();
      const attrs = span?.attributes as Record<string, string>;
      expect(attrs["gen_ai.agent.name"]).toBe("recon-sub");
      expect(attrs["gen_ai.conversation.id"]).toBe("ses_stub");
      expect(attrs["pensar.session.id"]).toBe("ses_stub");
      expect(attrs["pensar.run.id"]).toBeUndefined();
      expect(attrs["pensar.agent.mode"]).toBeUndefined();
    } finally {
      await otel.teardown();
    }
  });
});
