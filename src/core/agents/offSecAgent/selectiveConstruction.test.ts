// Pins the agent-level selection contract through the REAL
// OffensiveSecurityAgent constructor: gates run on names before any factory,
// only effective factories construct, and merge semantics (extras, response
// injection, approval wrapping, prototype-shaped names) match the baseline
// spread behavior. The tools module is stubbed so every constructed name is
// recorded; streamResponse is captured so the final provider-facing tool
// map and its ORDER can be asserted.

import { describe, expect, it, vi } from "vitest";

const state = vi.hoisted(() => ({
  constructedNames: [] as string[],
  toolContexts: [] as Array<Record<string, unknown>>,
  streamResponseCalls: [] as Array<Record<string, unknown>>,
}));

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

vi.mock("./tools", () => {
  const fakeTool = (name: string) => ({
    description: `${name} stub`,
    inputSchema: {},
    execute: async () => `${name} ok`,
  });
  // Mirrors the real registry order relevant to gating/ordering tests.
  const REGISTRY = [
    "browser_navigate",
    "browser_click",
    "execute_command",
    "http_request",
    "document_vulnerability",
    "read_file",
    "list_files",
    "grep",
    "web_search",
    "get_page",
    "create_file",
    "write_plan",
    "submit_plan",
    "spawn_pentest_agent",
    "email_list_inboxes",
    "email_list_messages",
    "email_get_message",
    "email_get_attachments",
    "email_mark_read",
    "send_email",
    "sms_list_messages",
    "list_workspace_domains",
    "create_workspace_domain",
    "ask_user_questions",
  ];
  const record = (ctx: Record<string, unknown>, names: readonly string[]) => {
    state.toolContexts.push(ctx);
    const wanted = names ?? REGISTRY;
    for (const name of wanted) {
      if (REGISTRY.includes(name)) state.constructedNames.push(name);
    }
    return Object.fromEntries(wanted.map((name) => [name, fakeTool(name)]));
  };
  return {
    createToolsForNames: (
      ctx: Record<string, unknown>,
      requested: readonly string[] | undefined,
    ) => record(ctx, requested ?? REGISTRY),
    listToolRegistryNames: () => [...REGISTRY],
    createAllTools: (ctx: Record<string, unknown>) => record(ctx, REGISTRY),
    EMAIL_TOOL_NAMES_ACTIVE: [
      "email_list_inboxes",
      "email_list_messages",
      "email_get_message",
      "email_get_attachments",
      "email_mark_read",
      "send_email",
    ],
    SEND_EMAIL_TOOL_NAME: "send_email",
    SMS_TOOL_NAMES_ACTIVE: ["sms_list_messages"],
    sessionHasSmsPasswordless: (session: { credentialManager?: unknown }) =>
      Boolean(session.credentialManager),
    PLAN_MODE_TOOL_NAMES: ["execute_command", "read_file", "web_search"],
    createResponseTool: () => fakeTool("response"),
    RESPONSE_TOOL_NAME: "response",
    ASK_USER_QUESTIONS_TOOL_NAME: "ask_user_questions",
    WORKSPACE_TOOL_NAMES: ["list_workspace_domains"],
    WORKSPACE_WRITE_TOOL_NAMES: ["create_workspace_domain"],
    FAST_STRIKE_EXCLUDED_TOOL_NAMES: ["spawn_pentest_agent", "write_plan"],
    PerCommandShell: class {},
    PlaywrightMcpSession: class {},
    resolveBrowserHeaderPolicy: () => ({ allowedHosts: [], headers: {} }),
    // Minimal registry stub: the agent constructs one per instance and
    // finalization drains it; these tests never start listeners.
    CallbackListenerRegistry: class {
      register() {}
      get() {
        return undefined;
      }
      remove() {}
      async stopAll() {
        return [];
      }
    },
  };
});

vi.mock("../../ai", () => ({
  streamResponse: (opts: Record<string, unknown>) => {
    state.streamResponseCalls.push(opts);
    return { fullStream: (async function* () {})() };
  },
  normalizeStepUsage: (step: Record<string, unknown>) => step,
}));
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
    recordStep() {}
    markSummarized() {}
  },
}));
vi.mock("../../operator", () => ({
  ApprovalDeniedError: class extends Error {},
}));
vi.mock("ai", () => ({ hasToolCall: () => () => false }));

import { OffensiveSecurityAgent } from "./offensiveSecurityAgent";

function baseInput(overrides: Record<string, unknown> = {}) {
  return {
    prompt: "run the test",
    model: "test-model",
    session: { id: "ses_selective", rootPath: "/tmp/apex-selective" },
    activeTools: ["execute_command", "read_file"],
    ...overrides,
  };
}

// Construct the agent and force the lazy stream open so streamResponse —
// and therefore the final provider tool map — is observable.
function makeAgent(input: Record<string, unknown>): OffensiveSecurityAgent {
  const agent = new OffensiveSecurityAgent(input as never);
  void agent.streamResult;
  return agent;
}

function constructedSince(marker: number): string[] {
  return state.constructedNames.slice(marker);
}

function marker(): number {
  return state.constructedNames.length;
}

function streamTools(at = -1): Record<string, unknown> {
  return (
    (state.streamResponseCalls.at(at) as { tools?: Record<string, unknown> })
      ?.tools ?? {}
  );
}

describe("agent-level selective construction", () => {
  it("constructs exactly the gated active names — email/SMS drop before factories run", () => {
    const m = marker();
    makeAgent(
      baseInput({
        activeTools: [
          "execute_command",
          "email_list_inboxes",
          "sms_list_messages",
          "send_email",
          "not_a_tool",
        ],
      }) as never,
    );
    expect(constructedSince(m)).toEqual(["execute_command"]);
  });

  it("keeps email and SMS tools when their config is present", () => {
    const m = marker();
    makeAgent(
      baseInput({
        activeTools: [
          "execute_command",
          "email_list_inboxes",
          "send_email",
          "sms_list_messages",
        ],
        session: {
          id: "ses_selective",
          rootPath: "/tmp/apex-selective",
          credentialManager: { listReferences: () => [] },
          config: {
            emailIntegration: { inboxes: [{ id: "inb_1" }] },
            smtpConfig: { host: "smtp.example" },
          },
        },
      }) as never,
    );
    expect(constructedSince(m).sort()).toEqual([
      "email_list_inboxes",
      "execute_command",
      "send_email",
      "sms_list_messages",
    ]);
  });

  it("plan mode intersects the selection with the read-only name set", () => {
    const m = marker();
    makeAgent(
      baseInput({
        mode: "plan",
        activeTools: ["execute_command", "create_file", "read_file"],
      }) as never,
    );
    expect(constructedSince(m).sort()).toEqual([
      "execute_command",
      "read_file",
    ]);
  });

  it("workspace gates drop unrequested workspace tools before construction", () => {
    const m = marker();
    makeAgent(
      baseInput({
        approvalGate: { check: async () => {} },
        activeTools: ["execute_command", "create_workspace_domain"],
      }) as never,
    );
    expect(constructedSince(m)).toEqual(["execute_command"]);
  });

  it("fast-strike constructs the registry minus exclusions and gates, extras riding along", () => {
    const m = marker();
    makeAgent(
      baseInput({
        mode: "fast-strike",
        activeTools: [],
        extraTools: {
          custom_extra: {
            description: "x",
            inputSchema: {},
            execute: async () => "custom",
          },
        },
      }) as never,
    );
    // Stub registry minus {spawn_pentest_agent, write_plan} and email/SMS
    // (gated off by default config) plus nothing extra constructed for the
    // custom tool (not a registry name).
    // Stub registry minus fast-strike exclusions {spawn_pentest_agent,
    // write_plan}, email/SMS (no config), and the read-only workspace tool
    // (non-workspace prompt drops it; the write tool drops with it). This
    // stubbed list mirrors the real gates — the real-path counts live in
    // selectiveConstruction.publicPath.test.ts.
    expect(constructedSince(m).sort()).toEqual(
      [
        "browser_navigate",
        "browser_click",
        "execute_command",
        "http_request",
        "document_vulnerability",
        "read_file",
        "list_files",
        "grep",
        "web_search",
        "get_page",
        "create_file",
        "submit_plan",
        "ask_user_questions",
        "create_workspace_domain",
      ].sort(),
    );
    expect(Object.keys(streamTools())).toContain("custom_extra");
  });

  it("fast-strike keeps a builtin extra override at its builtin position in the provider tool map", () => {
    // Baseline spread semantics: { ...builtinTools, ...extraTools } replaces
    // the value but KEEPS the builtin insertion position. A name-only merge
    // that moves overridden builtins to the tail changes the provider schema
    // order — this pins the historical order.
    const m = marker();
    const override = {
      description: "override",
      inputSchema: {},
      execute: async () => "overridden",
    };
    makeAgent(
      baseInput({
        mode: "fast-strike",
        activeTools: [],
        extraTools: { read_file: override },
      }) as never,
    );
    expect(constructedSince(m)).toContain("read_file");
    const keys = Object.keys(streamTools());
    expect(streamTools().read_file).toBe(override);
    // PARENT contract: the spread merge keeps the overridden builtin at its
    // canonical registry position — read_file BEFORE list_files, per
    // tools/index.ts. A name-only merge that moves overrides to the tail
    // violates this; the map keys must equal the registry-ordered
    // enumeration. Stubbed wiring test; real-path counts live in
    // selectiveConstruction.publicPath.test.ts.
    expect(keys.indexOf("read_file")).toBeLessThan(keys.indexOf("list_files"));
    expect(keys.indexOf("read_file")).toBeLessThan(keys.indexOf("grep"));
    // The overridden value still wins.
    expect(streamTools().read_file).toBe(override);
  });

  it("default mode keeps caller order for the constructed selection", () => {
    const m = marker();
    makeAgent(
      baseInput({
        activeTools: ["grep", "execute_command"],
      }) as never,
    );
    // The provider map order is the selection order the caller passed
    // (baseline Object.keys of a fully-built map was registry order — the
    // selected map preserves the requested enumeration).
    expect(constructedSince(m)).toEqual(["grep", "execute_command"]);
    expect(Object.keys(streamTools())).toEqual(["grep", "execute_command"]);
  });

  it("extra tools override builtins by name and append new keys after builtins", () => {
    const m = marker();
    const override = {
      description: "override",
      inputSchema: {},
      execute: async () => "overridden",
    };
    const added = {
      description: "added",
      inputSchema: {},
      execute: async () => "added",
    };
    makeAgent(
      baseInput({
        activeTools: ["execute_command", "read_file"],
        extraTools: { execute_command: override, custom_extra: added },
      }) as never,
    );
    const tools = streamTools();
    expect(tools.execute_command).toBe(override);
    expect(tools.custom_extra).toBe(added);
    // The overridden builtin keeps its position; the new extra lands after.
    const keys = Object.keys(tools);
    expect(keys.indexOf("execute_command")).toBeLessThan(
      keys.indexOf("custom_extra"),
    );
    // The named builtin still constructed before being replaced.
    expect(constructedSince(m).sort()).toEqual([
      "execute_command",
      "read_file",
    ]);
  });

  it("non-enumerable and inherited extra properties are excluded like baseline Object.keys", () => {
    const m = marker();
    const extras: Record<string, unknown> = {};
    Object.defineProperty(extras, "hidden_extra", {
      value: { description: "h", inputSchema: {}, execute: async () => "h" },
      enumerable: false,
    });
    const proto: Record<string, unknown> = {
      inherited_extra: {
        description: "i",
        inputSchema: {},
        execute: async () => "i",
      },
    };
    Object.setPrototypeOf(extras, proto);
    makeAgent(
      baseInput({
        activeTools: ["execute_command"],
        extraTools: extras,
      }) as never,
    );
    const keys = Object.keys(streamTools());
    expect(keys).toContain("execute_command");
    // Baseline Object.keys never saw inherited or non-enumerable properties;
    // neither does the name merge.
    expect(keys).not.toContain("hidden_extra");
    expect(keys).not.toContain("inherited_extra");
    expect(constructedSince(m)).toEqual(["execute_command"]);
  });

  it("injects the response tool after selection when a response schema is present", () => {
    const m = marker();
    makeAgent(
      baseInput({
        activeTools: ["execute_command", "response"],
        responseSchema: { parse: () => {} },
      }) as never,
    );
    // response is injected by the agent, not a registry factory.
    expect(constructedSince(m)).toEqual(["execute_command"]);
    expect(Object.keys(streamTools())).toContain("response");

    const m2 = marker();
    makeAgent(
      baseInput({
        activeTools: [],
        responseSchema: { parse: () => {} },
      }) as never,
    );
    expect(constructedSince(m2)).toEqual([]);
    expect(Object.keys(streamTools())).toEqual(["response"]);
  });

  it("an extra named response is overridden by the injected response tool", () => {
    const m = marker();
    const evilResponse = {
      description: "extra response",
      inputSchema: {},
      execute: async () => "extra response",
    };
    makeAgent(
      baseInput({
        activeTools: ["execute_command"],
        extraTools: { response: evilResponse },
        responseSchema: { parse: () => {} },
      }) as never,
    );
    const tools = streamTools();
    expect(tools.response).not.toBe(evilResponse);
    expect((tools.response as { description?: string }).description).toBe(
      "response stub",
    );
    expect(constructedSince(m)).toEqual(["execute_command"]);
  });

  it("wraps executable tools with the approval gate, exempting ask_user_questions", async () => {
    const gateChecks: string[] = [];
    const gate = {
      check: async (name: string) => {
        gateChecks.push(name);
        if (name === "execute_command") {
          const { ApprovalDeniedError } = await import("../../operator");
          throw new ApprovalDeniedError("denied");
        }
      },
    };
    const m = marker();
    makeAgent(
      baseInput({
        approvalGate: gate,
        activeTools: ["execute_command", "ask_user_questions"],
      }) as never,
    );
    expect(constructedSince(m).sort()).toEqual([
      "ask_user_questions",
      "execute_command",
    ]);
    const tools = streamTools() as Record<
      string,
      { execute?: (args: Record<string, unknown>) => Promise<unknown> }
    >;
    const deniedExecute = tools.execute_command?.execute;
    if (!deniedExecute) throw new Error("execute_command missing from tools");
    const denied = (await deniedExecute({
      toolCallId: "tc_1",
    })) as { blocked?: boolean };
    expect(denied?.blocked).toBe(true);
    expect(gateChecks).toEqual(["execute_command"]);
    const exemptExecute = tools.ask_user_questions?.execute;
    if (!exemptExecute) throw new Error("ask_user_questions missing");
    const exemptResult = await exemptExecute({});
    expect(String(exemptResult)).toContain("ask_user_questions");
  });

  it("passes the tool context through to construction with approval wiring", () => {
    const m = marker();
    makeAgent(
      baseInput({
        approvalGate: { check: async () => {} },
        activeTools: ["execute_command"],
      }) as never,
    );
    expect(constructedSince(m)).toEqual(["execute_command"]);
    const ctx = state.toolContexts.at(-1) as Record<string, unknown>;
    expect(ctx.session).toMatchObject({ id: "ses_selective" });
  });
});
