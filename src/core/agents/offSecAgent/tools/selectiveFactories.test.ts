// Selective tool-factory construction contracts, measured by a passthrough
// spy on the ai package's `tool` constructor — the real count invariant,
// call-path-agnostic (direct imports, group-internal nested calls, and
// duplicates all count). Selection must construct exactly the requested
// tools with zero unselected siblings. Baseline (8c5b46c8) built 78
// constructions for 74 retained keys (four email duplicates constructed then
// discarded); the registry design constructs 74 (77 with the callback
// helper tools). Agent-path counts include
// conditional tools (traceWriter is always provided) — see
// selectiveConstruction.test.ts.

import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it, vi } from "vitest";

const counts = vi.hoisted(() => ({
  toolCtor: 0,
  browserGroupRouter: 0,
  sharedBrowserFactories: 0,
  emailGroup: 0,
}));

vi.mock("ai", async (importOriginal) => {
  const actual = await importOriginal<Record<string, unknown>>();
  return {
    ...actual,
    tool: ((...args: unknown[]) => {
      counts.toolCtor++;
      return (actual.tool as (...a: unknown[]) => unknown)(...args);
    }) as unknown as typeof actual.tool,
  };
});

// browserTools.ts group router: routes each member factory to the local MCP
// or sandbox implementation. Any browser member selection passes through it.
vi.mock("./browserTools", async (importOriginal) => {
  const actual = await importOriginal<Record<string, unknown>>();
  return {
    ...actual,
    createBrowserToolsetFactories: ((...args: unknown[]) => {
      counts.browserGroupRouter++;
      return (
        actual.createBrowserToolsetFactories as (...a: unknown[]) => unknown
      )(...args);
    }) as unknown as typeof actual.createBrowserToolsetFactories,
  };
});

// All transports use the same lazy schema factories.
vi.mock("./browserToolFactories", async (importOriginal) => {
  const actual = await importOriginal<Record<string, unknown>>();
  return {
    ...actual,
    createBackendBrowserToolFactories: ((...args: unknown[]) => {
      counts.sharedBrowserFactories++;
      return (
        actual.createBackendBrowserToolFactories as (...a: unknown[]) => unknown
      )(...args);
    }) as unknown as typeof actual.createBackendBrowserToolFactories,
  };
});

// email/index.ts compat group entrypoint — not used by the registry, which
// references the leaf factories directly.
vi.mock("./email", async (importOriginal) => {
  const actual = await importOriginal<Record<string, unknown>>();
  return {
    ...actual,
    createEmailToolset: ((...args: unknown[]) => {
      counts.emailGroup++;
      return (actual.createEmailToolset as (...a: unknown[]) => unknown)(
        ...args,
      );
    }) as unknown as typeof actual.createEmailToolset,
  };
});

import { z } from "zod";
import type { executeCommand } from "./executeCommand";
// Import AFTER the spies are registered.
import {
  createAllTools,
  createToolsForNames,
  type ToolContext,
  type ToolName,
} from "./index";
import type { readSkill } from "./readSkill";

// Exact parent (8c5b46c8) fill-schema text — wire-visible parity anchors.
const FILL_VALUE_DESCRIPTION =
  "Literal value to fill into the field. Omit when using promptInjection.id or credentialId + credentialField.";

function makeCtx(overrides: Record<string, unknown> = {}): ToolContext {
  return {
    session: {
      id: "ses_selective",
      version: "1.0.0",
      targets: [],
      time: { created: Date.now(), updated: Date.now() },
      rootPath: "/tmp/apex-selective-factories",
      logsPath: "/tmp/apex-selective-factories/logs",
      findingsPath: "/tmp/apex-selective-factories/findings",
      scratchpadPath: "/tmp/apex-selective-factories/scratchpad",
      pocsPath: "/tmp/apex-selective-factories/pocs",
      config: {},
    },
    agentCwd: "/tmp/apex-selective-factories",
    sandbox: {
      type: "linux",
      execute: async () => {
        throw new Error("unexpected sandbox execution in test");
      },
    },
    ...overrides,
  } as unknown as ToolContext;
}

function reset(): void {
  counts.toolCtor = 0;
  counts.browserGroupRouter = 0;
  counts.sharedBrowserFactories = 0;
  counts.emailGroup = 0;
}

const JUDGE_TOOLS = [
  "execute_command",
  "http_request",
  "read_file",
  "list_files",
  "grep",
  "web_search",
  "get_page",
];

describe("createAllTools (full construction)", () => {
  it("constructs one tool per retained key — no discarded duplicates", () => {
    reset();
    const tools = createAllTools(makeCtx());
    expect(Object.keys(tools)).toHaveLength(77);
    // One construction per retained key — no discarded duplicates.
    expect(counts.toolCtor).toBe(77);
    expect(counts.browserGroupRouter).toBe(1);
    expect(counts.sharedBrowserFactories).toBe(1);
    expect(counts.emailGroup).toBe(0);
    expect(tools).toHaveProperty("start_callback_listener");
    expect(tools).toHaveProperty("poll_callback_listener");
    expect(tools).toHaveProperty("stop_callback_listener");
  });

  it("conditional context adds exactly the five conditional constructions", () => {
    reset();
    const tools = createAllTools(
      makeCtx({
        skillsRegistry: { buildCatalog: () => [] },
        traceWriter: { writeInit: () => {}, recordStep: () => {} },
        tasksDir: "/tmp/apex-selective-factories-tasks",
      }),
    );
    expect(Object.keys(tools)).toHaveLength(82);
    expect(counts.toolCtor).toBe(82);
  });
});

describe("createToolsForNames selective construction", () => {
  it("constructs exactly the seven specialist tools — no siblings, no groups", () => {
    reset();
    const selected = createToolsForNames(makeCtx(), JUDGE_TOOLS);
    expect(Object.keys(selected)).toEqual(JUDGE_TOOLS);
    expect(counts.toolCtor).toBe(7);
    expect(counts.browserGroupRouter).toBe(0);
    expect(counts.sharedBrowserFactories).toBe(0);
    expect(counts.emailGroup).toBe(0);
  });

  it("one browser member (sandbox routing): one construction, zero siblings", () => {
    reset();
    const selected = createToolsForNames(makeCtx(), ["browser_click"]);
    expect(Object.keys(selected)).toEqual(["browser_click"]);
    expect(counts.toolCtor).toBe(1);
    expect(counts.browserGroupRouter).toBe(1);
    expect(counts.sharedBrowserFactories).toBe(1);
    expect(counts.emailGroup).toBe(0);
  });

  it("one browser member (local MCP routing): one construction, zero siblings", () => {
    const { ctx, root } = sandboxlessCtx();
    try {
      reset();
      const selected = createToolsForNames(ctx, ["browser_navigate"]);
      expect(Object.keys(selected)).toEqual(["browser_navigate"]);
      expect(counts.toolCtor).toBe(1);
      expect(counts.browserGroupRouter).toBe(1);
      expect(counts.sharedBrowserFactories).toBe(1);
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });

  it("one email member: one construction, zero siblings", () => {
    reset();
    const selected = createToolsForNames(makeCtx(), ["email_list_inboxes"]);
    expect(Object.keys(selected)).toEqual(["email_list_inboxes"]);
    expect(counts.toolCtor).toBe(1);
    expect(counts.emailGroup).toBe(0);
    expect(counts.browserGroupRouter).toBe(0);
    expect(counts.sharedBrowserFactories).toBe(0);
  });

  it("sparse mixed selection constructs exactly the union, in registry order", () => {
    reset();
    const selected = createToolsForNames(makeCtx(), [
      "email_mark_read",
      "browser_get_cookies",
      "send_email",
      "grep",
    ]);
    expect(Object.keys(selected)).toEqual([
      "browser_get_cookies",
      "grep",
      "email_mark_read",
      "send_email",
    ]);
    expect(counts.toolCtor).toBe(4);
  });

  it("two browser members: each constructs once, one shared group", () => {
    reset();
    const selected = createToolsForNames(makeCtx(), [
      "browser_click",
      "browser_navigate",
    ]);
    expect(Object.keys(selected)).toEqual([
      "browser_navigate",
      "browser_click",
    ]);
    expect(counts.toolCtor).toBe(2);
    expect(counts.sharedBrowserFactories).toBe(1);
  });

  it("credentialManager browser_fill: wrapper is lazy — 1 construction without fill, 2 with", () => {
    const credentialManager = {
      listReferences: () => [],
      resolve: () => undefined,
    };
    reset();
    const withoutFill = createToolsForNames(makeCtx({ credentialManager }), [
      "browser_click",
    ]);
    expect(Object.keys(withoutFill)).toEqual(["browser_click"]);
    expect(counts.toolCtor).toBe(1);

    reset();
    // The credential wrapper derives its description from the inner fill
    // tool, so a selected browser_fill is the original inner+wrapper pair.
    const withFill = createToolsForNames(makeCtx({ credentialManager }), [
      "browser_fill",
    ]);
    expect(Object.keys(withFill)).toEqual(["browser_fill"]);
    expect(counts.toolCtor).toBe(2);
  });

  it("unavailable conditional factories never construct even when named", () => {
    reset();
    const selected = createToolsForNames(makeCtx(), [
      "read_skill",
      "checkpoint_state",
      "create_task",
      "update_task",
      "list_tasks",
      "execute_command",
    ]);
    expect(Object.keys(selected)).toEqual(["execute_command"]);
    expect(counts.toolCtor).toBe(1);
  });

  it("conditional members construct when their context is provided", () => {
    reset();
    const selected = createToolsForNames(
      makeCtx({
        skillsRegistry: { buildCatalog: () => [] },
        tasksDir: "/tmp/apex-selective-factories-tasks",
      }),
      ["read_skill", "create_task", "execute_command"],
    );
    expect(Object.keys(selected)).toEqual([
      "execute_command",
      "read_skill",
      "create_task",
    ]);
    expect(counts.toolCtor).toBe(3);
  });

  it("ignores unknown and duplicate names; empty selection constructs nothing", () => {
    reset();
    const selected = createToolsForNames(makeCtx(), [
      "get_page",
      "execute_command",
      "execute_command",
      "not_a_tool",
    ]);
    expect(Object.keys(selected)).toEqual(["execute_command", "get_page"]);
    expect(counts.toolCtor).toBe(2);

    reset();
    expect(Object.keys(createToolsForNames(makeCtx(), []))).toEqual([]);
    expect(counts.toolCtor).toBe(0);
  });

  it("a prototype-shaped name is not an own key and constructs nothing", () => {
    reset();
    const selected = createToolsForNames(makeCtx(), ["__proto__"]);
    expect(Object.keys(selected)).toEqual([]);
    expect(Object.getPrototypeOf(selected)).toBe(Object.prototype);
    expect(counts.toolCtor).toBe(0);
  });
});

describe("selected-tool definition parity with the full catalog", () => {
  it("selected members expose the same description and wire schema as the full catalog", () => {
    const ctx = makeCtx();
    const all = createAllTools(ctx);
    reset();
    const selected = createToolsForNames(ctx, [
      "execute_command",
      "browser_click",
      "send_email",
    ]);

    function toolView(
      set: typeof all | typeof selected,
      name: string,
    ): { description?: string; inputSchema: unknown } | undefined {
      const record = set as unknown as Record<string, unknown>;
      const entry = record[name] as
        | { description?: string; inputSchema: unknown }
        | undefined;
      return entry;
    }

    // Per-call construction: parity is provider-visible description + wire
    // schema, not object identity.
    for (const name of ["execute_command", "browser_click", "send_email"]) {
      const fromSelected = toolView(selected, name);
      const fromAll = toolView(all, name);
      expect(fromSelected?.description).toBe(fromAll?.description);
      expect(
        JSON.stringify(
          z.toJSONSchema(fromSelected?.inputSchema as z.ZodTypeAny),
        ),
      ).toBe(
        JSON.stringify(z.toJSONSchema(fromAll?.inputSchema as z.ZodTypeAny)),
      );
    }
  });
});

// Type-only guards: createAllTools keeps its precise public return type —
// finite names, member inference, optional conditional keys. Zero runtime
// cost; tsc enforces.
type Assert<T extends true> = T;
type Equal<A, B> =
  (<T>() => T extends A ? 1 : 2) extends <T>() => T extends B ? 1 : 2
    ? true
    : false;
type AllTools = ReturnType<typeof createAllTools>;
type _NoUnknownTool = Assert<
  "__unknown_builtin__" extends keyof AllTools ? false : true
>;
// The finite ToolName union and the createAllTools map keys are the same
// set of names — a registry entry cannot exist outside the map contract.
type _ToolNameMatchesMapKeys = Assert<Equal<ToolName, keyof AllTools & string>>;
type _ExecuteCommandInference = Assert<
  Equal<AllTools["execute_command"], ReturnType<typeof executeCommand>>
>;
type _ConditionalSkillRemainsOptional = Assert<
  undefined extends AllTools["read_skill"] ? true : false
>;
type _ReadSkillInference = Assert<
  Equal<AllTools["read_skill"], ReturnType<typeof readSkill> | undefined>
>;
void (null as unknown as {
  noUnknown: _NoUnknownTool;
  nameMatchesMapKeys: _ToolNameMatchesMapKeys;
  exec: _ExecuteCommandInference;
  skillOptional: _ConditionalSkillRemainsOptional;
  skillInference: _ReadSkillInference;
});

describe("credential/injection fill schema parity", () => {
  function fillSchema(tools: Record<string, unknown>): {
    properties: Record<string, { description?: string }>;
  } {
    return z.toJSONSchema(
      (tools.browser_fill as { inputSchema: z.ZodTypeAny }).inputSchema,
    ) as { properties: Record<string, { description?: string }> };
  }

  it("credential variant keeps the parent value-field description", () => {
    const tools = createToolsForNames(
      makeCtx({
        credentialManager: {
          listReferences: () => [],
          resolve: () => undefined,
        },
      }),
      ["browser_fill"],
    );
    const schema = fillSchema(tools);
    expect(schema.properties.value?.description).toBe(FILL_VALUE_DESCRIPTION);
    expect(schema.properties.credentialId).toBeDefined();
    expect(schema.properties.promptInjection).toBeUndefined();
  });

  it("injection variant keeps the parent value-field description", () => {
    const tools = createToolsForNames(
      makeCtx({ promptInjectionLibrarySource: "/tmp/nil-library" }),
      ["browser_fill"],
    );
    const schema = fillSchema(tools);
    expect(schema.properties.value?.description).toBe(FILL_VALUE_DESCRIPTION);
    expect(schema.properties.promptInjection).toBeDefined();
    expect(schema.properties.credentialId).toBeUndefined();
  });

  it("credential+injection composes both extras over the same base text", () => {
    const tools = createToolsForNames(
      makeCtx({
        credentialManager: {
          listReferences: () => [],
          resolve: () => undefined,
        },
        promptInjectionLibrarySource: "/tmp/nil-library",
      }),
      ["browser_fill"],
    );
    const schema = fillSchema(tools);
    expect(schema.properties.value?.description).toBe(FILL_VALUE_DESCRIPTION);
    expect(schema.properties.credentialId).toBeDefined();
    expect(schema.properties.promptInjection).toBeDefined();
  });

  it("plain fill variant has neither credential nor injection fields", () => {
    const tools = createToolsForNames(makeCtx(), ["browser_fill"]);
    const schema = fillSchema(tools);
    expect(schema.properties.value).toBeDefined();
    expect(schema.properties.credentialId).toBeUndefined();
    expect(schema.properties.promptInjection).toBeUndefined();
    expect(
      (tools.browser_fill as { description: string }).description,
    ).not.toMatch(/this field/);
  });
});

function sandboxlessCtx(): { ctx: ToolContext; root: string } {
  const root = mkdtempSync(join(tmpdir(), "apex-selective-mcp-"));
  const ctx = {
    session: {
      id: "ses_selective_mcp",
      version: "1.0.0",
      targets: [],
      time: { created: Date.now(), updated: Date.now() },
      rootPath: root,
      logsPath: join(root, "logs"),
      findingsPath: join(root, "findings"),
      scratchpadPath: join(root, "scratchpad"),
      pocsPath: join(root, "pocs"),
      config: {},
    },
    agentCwd: root,
    // Local MCP routing; PlaywrightMcpSession spawns nothing until the
    // first tool call, so this stays hermetic.
    target: "https://example.com",
  } as unknown as ToolContext;
  return { ctx, root };
}
