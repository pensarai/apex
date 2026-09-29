// Pins the effective-toolset contract: `activeTools` resolves ONCE, before
// context fitting, into a single map used for schema budgeting, provider
// exposure, execution, and repair — and, on the runtime-covered paths
// (initial call and reactive overflow recovery), that SAME map reference.
// Rate-limit/idle-resume/summary-resume identity follows from the same opts
// normalization by code reasoning, not a runtime-tested case. Baseline
// counted every catalog schema toward the budget (an unnecessary summary for
// tool-light agents) while the SDK could still execute un-advertised tools;
// see resolveEffectiveTools in ./ai.

import { mkdtempSync, readdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { LanguageModelV3StreamPart } from "@ai-sdk/provider";
import {
  type ModelMessage,
  simulateReadableStream,
  stepCountIs,
  type ToolSet,
} from "ai";
import { MockLanguageModelV3 } from "ai/test";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { z } from "zod";
import {
  applySequentialToolCallPolicy,
  SEQUENTIAL_TOOL_CALL_INSTRUCTION,
} from "./ai";

// getProviderModel is patched so no provider keys are needed; the summarizing
// stream is stubbed so escalation is observable as a count, not a network call.
const state: {
  model: MockLanguageModelV3 | null;
  summaries: number;
  providerTools: Array<Array<string | undefined>>;
  generated: string[];
} = vi.hoisted(() => ({
  model: null,
  summaries: 0,
  providerTools: [],
  generated: [],
}));

vi.mock("./utils", async () => {
  const actual = await vi.importActual<typeof import("./utils")>("./utils");
  return {
    ...actual,
    getProviderModel: () => {
      if (!state.model) throw new Error("mock model not set");
      return state.model;
    },
    createSummarizationStream: () => {
      state.summaries++;
      return {
        fullStream: (async function* () {
          yield { type: "finish" as const };
        })(),
        response: Promise.resolve({ messages: [] }),
      };
    },
  };
});

const { streamResponse, getContextWindow, resolveEffectiveTools } =
  await import("./ai");
const { getMaxOutputTokens } = await import("./models");
const { estimateToolsOverheadTokens, fitMessagesToContext } = await import(
  "./contextManagement"
);
const { createAllTools } = await import("../agents/offSecAgent/tools");

const MODEL = "claude-sonnet-4-5";
const CONTEXT_ERROR = new Error(
  "prompt is too long: 999999 tokens > 200000 maximum",
);

const usage = {
  inputTokens: { total: 10, noCache: 10, cacheRead: 0, cacheWrite: 0 },
  outputTokens: { total: 1, text: 1, reasoning: undefined },
};

function textStepChunks(): Array<Record<string, unknown>> {
  return [
    { type: "stream-start", warnings: [] },
    { type: "text-start", id: "t" },
    { type: "text-delta", id: "t", delta: "Done" },
    { type: "text-end", id: "t" },
    {
      type: "finish",
      finishReason: { unified: "stop", raw: "stop" },
      usage,
    },
  ];
}

function toolCallChunks(
  toolName: string,
  input: string,
): Array<Record<string, unknown>> {
  return [
    { type: "stream-start", warnings: [] },
    { type: "tool-call", toolCallId: `call-${toolName}`, toolName, input },
    {
      type: "finish",
      finishReason: { unified: "tool-calls", raw: "tool_calls" },
      usage,
    },
  ];
}

interface MockModelSpec {
  steps: Array<
    | { kind: "text" }
    | { kind: "tool-call"; toolName: string; input: string }
    | { kind: "error" }
  >;
  /** Returned by doGenerate for tool-call repair. */
  repairOutput?: string;
}

// One doStream call per step; an "error" step rejects so the provider error
// surfaces through the stream's error part and the recovery paths run.
function mockModel(spec: MockModelSpec): MockLanguageModelV3 {
  let call = 0;
  return new MockLanguageModelV3({
    doStream: async (options: { tools?: Array<{ name: string }> }) => {
      state.providerTools.push(options.tools?.map((t) => t.name) ?? []);
      const step = spec.steps[Math.min(call, spec.steps.length - 1)] ?? {
        kind: "text",
      };
      call++;
      if (step.kind === "error") throw CONTEXT_ERROR;
      const chunks =
        step.kind === "tool-call"
          ? toolCallChunks(step.toolName, step.input)
          : textStepChunks();
      return {
        stream: simulateReadableStream({
          chunks: chunks as unknown as Array<LanguageModelV3StreamPart>,
        }),
      };
    },
    doGenerate: async () => {
      state.generated.push(spec.repairOutput ?? "{}");
      return {
        content: [{ type: "text", text: spec.repairOutput ?? "{}" }],
        finishReason: { unified: "stop", raw: "stop" },
        usage,
        warnings: [],
      };
    },
  });
}

async function drain(stream: { fullStream: AsyncIterable<unknown> }) {
  const parts: Array<Record<string, unknown>> = [];
  for await (const part of stream.fullStream) {
    parts.push(part as Record<string, unknown>);
  }
  return parts;
}

function recordingTool(name: string, schema: z.ZodType) {
  const executions: Array<unknown>[] = [];
  const tool = {
    description: `${name} fixture tool`,
    inputSchema: schema,
    execute: async (input: unknown) => {
      executions.push([input]);
      return `${name} ok`;
    },
  };
  return { tool, executions };
}

// ---------------------------------------------------------------------------
// resolveEffectiveTools (pure)
// ---------------------------------------------------------------------------

describe("resolveEffectiveTools", () => {
  const tools: ToolSet = {
    b: { description: "b", inputSchema: z.object({}) },
    a: { description: "a", inputSchema: z.object({}) },
  };

  it("keeps the caller's ToolSet identity when activeTools is undefined (all tools)", () => {
    expect(resolveEffectiveTools(tools, undefined)).toEqual({});
    expect(resolveEffectiveTools(undefined, ["a"])).toEqual({});
  });

  it("resolves an empty list to no tools advertised and none executable", () => {
    expect(resolveEffectiveTools(tools, [])).toEqual({
      tools: {},
      activeTools: undefined,
    });
  });

  it("filters a nonempty list preserving registry order, dropping activeTools so re-entry is identity", () => {
    const result = resolveEffectiveTools(tools, ["a", "b"]);
    expect(Object.keys(result.tools ?? {})).toEqual(["b", "a"]);
    expect(result.activeTools).toBeUndefined();
    expect(result.tools?.a).toBe(tools.a);
    expect(result.tools?.b).toBe(tools.b);
  });

  it("ignores unknown names and duplicates without throwing", () => {
    const result = resolveEffectiveTools(tools, ["a", "nope", "a"]);
    expect(Object.keys(result.tools ?? {})).toEqual(["a"]);
  });

  it("does not mutate the inputs", () => {
    const activeTools = ["a", "nope"];
    resolveEffectiveTools(tools, activeTools);
    expect(activeTools).toEqual(["a", "nope"]);
    expect(Object.keys(tools)).toEqual(["b", "a"]);
  });

  it("never activates a tool absent from the selection, including response", () => {
    const withResponse: ToolSet = {
      ...tools,
      response: { description: "response", inputSchema: z.object({}) },
    };
    const result = resolveEffectiveTools(withResponse, ["a"]);
    expect(Object.keys(result.tools ?? {})).toEqual(["a"]);
  });

  it("keeps prototype-shaped own names as own keys, not the object prototype", () => {
    const dangerous = Object.fromEntries([
      ["__proto__", { description: "proto tool", inputSchema: z.object({}) }],
      ["constructor", { description: "ctor tool", inputSchema: z.object({}) }],
      ["a", tools.a],
    ]) as ToolSet;
    expect(Object.keys(dangerous)).toEqual(["__proto__", "constructor", "a"]);

    const selected = resolveEffectiveTools(dangerous, [
      "__proto__",
      "constructor",
    ]).tools as ToolSet;
    expect(Object.keys(selected)).toEqual(["__proto__", "constructor"]);
    expect(Object.hasOwn(selected, "__proto__")).toBe(true);
    expect(Object.hasOwn(selected, "constructor")).toBe(true);
    expect(Object.getPrototypeOf(selected)).toBe(Object.prototype);
    expect(selected.__proto__?.description).toBe("proto tool");

    const inactive = resolveEffectiveTools(dangerous, ["a"]).tools as ToolSet;
    expect(Object.keys(inactive)).toEqual(["a"]);
    expect(Object.hasOwn(inactive, "__proto__")).toBe(false);
    expect(Object.getPrototypeOf(inactive)).toBe(Object.prototype);
  });
});

// The sequential-tool-call instruction is budgeted via the same effective
// map; a zero-tool selection must not append it.
describe("effective tools and the sequential-tool-call policy", () => {
  it("appends no instruction for an empty effective toolset on a sequential model", () => {
    const empty = resolveEffectiveTools(
      { a: { description: "a", inputSchema: z.object({}) } },
      [],
    ).tools;
    expect(
      applySequentialToolCallPolicy("Base.", empty, "deepseek.v3-v1:0"),
    ).toBe("Base.");
  });

  it("appends the instruction for a nonempty effective toolset", () => {
    const effective = resolveEffectiveTools(
      { a: { description: "a", inputSchema: z.object({}) } },
      ["a"],
    ).tools;
    expect(
      applySequentialToolCallPolicy("Base.", effective, "deepseek.v3-v1:0"),
    ).toBe(`Base.\n\n${SEQUENTIAL_TOOL_CALL_INSTRUCTION}`);
  });
});

// ---------------------------------------------------------------------------
// SDK integration: real catalog boundary fixture (audit scenario: ~105.7K
// message tokens between the 7-tool and full-catalog budgets)
// ---------------------------------------------------------------------------

const JUDGE_TOOLS = [
  "execute_command",
  "http_request",
  "read_file",
  "list_files",
  "grep",
  "web_search",
  "get_page",
] as const;

function catalogFixture() {
  const root = mkdtempSync(join(tmpdir(), "apex-effective-tools-"));
  const ctx = {
    session: {
      id: "fixture",
      rootPath: root,
      logsPath: join(root, "logs"),
      scratchpadPath: join(root, "scratchpad"),
      findingsPath: join(root, "findings"),
      config: {},
    },
    agentCwd: root,
    sandbox: {
      type: "linux",
      execute: async () => {
        throw new Error("unexpected execution");
      },
    },
  } as never;
  const all = createAllTools(ctx);
  const judgeSet = new Set<string>(JUDGE_TOOLS);
  const effective = Object.fromEntries(
    Object.entries(all).filter(([name]) => judgeSet.has(name)),
  ) as ToolSet;
  const allOverhead = estimateToolsOverheadTokens(all);
  const activeOverhead = estimateToolsOverheadTokens(effective);
  const contextWindow = getContextWindow(MODEL);
  const maxOutputTokens = getMaxOutputTokens(MODEL);
  const budget = (overhead: number) =>
    contextWindow - maxOutputTokens - overhead - 1_000 - 10_000;
  const fullBudget = budget(allOverhead);
  const activeBudget = budget(activeOverhead);
  return {
    root,
    all,
    effective,
    allOverhead,
    activeOverhead,
    fullBudget,
    activeBudget,
  };
}

function boundaryMessages(tokenTarget: number): ModelMessage[] {
  // estimateMessageTokens: 8 structural chars + content; 4 chars/token.
  return [{ role: "user" as const, content: "x".repeat(tokenTarget * 4 - 8) }];
}

describe("effective toolset budgeting (real catalog, real SDK)", () => {
  let fixture: ReturnType<typeof catalogFixture>;

  beforeEach(() => {
    fixture = catalogFixture();
    state.summaries = 0;
    state.providerTools = [];
    state.generated = [];
  });

  afterEach(() => {
    rmSync(fixture.root, { recursive: true, force: true });
    state.model = null;
  });

  it("spans a working boundary: full catalog overflows, effective selection fits", () => {
    // Self-checking precondition — fails loudly if the catalog or model
    // windows change enough to invalidate the fixture.
    expect(JUDGE_TOOLS.every((name) => name in fixture.all)).toBe(true);
    const between = Math.floor((fixture.fullBudget + fixture.activeBudget) / 2);
    expect(between).toBeGreaterThan(fixture.fullBudget);
    expect(between).toBeLessThan(fixture.activeBudget);

    const runFit = (tools: ToolSet) =>
      fitMessagesToContext(boundaryMessages(between), {
        contextWindow: getContextWindow(MODEL),
        maxOutputTokens: getMaxOutputTokens(MODEL),
        tools,
      });
    expect(runFit(fixture.all).fitsBudget).toBe(false);
    expect(runFit(fixture.effective).fitsBudget).toBe(true);
  });

  it("reaches the provider directly at the boundary instead of summarizing", async () => {
    const between = Math.floor((fixture.fullBudget + fixture.activeBudget) / 2);
    state.model = mockModel({ steps: [{ kind: "text" }] });

    await drain(
      streamResponse({
        model: MODEL,
        prompt: "fixture",
        messages: boundaryMessages(between),
        tools: fixture.all,
        activeTools: [...JUDGE_TOOLS],
        silent: true,
      }),
    );

    expect(state.summaries).toBe(0);
    expect(state.providerTools).toEqual([[...JUDGE_TOOLS]]);
  });

  it("still escalates to summarization when the effective selection itself overflows", async () => {
    const over = fixture.activeBudget + 20_000;
    state.model = mockModel({ steps: [{ kind: "text" }] });

    await drain(
      streamResponse({
        model: MODEL,
        prompt: "fixture",
        messages: boundaryMessages(over),
        tools: fixture.all,
        activeTools: [...JUDGE_TOOLS],
        silent: true,
        sessionPath: fixture.root,
      }),
    );

    expect(state.summaries).toBe(1);
    expect(state.providerTools).toEqual([]);
  });

  it("recovers from a provider context error using the effective budget, without summarizing", async () => {
    // Start between the budgets (fits effective proactively, would overflow
    // the full catalog). Step 1's tool result is oversized past even the
    // effective budget, so step 2 is rejected by the provider and the
    // reactive fit must truncate against the SELECTED schema overhead and
    // retry with the same 7 schemas.
    const between = Math.floor((fixture.fullBudget + fixture.activeBudget) / 2);
    const bigResultTool = {
      description: "grows the context past the effective budget",
      inputSchema: z.object({}),
      execute: async () => "y".repeat((fixture.activeBudget + 5_000) * 4),
    };
    const tools: ToolSet = { ...fixture.all, grep: bigResultTool };

    state.model = mockModel({
      steps: [
        { kind: "tool-call", toolName: "grep", input: "{}" },
        { kind: "error" },
        { kind: "text" },
      ],
    });

    const parts = await drain(
      streamResponse({
        model: MODEL,
        prompt: "fixture",
        messages: boundaryMessages(between),
        tools,
        activeTools: [...JUDGE_TOOLS],
        stopWhen: stepCountIs(5),
        silent: true,
        sessionPath: fixture.root,
      }),
    );

    expect(state.summaries).toBe(0);
    expect(parts.some((p) => p.type === "error")).toBe(false);
    expect(state.providerTools).toHaveLength(3);
    expect(state.providerTools[0]).toEqual([...JUDGE_TOOLS]);
    expect(state.providerTools[2]).toEqual([...JUDGE_TOOLS]);
    // Layer 1 persisted the oversized tool result for the reactive retry.
    expect(readdirSync(join(fixture.root, "tool-results"))).toHaveLength(1);
  });
});

// ---------------------------------------------------------------------------
// SDK integration: advertisement/execution/repair gating matrix
// ---------------------------------------------------------------------------

describe("effective toolset advertisement and execution", () => {
  let executions: { a: number; b: number; response: number };

  beforeEach(() => {
    executions = { a: 0, b: 0, response: 0 };
    state.summaries = 0;
    state.providerTools = [];
    state.generated = [];
  });

  afterEach(() => {
    state.model = null;
  });

  function fixtureTools(): ToolSet {
    const counter = (name: keyof typeof executions) => ({
      description: `${name} fixture`,
      inputSchema: z.object({ q: z.string() }),
      execute: async () => {
        executions[name]++;
        return `${name} ok`;
      },
    });
    return {
      b: counter("b"),
      a: counter("a"),
      response: counter("response"),
    };
  }

  it("advertises every tool when activeTools is undefined", async () => {
    state.model = mockModel({ steps: [{ kind: "text" }] });
    await drain(
      streamResponse({
        model: MODEL,
        prompt: "fixture",
        tools: fixtureTools(),
        silent: true,
      }),
    );
    expect(state.providerTools).toEqual([["b", "a", "response"]]);
  });

  it("advertises no tools for an empty list and executes nothing", async () => {
    state.model = mockModel({
      steps: [{ kind: "tool-call", toolName: "a", input: '{"q":"x"}' }],
    });
    const parts = await drain(
      streamResponse({
        model: MODEL,
        prompt: "fixture",
        tools: fixtureTools(),
        activeTools: [],
        silent: true,
      }),
    );
    expect(state.providerTools).toEqual([[]]);
    expect(executions).toEqual({ a: 0, b: 0, response: 0 });
    expect(state.generated).toEqual([]);
    const toolCall = parts.find((p) => p.type === "tool-call");
    expect(toolCall?.invalid).toBe(true);
  });

  it("executes a call to a selected tool but not to an unselected one", async () => {
    state.model = mockModel({
      steps: [
        { kind: "tool-call", toolName: "a", input: '{"q":"x"}' },
        { kind: "tool-call", toolName: "b", input: '{"q":"x"}' },
      ],
    });
    await drain(
      streamResponse({
        model: MODEL,
        prompt: "fixture",
        tools: fixtureTools(),
        activeTools: ["a"],
        stopWhen: stepCountIs(3),
        silent: true,
      }),
    );
    expect(executions).toEqual({ a: 1, b: 0, response: 0 });
  });

  it("keeps the response tool explicit: included when listed, inert when omitted", async () => {
    state.model = mockModel({
      steps: [{ kind: "tool-call", toolName: "response", input: '{"q":"x"}' }],
    });
    const omitted = await drain(
      streamResponse({
        model: MODEL,
        prompt: "fixture",
        tools: fixtureTools(),
        activeTools: ["a"],
        silent: true,
      }),
    );
    expect(state.providerTools).toEqual([["a"]]);
    expect(executions.response).toBe(0);
    expect(state.generated).toEqual([]);
    expect(omitted.find((p) => p.type === "tool-call")?.invalid).toBe(true);

    executions.response = 0;
    state.providerTools = [];
    state.model = mockModel({
      steps: [{ kind: "tool-call", toolName: "response", input: '{"q":"x"}' }],
    });
    await drain(
      streamResponse({
        model: MODEL,
        prompt: "fixture",
        tools: fixtureTools(),
        activeTools: ["a", "response"],
        silent: true,
      }),
    );
    expect(state.providerTools).toEqual([["a", "response"]]);
    expect(executions.response).toBe(1);
  });

  it("repairs a malformed call to a selected tool and never repairs or executes an unselected one", async () => {
    state.model = mockModel({
      steps: [{ kind: "tool-call", toolName: "a", input: "not-json" }],
      repairOutput: '{"q":"repaired"}',
    });
    const repairedParts = await drain(
      streamResponse({
        model: MODEL,
        prompt: "fixture",
        tools: fixtureTools(),
        activeTools: ["a"],
        silent: true,
      }),
    );
    expect(state.generated).toEqual(['{"q":"repaired"}']);
    expect(executions.a).toBe(1);
    const repairedCall = repairedParts.find((p) => p.type === "tool-call");
    expect((repairedCall?.input as { q?: string })?.q).toBe("repaired");

    state.generated = [];
    executions.a = 0;
    state.providerTools = [];
    state.model = mockModel({
      steps: [{ kind: "tool-call", toolName: "b", input: '{"q":"x"}' }],
    });
    await drain(
      streamResponse({
        model: MODEL,
        prompt: "fixture",
        tools: fixtureTools(),
        activeTools: ["a"],
        silent: true,
      }),
    );
    // b is executable in the full map but unselected: no repair generation,
    // no execution — the invalid call surfaces instead.
    expect(state.generated).toEqual([]);
    expect(executions).toEqual({ a: 0, b: 0, response: 0 });
  });

  it("advertises and executes a selected tool named __proto__ through the real SDK", async () => {
    const protoTool = {
      description: "prototype-shaped own name",
      inputSchema: z.object({ q: z.string() }),
      execute: async () => "proto ok",
    };
    const tools = Object.fromEntries([
      ["__proto__", protoTool],
      [
        "a",
        {
          description: "a fixture",
          inputSchema: z.object({ q: z.string() }),
          execute: async () => {
            executions.a++;
            return "a ok";
          },
        },
      ],
    ]) as ToolSet;
    // The fixture must carry __proto__ as an OWN key; a plain object literal
    // would instead mutate the prototype.
    expect(Object.hasOwn(tools, "__proto__")).toBe(true);

    state.model = mockModel({
      steps: [{ kind: "tool-call", toolName: "__proto__", input: '{"q":"x"}' }],
    });
    const parts = await drain(
      streamResponse({
        model: MODEL,
        prompt: "fixture",
        tools,
        activeTools: ["__proto__", "a"],
        silent: true,
      }),
    );

    expect(state.providerTools).toEqual([["__proto__", "a"]]);
    expect(parts.some((p) => p.type === "error")).toBe(false);
    const protoResult = parts.find(
      (p) => p.type === "tool-result" && p.toolName === "__proto__",
    );
    expect(protoResult).toBeDefined();
    expect(executions.a).toBe(0);
  });
});

// ---------------------------------------------------------------------------
// Continuation reuse: every fit sees the SAME effective map (object identity),
// so the schema-overhead WeakMap in contextManagement stays warm across the
// initial call and the reactive overflow retry.
// ---------------------------------------------------------------------------

describe("effective toolset reuse across recovery", () => {
  it("passes one effective map reference to the initial and reactive fits", async () => {
    const fixture = catalogFixture();
    const between = Math.floor((fixture.fullBudget + fixture.activeBudget) / 2);
    const bigResultTool = {
      description: "grows the context past the effective budget",
      inputSchema: z.object({}),
      execute: async () => "y".repeat((fixture.activeBudget + 5_000) * 4),
    };
    const tools: ToolSet = { ...fixture.all, grep: bigResultTool };

    const contextManagement = await import("./contextManagement");
    const realFit = contextManagement.fitMessagesToContext;
    // Record EVERY invocation — including undefined/empty tools — so a bad
    // reactive map cannot hide behind the filter. Synchronous passthrough:
    // the production function is sync and ai.ts reads the result sync.
    const recorded: Array<{ tools?: ToolSet; trigger?: string }> = [];
    const spy = vi.spyOn(contextManagement, "fitMessagesToContext");
    spy.mockImplementation((messages, opts) => {
      recorded.push({ tools: opts.tools, trigger: opts.telemetry?.trigger });
      return realFit(messages, opts);
    });

    state.summaries = 0;
    state.providerTools = [];
    state.model = mockModel({
      steps: [
        { kind: "tool-call", toolName: "grep", input: "{}" },
        { kind: "error" },
        { kind: "text" },
      ],
    });

    try {
      await drain(
        streamResponse({
          model: MODEL,
          prompt: "fixture",
          messages: boundaryMessages(between),
          tools,
          activeTools: [...JUDGE_TOOLS],
          stopWhen: stepCountIs(5),
          silent: true,
          sessionPath: fixture.root,
        }),
      );
    } finally {
      spy.mockRestore();
      rmSync(fixture.root, { recursive: true, force: true });
      state.model = null;
    }

    // Reactive overflow recovery actually ran: the provider error was
    // classified as a context overflow (ai.ts supplies this trigger on the
    // reactive fit) and the recovery fit executed without summarizing.
    expect(state.summaries).toBe(0);
    expect(recorded.some((call) => call.trigger === "context_overflow")).toBe(
      true,
    );
    const judgeKey = JUDGE_TOOLS.join(",");
    expect(recorded.length).toBeGreaterThanOrEqual(2);
    // EVERY recorded fit (proactive and reactive alike) carries the seven
    // selected keys and the SAME map reference.
    for (const call of recorded) {
      expect(Object.keys(call.tools ?? {}).join(",")).toBe(judgeKey);
      expect(call.tools).toBe(recorded[0]?.tools);
    }
  });
});
