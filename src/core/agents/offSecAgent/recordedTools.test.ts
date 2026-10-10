import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { ToolExecutionOptions, ToolResultPart, ToolSet } from "ai";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { ToolExecutionRecorder } from "../../runtime/runToolStore";
import { wrapRecordedTools } from "./recordedTools";

type SettledOutput = ToolResultPart["output"];
type WiredTool = {
  execute: (i: unknown, o: ToolExecutionOptions) => Promise<unknown>;
  toModelOutput: (c: unknown) => Promise<SettledOutput>;
};

// ---------------------------------------------------------------------------
// Unit harness: fake recorder + minimal tools. Input validation and repair
// happen in the SDK before execute — the wrapper only ever sees validated
// input, so these tests pass input directly at that boundary.
// ---------------------------------------------------------------------------

type Gate = { kind: "execute" } | { kind: "reuse"; output: SettledOutput };

function fakeRecorder(overrides: Partial<ToolExecutionRecorder> = {}) {
  const before: Array<{
    toolCallId: string;
    toolName: string;
    input: unknown;
  }> = [];
  const settles: Array<{ toolCallId: string; output: SettledOutput }> = [];
  const unknowns: string[] = [];
  const recorder: ToolExecutionRecorder = {
    beforeExecute: async (input) => {
      before.push(input);
      return { kind: "execute" };
    },
    settle: async (toolCallId, output) => {
      settles.push({ toolCallId, output });
    },
    unknown: async (toolCallId) => {
      unknowns.push(toolCallId);
    },
    flush: async () => {},
    ...overrides,
  };
  return { recorder, before, settles, unknowns };
}

const OPTIONS = (
  overrides: Partial<ToolExecutionOptions> = {},
): ToolExecutionOptions =>
  ({
    toolCallId: "tc_1",
    messages: [],
    ...overrides,
  }) as ToolExecutionOptions;

function makeTool(overrides: Record<string, unknown> = {}) {
  const tool = {
    description: "probe tool",
    inputSchema: { type: "object" },
    customMetadata: "kept",
    execute: vi.fn(async (input: unknown) => ({ ok: true, input })),
    ...overrides,
  };
  return tool;
}

function modelOutputCall(
  toolCallId: string,
  output: unknown,
): { toolCallId: string; input: unknown; output: unknown } {
  return { toolCallId, input: undefined, output };
}

beforeEach(() => {
  vi.restoreAllMocks();
});

afterEach(() => {
  vi.restoreAllMocks();
});

describe("wrapRecordedTools metadata passthrough", () => {
  it("preserves original tool metadata and leaves execute-less tools untouched", () => {
    const { recorder } = fakeRecorder();
    const probe = makeTool();
    const passthrough = { description: "no execute", inputSchema: {} };
    const wrapped = wrapRecordedTools(
      { probe: probe as never, passthrough: passthrough as never },
      recorder,
    );

    expect((wrapped.probe as Record<string, unknown>).description).toBe(
      "probe tool",
    );
    expect((wrapped.probe as Record<string, unknown>).inputSchema).toBe(
      probe.inputSchema,
    );
    expect((wrapped.probe as Record<string, unknown>).customMetadata).toBe(
      "kept",
    );
    expect(typeof (wrapped.probe as Record<string, unknown>).execute).toBe(
      "function",
    );
    expect(wrapped.passthrough).toBe(passthrough);
  });
});

describe("wrapRecordedTools dispatch and settlement", () => {
  it("commits intent before the effect and settles the exact model-visible JSON output", async () => {
    const { recorder, before, settles } = fakeRecorder();
    const probe = makeTool();
    const wrapped = wrapRecordedTools({ probe: probe as never }, recorder);

    const result = await (
      wrapped.probe as {
        execute: (i: unknown, o: ToolExecutionOptions) => Promise<unknown>;
      }
    ).execute({ q: "x" }, OPTIONS());

    // Raw return preserved for UI/event compatibility.
    expect(result).toEqual({ ok: true, input: { q: "x" } });
    expect(probe.execute).toHaveBeenCalledTimes(1);
    expect(before).toEqual([
      { toolCallId: "tc_1", toolName: "probe", input: { q: "x" } },
    ]);
    // SDK default conversion mirrored: object → json.
    expect(settles).toEqual([
      { toolCallId: "tc_1", output: { type: "json", value: result } },
    ]);
  });

  it("mirrors the SDK default for string and undefined outputs", async () => {
    const { recorder, settles } = fakeRecorder();
    const text = makeTool({ execute: vi.fn(async () => "plain text") });
    const empty = makeTool({ execute: vi.fn(async () => undefined) });
    const wrapped = wrapRecordedTools(
      { text: text as never, empty: empty as never },
      recorder,
    );

    await (
      wrapped.text as {
        execute: (i: unknown, o: ToolExecutionOptions) => Promise<unknown>;
      }
    ).execute({}, OPTIONS({ toolCallId: "tc_text" }));
    await (
      wrapped.empty as {
        execute: (i: unknown, o: ToolExecutionOptions) => Promise<unknown>;
      }
    ).execute({}, OPTIONS({ toolCallId: "tc_empty" }));

    expect(settles).toEqual([
      { toolCallId: "tc_text", output: { type: "text", value: "plain text" } },
      // toJSONValue(undefined) === null.
      { toolCallId: "tc_empty", output: { type: "json", value: null } },
    ]);
  });

  it("computes a custom toModelOutput exactly once and caches it across repeated SDK conversions", async () => {
    const { recorder, settles } = fakeRecorder();
    let conversions = 0;
    const probe = makeTool({
      // A spill-writing converter: each legacy invocation would mint a new
      // retained-output file. The wrapper must run it once per call.
      toModelOutput: vi.fn(async () => {
        conversions++;
        return { type: "text", value: `tool-output:${conversions}` };
      }),
    });
    const wrapped = wrapRecordedTools({ probe: probe as never }, recorder);
    const tool = wrapped.probe as unknown as WiredTool;

    await tool.execute({}, OPTIONS());

    // The SDK converts the same result at stream-emit, step-content, and
    // later-turn message re-conversion — all must hit the cache.
    const first = await tool.toModelOutput(modelOutputCall("tc_1", {}));
    const second = await tool.toModelOutput(modelOutputCall("tc_1", {}));
    const third = await tool.toModelOutput(modelOutputCall("tc_1", {}));
    expect(first).toEqual({ type: "text", value: "tool-output:1" });
    expect(second).toEqual(first);
    expect(third).toEqual(first);
    expect(conversions).toBe(1);
    // Settlement carries the exact conversion the model will see.
    expect(settles).toEqual([
      { toolCallId: "tc_1", output: { type: "text", value: "tool-output:1" } },
    ]);
  });

  it("serves the settled conversion for bounded artifact outputs without re-running the converter", async () => {
    const { recorder } = fakeRecorder();
    const bounded = { type: "text", value: "tool-output:uuid\nCaptured…" };
    const probe = makeTool({
      toModelOutput: vi.fn(async () => bounded),
    });
    const wrapped = wrapRecordedTools({ probe: probe as never }, recorder);
    const tool = wrapped.probe as unknown as WiredTool;

    await tool.execute({}, OPTIONS());
    await tool.toModelOutput(modelOutputCall("tc_1", {}));
    await tool.toModelOutput(modelOutputCall("tc_1", {}));

    expect(
      (probe as unknown as { toModelOutput: unknown }).toModelOutput,
    ).toHaveBeenCalledTimes(1);
    expect(await tool.toModelOutput(modelOutputCall("tc_1", {}))).toEqual(
      bounded,
    );
  });
});

describe("wrapRecordedTools reuse", () => {
  it("never reruns the implementation or conversion for a settled call", async () => {
    const { recorder, settles, unknowns } = fakeRecorder({
      beforeExecute: async () => ({
        kind: "reuse",
        output: { type: "json", value: { cached: true } },
      }),
    });
    const probe = makeTool({
      toModelOutput: vi.fn(async () => {
        throw new Error("conversion must not rerun on reuse");
      }),
    });
    const wrapped = wrapRecordedTools({ probe: probe as never }, recorder);
    const tool = wrapped.probe as unknown as WiredTool;

    const raw = await tool.execute({}, OPTIONS());
    expect(probe.execute).not.toHaveBeenCalled();
    // Suitable raw representation of the settled outcome.
    expect(raw).toEqual({ cached: true });
    expect(await tool.toModelOutput(modelOutputCall("tc_1", raw))).toEqual({
      type: "json",
      value: { cached: true },
    });
    expect(settles).toEqual([]);
    expect(unknowns).toEqual([]);
  });

  it("a reused json result cannot poison the conversion cache by in-place mutation", async () => {
    const { recorder } = fakeRecorder({
      beforeExecute: async () => ({
        kind: "reuse",
        output: { type: "json", value: { cached: true } },
      }),
    });
    const probe = makeTool();
    const wrapped = wrapRecordedTools({ probe: probe as never }, recorder);
    const tool = wrapped.probe as unknown as WiredTool;

    const raw = (await tool.execute({}, OPTIONS())) as { cached: boolean };
    raw.cached = false; // the SDK owns the execute result and may mutate it

    expect(await tool.toModelOutput(modelOutputCall("tc_1", raw))).toEqual({
      type: "json",
      value: { cached: true },
    });
  });

  it("a reused non-text/json result cannot poison the conversion cache by in-place mutation", async () => {
    const { recorder } = fakeRecorder({
      beforeExecute: async () => ({
        kind: "reuse",
        output: { type: "error-json", value: { code: "E1" } },
      }),
    });
    const probe = makeTool();
    const wrapped = wrapRecordedTools({ probe: probe as never }, recorder);
    const tool = wrapped.probe as unknown as WiredTool;

    const raw = (await tool.execute({}, OPTIONS())) as {
      type: string;
      value: { code: string };
    };
    raw.value.code = "MUTATED";

    expect(await tool.toModelOutput(modelOutputCall("tc_1", raw))).toEqual({
      type: "error-json",
      value: { code: "E1" },
    });
  });
});

describe("wrapRecordedTools failure semantics", () => {
  it("treats an abort after the intent gate as an unknown outcome", async () => {
    const { recorder, unknowns, settles } = fakeRecorder();
    const probe = makeTool();
    const wrapped = wrapRecordedTools({ probe: probe as never }, recorder);
    const controller = new AbortController();
    controller.abort();

    await expect(
      (wrapped.probe as unknown as WiredTool).execute(
        {},
        OPTIONS({ abortSignal: controller.signal }),
      ),
    ).rejects.toMatchObject({ name: "AbortError" });

    expect(probe.execute).not.toHaveBeenCalled();
    expect(unknowns).toEqual(["tc_1"]);
    expect(settles).toEqual([]);
  });

  it("marks unknown and rethrows the original error when execute throws", async () => {
    const { recorder, unknowns, settles } = fakeRecorder();
    const sentinel = new Error("shell exploded");
    const probe = makeTool({
      execute: vi.fn(async () => {
        throw sentinel;
      }),
    });
    const wrapped = wrapRecordedTools({ probe: probe as never }, recorder);

    await expect(
      (wrapped.probe as unknown as WiredTool).execute({}, OPTIONS()),
    ).rejects.toBe(sentinel);

    expect(unknowns).toEqual(["tc_1"]);
    expect(settles).toEqual([]);
  });

  it("marks unknown and rethrows when the conversion throws", async () => {
    const { recorder, unknowns, settles } = fakeRecorder();
    const sentinel = new Error("spill write failed");
    const probe = makeTool({
      toModelOutput: vi.fn(async () => {
        throw sentinel;
      }),
    });
    const wrapped = wrapRecordedTools({ probe: probe as never }, recorder);

    await expect(
      (wrapped.probe as unknown as WiredTool).execute({}, OPTIONS()),
    ).rejects.toBe(sentinel);

    expect(probe.execute).toHaveBeenCalledTimes(1);
    expect(unknowns).toEqual(["tc_1"]);
    expect(settles).toEqual([]);
  });

  it("does not return the result when settlement fails; the settle error propagates", async () => {
    const settleFailure = new Error("journal store unreachable");
    const { recorder, unknowns } = fakeRecorder({
      settle: async () => {
        throw settleFailure;
      },
    });
    const probe = makeTool();
    const wrapped = wrapRecordedTools({ probe: probe as never }, recorder);

    await expect(
      (wrapped.probe as unknown as WiredTool).execute({}, OPTIONS()),
    ).rejects.toBe(settleFailure);

    expect(probe.execute).toHaveBeenCalledTimes(1);
    // The effect happened but the result never surfaces; unknown is the
    // honest recorded state (a latched recorder swallows the unknown write).
    expect(unknowns).toEqual(["tc_1"]);
  });

  it("rejects streaming tool output explicitly", async () => {
    const { recorder, unknowns } = fakeRecorder();
    const probe = makeTool({
      execute: vi.fn(async function* () {
        yield "preliminary";
      }),
    });
    const wrapped = wrapRecordedTools({ probe: probe as never }, recorder);

    await expect(
      (wrapped.probe as unknown as WiredTool).execute({}, OPTIONS()),
    ).rejects.toThrow("Streaming tool output is not supported");

    expect(probe.execute).toHaveBeenCalledTimes(1);
    expect(unknowns).toEqual(["tc_1"]);
  });
});

describe("wrapRecordedTools snapshot isolation", () => {
  it("commits and executes the same snapshot when the caller mutates input during the intent wait", async () => {
    let releaseGate!: () => void;
    const intentGate = new Promise<void>((resolve) => {
      releaseGate = resolve;
    });
    const { recorder, before } = fakeRecorder({
      beforeExecute: async (input) => {
        before.push(input);
        await intentGate;
        return { kind: "execute" };
      },
    });
    const probe = makeTool({
      execute: vi.fn(async (input: unknown) => ({ got: input })),
    });
    const wrapped = wrapRecordedTools({ probe: probe as never }, recorder);
    const tool = wrapped.probe as unknown as WiredTool;

    const input = { q: "x" };
    const pending = tool.execute(input, OPTIONS());
    await vi.waitFor(() => expect(before).toHaveLength(1));
    input.q = "mutated"; // caller mutation during the intent wait
    releaseGate();

    const raw = (await pending) as { got: { q: string } };
    expect(before[0]?.input).toEqual({ q: "x" });
    expect(raw.got).toEqual({ q: "x" });
  });

  it("snapshots the conversion before settlement; raw mutation cannot diverge from the persisted output", async () => {
    let releaseSettle!: () => void;
    const settleGate = new Promise<void>((resolve) => {
      releaseSettle = resolve;
    });
    const { recorder, settles } = fakeRecorder({
      settle: async (toolCallId, output) => {
        settles.push({ toolCallId, output });
        await settleGate;
      },
    });
    const shared = { lines: ["a"] };
    const probe = makeTool({ execute: vi.fn(async () => shared) });
    const wrapped = wrapRecordedTools({ probe: probe as never }, recorder);
    const tool = wrapped.probe as unknown as WiredTool;

    const pending = tool.execute({}, OPTIONS());
    await vi.waitFor(() => expect(settles).toHaveLength(1));
    shared.lines.push("mutated"); // raw-result mutation while settlement waits
    releaseSettle();
    const raw = await pending;

    // The raw return stays the live object for UI/event compatibility.
    expect(raw).toBe(shared);
    // What settled — and what the cache serves — is the pre-mutation snapshot.
    expect(settles[0]?.output).toEqual({
      type: "json",
      value: { lines: ["a"] },
    });
    expect(await tool.toModelOutput(modelOutputCall("tc_1", {}))).toEqual({
      type: "json",
      value: { lines: ["a"] },
    });
  });

  it("serves detached cache values: mutating a served conversion cannot poison the cache", async () => {
    const { recorder } = fakeRecorder();
    const probe = makeTool();
    const wrapped = wrapRecordedTools({ probe: probe as never }, recorder);
    const tool = wrapped.probe as unknown as WiredTool;
    await tool.execute({}, OPTIONS());

    const served = (await tool.toModelOutput(
      modelOutputCall("tc_1", {}),
    )) as unknown as { value: { ok: boolean } };
    served.value.ok = false;
    expect(await tool.toModelOutput(modelOutputCall("tc_1", {}))).toEqual({
      type: "json",
      value: { ok: true, input: {} },
    });
  });
});

// ---------------------------------------------------------------------------
// Agent wiring: the journal wraps the merged toolset only when the input
// provides a recorder, and sits inside the approval gate.
// ---------------------------------------------------------------------------

const streamResponseCalls = vi.hoisted(() => [] as Array<{ tools: ToolSet }>);

vi.mock("zod", () => {
  const handler: ProxyHandler<CallableFunction> = {
    get: () => new Proxy(() => {}, handler),
    apply: () => new Proxy(() => {}, handler),
  };
  const z = new Proxy(() => {}, handler);
  return { z, default: z };
});

vi.mock("./tools", () => ({
  createToolsForNames: () => ({}),
  createResponseTool: () => ({}),
  RESPONSE_TOOL_NAME: "response",
  listToolRegistryNames: () => [],
  ASK_USER_QUESTIONS_TOOL_NAME: "ask_user_questions",
  WORKSPACE_TOOL_NAMES: [],
  WORKSPACE_WRITE_TOOL_NAMES: [],
  PLAN_MODE_TOOL_NAMES: [],
  FAST_STRIKE_EXCLUDED_TOOL_NAMES: [],
  EMAIL_TOOL_NAMES_ACTIVE: [],
  SEND_EMAIL_TOOL_NAME: "send_email",
  SMS_TOOL_NAMES_ACTIVE: [],
  sessionHasSmsPasswordless: () => false,
  PerCommandShell: class {},
  PlaywrightMcpSession: class {},
  resolveBrowserHeaderPolicy: () => ({ allowedHosts: [], headers: {} }),
  CallbackListenerRegistry: class {
    async stopAll() {
      return [];
    }
  },
  createToolsForNamesUnused: () => ({}),
}));

vi.mock("../../ai", () => ({
  streamResponse: (opts: { tools: ToolSet }) => {
    streamResponseCalls.push(opts);
    return { fullStream: (async function* () {})() };
  },
  normalizeStepUsage: () => ({
    inputTokens: 0,
    outputTokens: 0,
    cacheReadTokens: 0,
    cacheWriteTokens: 0,
  }),
}));

const { OffensiveSecurityAgent } = await import("./offensiveSecurityAgent");

describe("OffensiveSecurityAgent tool journal wiring", () => {
  let tempDirs: string[];

  beforeEach(() => {
    streamResponseCalls.length = 0;
    tempDirs = [];
  });

  afterEach(() => {
    for (const dir of tempDirs) rmSync(dir, { recursive: true, force: true });
  });

  function makeSession() {
    const rootPath = mkdtempSync(join(tmpdir(), "recorded-tools-wiring-"));
    tempDirs.push(rootPath);
    return {
      id: "ses_recorded_tools",
      rootPath,
      scratchpadPath: join(rootPath, "scratchpad"),
      targets: [],
    };
  }

  it("wraps extraTools with the recorder when toolExecutionRecorder is provided", async () => {
    const { recorder, before } = fakeRecorder();
    const probe = makeTool();
    const agent = new OffensiveSecurityAgent({
      prompt: "recorded run",
      model: "test-model",
      session: makeSession() as never,
      activeTools: [],
      extraTools: { probe: probe as never },
      toolExecutionRecorder: recorder,
    } as never);
    void agent.streamResult; // createStream is lazy — force construction

    const wiredProbe = streamResponseCalls[0].tools.probe as unknown as {
      execute: (i: unknown, o: ToolExecutionOptions) => Promise<unknown>;
    };
    expect(wiredProbe.execute).not.toBe(probe.execute);

    await wiredProbe.execute({ q: "x" }, OPTIONS());
    expect(before).toEqual([
      { toolCallId: "tc_1", toolName: "probe", input: { q: "x" } },
    ]);
    expect(probe.execute).toHaveBeenCalledTimes(1);
  });

  it("leaves tools untouched when no recorder is provided", async () => {
    const probe = makeTool();
    const agent = new OffensiveSecurityAgent({
      prompt: "legacy run",
      model: "test-model",
      session: makeSession() as never,
      activeTools: [],
      extraTools: { probe: probe as never },
    } as never);
    void agent.streamResult;

    expect(streamResponseCalls[0].tools.probe).toBe(probe as never);
  });
});
