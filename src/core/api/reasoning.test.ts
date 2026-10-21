import { beforeEach, describe, expect, it, vi } from "vitest";
import type { ReasoningSetting } from "../ai";
import type { SessionInfo } from "../session";
import { runOffensiveSecurityAgent } from "./offesecAgent";
import { startTargetedPentestAgent } from "./targetedPentest";

const mocks = vi.hoisted(() => {
  const inputs: Array<Record<string, unknown>> = [];
  const consume = vi.fn(async () => ({ findings: [] }));
  const update = vi.fn();
  const abortAndDrain = vi.fn(async () => {});
  class Agent {
    session: unknown;
    streamResult = {};
    eventBus = { on: vi.fn() };
    drained = Promise.resolve();
    consume = consume;
    abortAndDrain = abortAndDrain;
    constructor(input: Record<string, unknown>) {
      inputs.push(input);
      this.session = input.session;
    }
  }
  return { inputs, consume, update, abortAndDrain, Agent };
});
vi.mock("../agents/offSecAgent", () => ({
  OffensiveSecurityAgent: mocks.Agent,
}));
vi.mock("../agents/specialized/pentest/agent", () => ({
  TargetedPentestAgent: mocks.Agent,
}));
vi.mock("../session", () => ({
  sessions: { updateModelReasoning: mocks.update },
}));

function session(model = "gpt-6.1-sol", setting: ReasoningSetting = "low") {
  return {
    id: "root",
    config: { modelReasoning: { model, setting } },
  } as SessionInfo;
}
beforeEach(() => {
  mocks.inputs.length = 0;
  mocks.consume.mockClear();
  mocks.abortAndDrain.mockClear();
  mocks.update
    .mockReset()
    .mockImplementation(async (_id, model, setting) => session(model, setting));
});

describe.each([
  {
    name: "generic",
    run: (input: Record<string, unknown>) =>
      runOffensiveSecurityAgent(input as never),
  },
  {
    name: "targeted",
    run: (input: Record<string, unknown>) =>
      startTargetedPentestAgent(input as never).result,
  },
])("$name root reasoning", ({ run }) => {
  it.each([
    {
      name: "matching saved selection",
      overrides: {},
      expected: "low",
      persists: false,
    },
    {
      name: "explicit override",
      overrides: { reasoning: "high" },
      expected: "high",
      persists: true,
    },
    {
      name: "explicit default",
      overrides: { reasoning: "default" },
      expected: "default",
      persists: true,
    },
    {
      name: "saved ahead of legacy",
      overrides: { openAIReasoningEffort: "high" },
      expected: "low",
      persists: false,
    },
    {
      name: "model switch",
      overrides: { model: "gpt-5" },
      expected: "medium",
      persists: false,
    },
    {
      name: "legacy fallback on model switch",
      overrides: {
        model: "concentrate:glm-5.3",
        openAIReasoningEffort: "xhigh",
      },
      expected: "max",
      persists: false,
    },
    {
      name: "explicit none",
      overrides: { model: "gpt-5.1", reasoning: "none" },
      expected: "none",
      persists: true,
    },
    {
      name: "explicit disabled",
      overrides: { model: "claude-sonnet-4-5", reasoning: "disabled" },
      expected: "disabled",
      persists: true,
    },
    {
      name: "child override",
      overrides: { subagentId: "child", reasoning: "high" },
      expected: "high",
      persists: false,
    },
    {
      name: "child with no inherited choice",
      overrides: { subagentId: "child" },
      expected: "medium",
      persists: false,
    },
  ])("resolves $name before constructing the agent", async ({
    overrides,
    expected,
    persists,
  }) => {
    const saved = session();
    const input = {
      session: saved,
      model: "gpt-6.1-sol",
      eventBus: {},
      ...overrides,
    };
    await run(input);
    expect(mocks.inputs).toHaveLength(1);
    expect(mocks.inputs[0]).toMatchObject({
      model: input.model,
      reasoning: expected,
    });
    expect(mocks.update).toHaveBeenCalledTimes(persists ? 1 : 0);
    if (persists) {
      expect(mocks.update).toHaveBeenCalledWith("root", input.model, expected);
      expect(
        (mocks.inputs[0].session as SessionInfo).config?.modelReasoning,
      ).toEqual({ model: input.model, setting: expected });
    }
    expect(saved.config?.modelReasoning).toEqual({
      model: "gpt-6.1-sol",
      setting: "low",
    });
  });

  it("rejects unsupported explicit settings before construction or persistence", async () => {
    await expect(async () =>
      run({ session: session(), model: "gpt-6.1-sol", reasoning: "none" }),
    ).rejects.toThrow("not supported");
    expect(mocks.inputs).toHaveLength(0);
    expect(mocks.update).not.toHaveBeenCalled();
  });
});

describe("targeted reasoning persistence lifecycle", () => {
  function pendingSave() {
    let resolve!: (session: SessionInfo) => void;
    mocks.update.mockReturnValue(
      new Promise<SessionInfo>((done) => {
        resolve = done;
      }),
    );
    const handle = startTargetedPentestAgent({
      session: session(),
      model: "gpt-6.1-sol",
      reasoning: "high",
      eventBus: {},
    } as never);
    return { handle, resolve };
  }
  it("returns a handle immediately and waits for persistence before constructing", async () => {
    const { handle, resolve } = pendingSave();
    expect(mocks.inputs).toHaveLength(0);
    resolve(session("gpt-6.1-sol", "high"));
    await handle.result;
    expect(mocks.consume).toHaveBeenCalledOnce();
    await handle.abortAndDrain();
    expect(mocks.abortAndDrain).toHaveBeenCalledOnce();
    await handle.drained;
  });
  it("does not start a late agent after teardown while persistence is pending", async () => {
    const { handle, resolve } = pendingSave();
    await handle.abortAndDrain();
    resolve(session("gpt-6.1-sol", "high"));
    await expect(handle.result).rejects.toMatchObject({ name: "AbortError" });
    await handle.drained;
    expect(mocks.inputs).toHaveLength(0);
    expect(mocks.consume).not.toHaveBeenCalled();
  });
  it("propagates persistence failure without starting the agent", async () => {
    mocks.update.mockRejectedValue(new Error("save failed"));
    const handle = startTargetedPentestAgent({
      session: session(),
      model: "gpt-6.1-sol",
      reasoning: "high",
    } as never);
    await expect(handle.result).rejects.toThrow("save failed");
    await handle.drained;
    expect(mocks.inputs).toHaveLength(0);
  });
});
