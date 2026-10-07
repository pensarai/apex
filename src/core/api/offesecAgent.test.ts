import { beforeEach, describe, expect, expectTypeOf, it, vi } from "vitest";
import type { CreateAgentInput } from "../agents/offSecAgent";
import {
  createOffensiveSecurityAgentClient,
  type OffensiveSecurityAgentClientInput,
  runOffensiveSecurityAgent,
} from "./offesecAgent";

const fake = vi.hoisted(() => {
  class FakeOffensiveSecurityAgent {
    static order: string[] = [];
    static instances: FakeOffensiveSecurityAgent[] = [];
    /** Hold async session creation open so tests can abort mid-create. */
    static createGate: Promise<void> | null = null;
    static failCreate: unknown;
    static failConsume: unknown;

    input: Record<string, unknown>;
    session: { id: string };
    streamResult = { marker: "stream" };
    consumeCalls = 0;
    abortAndDrainCalls = 0;
    // Mirrors the real lifecycle: a placeholder until consume() swaps it.
    // The swap never settles, proving callers resolve on result alone.
    drained: Promise<void> = Promise.resolve();

    constructor(input: Record<string, unknown>) {
      this.input = input;
      this.session = (input.session as { id: string } | undefined) ?? {
        id: "ses_created",
      };
      FakeOffensiveSecurityAgent.order.push("construct");
      FakeOffensiveSecurityAgent.instances.push(this);
    }

    async consume(): Promise<void> {
      this.consumeCalls += 1;
      FakeOffensiveSecurityAgent.order.push("consume");
      this.drained = new Promise<void>(() => {});
      if (FakeOffensiveSecurityAgent.failConsume !== undefined) {
        throw FakeOffensiveSecurityAgent.failConsume;
      }
    }

    async abortAndDrain(): Promise<void> {
      this.abortAndDrainCalls += 1;
    }

    static async create(
      input: Record<string, unknown>,
    ): Promise<FakeOffensiveSecurityAgent> {
      FakeOffensiveSecurityAgent.order.push("create");
      if (FakeOffensiveSecurityAgent.createGate) {
        await FakeOffensiveSecurityAgent.createGate;
      }
      if (FakeOffensiveSecurityAgent.failCreate !== undefined) {
        throw FakeOffensiveSecurityAgent.failCreate;
      }
      return new FakeOffensiveSecurityAgent(input);
    }
  }
  return { FakeOffensiveSecurityAgent };
});

vi.mock("../agents/offSecAgent", () => ({
  OffensiveSecurityAgent: fake.FakeOffensiveSecurityAgent,
}));

const Fake = fake.FakeOffensiveSecurityAgent;

/** Session-branch input; the real type needs a full SessionInfo, so cast here. */
function existingSessionInput(overrides: Record<string, unknown> = {}) {
  return {
    prompt: "test prompt",
    model: "test-model",
    activeTools: ["read_file"],
    session: { id: "ses_existing", rootPath: "/tmp/session" },
    ...overrides,
  };
}

beforeEach(() => {
  Fake.order.length = 0;
  Fake.instances.length = 0;
  Fake.createGate = null;
  Fake.failCreate = undefined;
  Fake.failConsume = undefined;
});

describe("runOffensiveSecurityAgent", () => {
  it("constructs synchronously for a pre-existing session and fires onSessionReady before consume", async () => {
    const onSessionReady = vi.fn(() => Fake.order.push("onSessionReady"));
    const running = runOffensiveSecurityAgent(
      existingSessionInput({ onSessionReady }) as never,
    );

    expect(Fake.order).toEqual(["construct", "onSessionReady", "consume"]);
    const result = await running;
    expect(Fake.instances[0].consumeCalls).toBe(1);
    expect(onSessionReady).toHaveBeenCalledWith(Fake.instances[0].session);
    expect(result.session).toBe(Fake.instances[0].session);
    expect(result.streamResult).toBe(Fake.instances[0].streamResult);
  });

  it("awaits session creation before hooks and consume", async () => {
    const onSessionReady = vi.fn(() => Fake.order.push("onSessionReady"));
    const result = await runOffensiveSecurityAgent({
      prompt: "p",
      model: "m",
      activeTools: [],
      onSessionReady,
    });

    expect(Fake.order).toEqual([
      "create",
      "construct",
      "onSessionReady",
      "consume",
    ]);
    expect(Fake.instances[0].input.session).toBeUndefined();
    expect(result.session).toBe(Fake.instances[0].session);
  });

  it("forwards the caller's abortSignal unmodified — signal identity", async () => {
    const controller = new AbortController();
    await runOffensiveSecurityAgent({
      ...existingSessionInput(),
      abortSignal: controller.signal,
    } as never);

    expect(Fake.instances[0].input.abortSignal).toBe(controller.signal);
  });

  it("forwards event bus, hooks, and input fields to the agent unchanged", async () => {
    const eventBus = { on: () => {} };
    const onStepFinish = () => {};
    await runOffensiveSecurityAgent(
      existingSessionInput({
        eventBus,
        onStepFinish,
        target: "example.com",
        mode: "plan",
      }) as never,
    );

    const input = Fake.instances[0].input;
    expect(input.eventBus).toBe(eventBus);
    expect(input.onStepFinish).toBe(onStepFinish);
    expect(input.target).toBe("example.com");
    expect(input.mode).toBe("plan");
  });

  it("rejects with the provider's start failure and constructs nothing", async () => {
    const sentinel = new Error("session creation failed");
    Fake.failCreate = sentinel;

    await expect(
      runOffensiveSecurityAgent({ prompt: "p", model: "m", activeTools: [] }),
    ).rejects.toBe(sentinel);
    expect(Fake.instances).toHaveLength(0);
  });

  it("propagates the consume failure untouched", async () => {
    const sentinel = new DOMException("Agent aborted by user", "AbortError");
    Fake.failConsume = sentinel;

    await expect(
      runOffensiveSecurityAgent(existingSessionInput() as never),
    ).rejects.toBe(sentinel);
  });

  it("resolves on consume alone — the drain is never awaited", async () => {
    // The fake's drain never settles; awaiting drained here would hang.
    const result = await runOffensiveSecurityAgent(
      existingSessionInput() as never,
    );
    expect(result.session.id).toBe("ses_existing");
  }, 1000);
});

describe("createOffensiveSecurityAgentClient", () => {
  it("injects its own signal and forwards hooks through the run", async () => {
    const client = createOffensiveSecurityAgentClient();
    const onSessionReady = vi.fn();
    const result = await client.run(
      existingSessionInput({ onSessionReady }) as never,
    );

    expect(Fake.instances[0].input.abortSignal).toBeInstanceOf(AbortSignal);
    expect(onSessionReady).toHaveBeenCalledTimes(1);
    expect(onSessionReady).toHaveBeenCalledWith(Fake.instances[0].session);
    expect(result.session).toBe(Fake.instances[0].session);
    expect(result.streamResult).toBe(Fake.instances[0].streamResult);
  });

  it("owns cancellation — abortSignal is excluded from the client input", () => {
    expectTypeOf<CreateAgentInput>().not.toMatchTypeOf<OffensiveSecurityAgentClientInput>();
  });

  it("aborts synchronously — the signal flips without an await", async () => {
    const client = createOffensiveSecurityAgentClient();
    const running = client.run(existingSessionInput() as never);
    const signal = Fake.instances[0].input.abortSignal as AbortSignal;

    expect(signal.aborted).toBe(false);
    client.abort();
    expect(signal.aborted).toBe(true);
    await running;
  });

  it("abort before run pre-aborts the signal the agent receives", async () => {
    const client = createOffensiveSecurityAgentClient();
    client.abort();
    await client.run(existingSessionInput() as never);

    expect((Fake.instances[0].input.abortSignal as AbortSignal).aborted).toBe(
      true,
    );
  });

  it("cancels while async session creation is still in flight", async () => {
    const client = createOffensiveSecurityAgentClient();
    const onSessionReady = vi.fn(() => Fake.order.push("onSessionReady"));
    let releaseCreate!: () => void;
    Fake.createGate = new Promise<void>((resolve) => {
      releaseCreate = resolve;
    });

    const running = client.run({
      prompt: "p",
      model: "m",
      activeTools: [],
      onSessionReady,
    });
    expect(Fake.instances).toHaveLength(0);

    client.abort();
    releaseCreate();
    await running;

    expect(onSessionReady).toHaveBeenCalledWith(Fake.instances[0].session);
    expect(Fake.order).toEqual([
      "create",
      "construct",
      "onSessionReady",
      "consume",
    ]);
    expect((Fake.instances[0].input.abortSignal as AbortSignal).aborted).toBe(
      true,
    );
  });

  it("refuses a second run — the client is single-use", async () => {
    const client = createOffensiveSecurityAgentClient();
    const first = client.run(existingSessionInput() as never);

    expect(() => client.run(existingSessionInput() as never)).toThrow(
      "already started a run",
    );
    await first;
  });

  it("clients are independent — aborting one leaves the other's signal live", async () => {
    const a = createOffensiveSecurityAgentClient();
    const b = createOffensiveSecurityAgentClient();
    const runA = a.run(existingSessionInput() as never);
    const runB = b.run(existingSessionInput() as never);
    const [agentA, agentB] = Fake.instances;

    a.abort();

    expect((agentA.input.abortSignal as AbortSignal).aborted).toBe(true);
    expect((agentB.input.abortSignal as AbortSignal).aborted).toBe(false);
    expect(agentA.input.abortSignal).not.toBe(agentB.input.abortSignal);
    await runA;
    await runB;
  });

  it("propagates the provider's start failure untouched", async () => {
    const client = createOffensiveSecurityAgentClient();
    const sentinel = new Error("provider unavailable");
    Fake.failCreate = sentinel;

    await expect(
      client.run({ prompt: "p", model: "m", activeTools: [] }),
    ).rejects.toBe(sentinel);
    expect(Fake.instances).toHaveLength(0);
  });
});
