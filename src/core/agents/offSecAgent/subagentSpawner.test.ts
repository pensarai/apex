import { afterEach, describe, expect, it, vi } from "vitest";

let constructorError: Error | undefined;
let drain: { promise: Promise<void>; resolve: () => void };
let consumeStarted = false;
let lastConstructorProps: Record<string, unknown> | undefined;

vi.mock("../specialized/pentest/agent", () => ({
  TargetedPentestAgent: class {
    drained = Promise.resolve();

    constructor(props: Record<string, unknown>) {
      lastConstructorProps = props;
      if (constructorError) throw constructorError;
    }

    async consume() {
      consumeStarted = true;
      this.drained = drain.promise;
      return { findings: [], objectiveResults: [] };
    }
  },
}));

import type { AIModel } from "../../ai";
import { AgentEventBus } from "../../eventBus";
import type { SessionInfo } from "../../session";
import { inProcessSeams } from "../../workflows/seams";
import {
  createInProcessSubagentSpawner,
  inProcessSubagentSpawner,
  runSpawnedPentestWorker,
} from "./subagentSpawner";
import type { PlaywrightMcpSession } from "./tools";
import type { AgentHooks } from "./types";

function createDrain() {
  let resolve!: () => void;
  const promise = new Promise<void>((done) => {
    resolve = done;
  });
  return { promise, resolve };
}

function spawn(parentBus: AgentEventBus) {
  return inProcessSubagentSpawner.spawn({
    spec: {
      type: "pentest",
      target: "https://example.com",
      objectives: ["Test"],
    },
    runtime: {
      session: {} as SessionInfo,
      model: "test-model" as AIModel,
    },
    parentBus,
    subagentId: "child-session",
    drainGraceMs: 10_000,
  });
}

afterEach(() => {
  constructorError = undefined;
  consumeStarted = false;
  lastConstructorProps = undefined;
  vi.restoreAllMocks();
});

describe("inProcessSubagentSpawner", () => {
  it("waits for the drain created by consume before emitting completion", async () => {
    drain = createDrain();
    const parentBus = new AgentEventBus();
    const completions: string[] = [];
    parentBus.on("subagent-complete", ({ status }) => completions.push(status));

    const spawning = spawn(parentBus);
    await vi.waitFor(() => {
      expect(consumeStarted).toBe(true);
      expect(completions).toEqual([]);
    });

    drain.resolve();
    await spawning;

    expect(completions).toEqual(["completed"]);
  });

  it("emits a failed completion when child construction fails", async () => {
    drain = createDrain();
    constructorError = new Error("construction failed");
    const parentBus = new AgentEventBus();
    const lifecycle: string[] = [];
    parentBus.on("subagent-spawn", () => lifecycle.push("spawn"));
    parentBus.on("subagent-complete", ({ status }) => lifecycle.push(status));

    await expect(spawn(parentBus)).rejects.toThrow("construction failed");

    expect(lifecycle).toEqual(["spawn", "failed"]);
  });

  it("emits a failed completion when the error callback fails", async () => {
    drain = createDrain();
    constructorError = new Error("construction failed");
    const parentBus = new AgentEventBus();
    const completions: string[] = [];
    parentBus.on("subagent-complete", ({ status }) => completions.push(status));

    await expect(
      inProcessSubagentSpawner.spawn({
        spec: {
          type: "pentest",
          target: "https://example.com",
          objectives: ["Test"],
        },
        runtime: {
          session: {} as SessionInfo,
          model: "test-model" as AIModel,
        },
        parentBus,
        subagentId: "child-session",
        onError: () => {
          throw new Error("callback failed");
        },
      }),
    ).rejects.toThrow("callback failed");

    expect(completions).toEqual(["failed"]);
  });
});

describe("createInProcessSubagentSpawner", () => {
  it("mints child ids through a custom SessionIdFactory instead of the random default", async () => {
    drain = createDrain();
    const parentBus = new AgentEventBus();
    const completions: { subagentId: string; status: string }[] = [];
    parentBus.on("subagent-complete", (e) => completions.push(e));

    const newSessionId = vi.fn(
      (name: string, ordinal: number) => `custom-${name}-${ordinal}`,
    );
    const spawner = createInProcessSubagentSpawner({ ids: { newSessionId } });

    await spawner.spawn({
      spec: {
        type: "pentest",
        target: "https://example.com",
        objectives: ["Test"],
      },
      runtime: { session: {} as SessionInfo, model: "test-model" as AIModel },
      parentBus,
      subagentName: "worker",
    });

    expect(newSessionId).toHaveBeenCalledWith("worker", 0);
    expect(completions).toEqual([
      { subagentId: "custom-worker-0", status: "completed" },
    ]);
  });

  it("reattaches the browser session by scope when the spec omits one", async () => {
    drain = createDrain();
    const parentBus = new AgentEventBus();
    const fakeSession = { id: "shared" } as unknown as PlaywrightMcpSession;
    const forChild = vi.fn(() => fakeSession);
    const spawner = createInProcessSubagentSpawner({
      browser: { forChild },
    });

    await spawner.spawn({
      spec: {
        type: "pentest",
        target: "https://example.com",
        objectives: ["Test"],
      },
      runtime: { session: {} as SessionInfo, model: "test-model" as AIModel },
      parentBus,
      subagentId: "child-session",
    });

    expect(forChild).toHaveBeenCalledWith({
      subagentId: "child-session",
      subagentName: undefined,
    });
    expect(lastConstructorProps?.browserSession).toBe(fakeSession);
  });

  it("leaves an explicit browserSession on the spec untouched", async () => {
    drain = createDrain();
    const parentBus = new AgentEventBus();
    const explicitSession = {
      id: "explicit",
    } as unknown as PlaywrightMcpSession;
    const forChild = vi.fn(
      () => ({ id: "unused" }) as unknown as PlaywrightMcpSession,
    );
    const spawner = createInProcessSubagentSpawner({
      browser: { forChild },
    });

    await spawner.spawn({
      spec: {
        type: "pentest",
        target: "https://example.com",
        objectives: ["Test"],
        browserSession: explicitSession,
      },
      runtime: { session: {} as SessionInfo, model: "test-model" as AIModel },
      parentBus,
      subagentId: "child-session",
    });

    expect(forChild).not.toHaveBeenCalled();
    expect(lastConstructorProps?.browserSession).toBe(explicitSession);
  });
});

describe("runSpawnedPentestWorker — standalone, no InProcessSubagentSpawner involved", () => {
  it("constructs TargetedPentestAgent through the caller's own AgentHooks and returns consume()'s result unchanged", async () => {
    drain = createDrain();
    drain.resolve();
    const backends = {
      __sentinel: "standalone-backends",
    } as unknown as AgentHooks["backends"];

    const result = await runSpawnedPentestWorker(
      { target: "https://example.com", objectives: ["Test"] },
      {
        model: "test-model" as AIModel,
        session: {} as SessionInfo,
        hooks: { backends },
        seams: inProcessSeams(),
      },
    );

    expect(lastConstructorProps?.backends).toBe(backends);
    expect(result).toEqual({ findings: [], objectiveResults: [] });
  });
});

describe("inProcessSubagentSpawner — pentest — delegates to runSpawnedPentestWorker", () => {
  it("still constructs the agent with the same fields the old inline construction used", async () => {
    drain = createDrain();
    drain.resolve();
    const parentBus = new AgentEventBus();
    const languageModelMiddleware = {
      __sentinel: "mw",
    } as unknown as AgentHooks["languageModelMiddleware"];

    await inProcessSubagentSpawner.spawn({
      spec: {
        type: "pentest",
        target: "https://example.com",
        objectives: ["Test"],
        context: "ctx",
        role: "worker",
      },
      runtime: {
        session: {} as SessionInfo,
        model: "test-model" as AIModel,
        languageModelMiddleware,
      },
      parentBus,
      subagentId: "child-session",
    });

    expect(lastConstructorProps).toMatchObject({
      target: "https://example.com",
      objectives: ["Test"],
      context: "ctx",
      role: "worker",
      subagentId: "child-session",
      languageModelMiddleware,
    });
  });
});
