import { afterEach, describe, expect, it, vi } from "vitest";

let constructorError: Error | undefined;
let drain: { promise: Promise<void>; resolve: () => void };
let consumeStarted = false;

vi.mock("../specialized/pentest/agent", () => ({
  TargetedPentestAgent: class {
    drained = Promise.resolve();

    constructor() {
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
import { inProcessSubagentSpawner } from "./subagentSpawner";

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
