import { afterEach, describe, expect, it, vi } from "vitest";

let constructorError: Error | undefined;
let drain: { promise: Promise<void>; resolve: () => void };
let consumeStarted = false;
let consumeHook: (() => Promise<void>) | undefined;

vi.mock("../specialized/pentest/agent", () => ({
  TargetedPentestAgent: class {
    drained = Promise.resolve();

    constructor() {
      if (constructorError) throw constructorError;
    }

    async consume() {
      consumeStarted = true;
      await consumeHook?.();
      this.drained = drain.promise;
      return { findings: [], objectiveResults: [] };
    }
  },
}));

import type { AIModel } from "../../ai";
import {
  createNativeRolloutEvidenceCapture,
  withNativeRolloutEvidenceModel,
} from "../../ai/native-rollout-evidence";
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
  consumeHook = undefined;
  vi.restoreAllMocks();
});

describe("inProcessSubagentSpawner", () => {
  it("attributes child model calls to the exact parent tool invocation", async () => {
    drain = createDrain();
    drain.resolve();
    const envelopes: Array<{
      sessionId?: string;
      parent?: { sessionId: string; toolCallId: string };
    }> = [];
    const capture = createNativeRolloutEvidenceCapture({
      enabled: true,
      runId: "run-nested-spawn",
      sink: {
        write: (envelope) => {
          envelopes.push(envelope);
        },
      },
    });
    consumeHook = async () => {
      const base = {
        specificationVersion: "v3" as const,
        provider: "fixture",
        modelId: "fixture-model",
        supportedUrls: {},
        doGenerate: async () => ({
          content: [{ type: "text" as const, text: "done" }],
          finishReason: { unified: "stop" as const, raw: "stop" },
          usage: {
            inputTokens: {
              total: 1,
              noCache: 1,
              cacheRead: 0,
              cacheWrite: 0,
            },
            outputTokens: { total: 1, text: 1, reasoning: 0 },
          },
          warnings: [],
        }),
        doStream: vi.fn(),
      };
      await withNativeRolloutEvidenceModel(base, {
        requestedModelId: "fixture-model",
        operationKind: "agent.stream",
        sessionId: "untrusted-alias",
      }).doGenerate({ prompt: [] });
    };

    await capture.run(() =>
      inProcessSubagentSpawner.spawn({
        spec: {
          type: "pentest",
          target: "https://example.com",
          objectives: ["Test"],
        },
        runtime: {
          session: { id: "ses-root" } as SessionInfo,
          model: "test-model" as AIModel,
        },
        subagentId: "ses-child",
        parentSessionId: "ses-root",
        parentToolCallId: "call-spawn-child",
      }),
    );
    await capture.flush();

    expect(envelopes).toEqual([
      expect.objectContaining({
        sessionId: "ses-child",
        parent: {
          sessionId: "ses-root",
          toolCallId: "call-spawn-child",
        },
      }),
    ]);
  });

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
