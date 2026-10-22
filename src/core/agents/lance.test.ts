import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { tool } from "ai";
import { afterEach, describe, expect, it, vi } from "vitest";
import { z } from "zod";
import { LANCE_CONFIG, LanceRuntime } from "./lance";

const context = { toolCallId: "test", messages: [] };
const execute = (
  tools: ReturnType<LanceRuntime["tools"]>,
  name: string,
  input: unknown = {},
) => Promise.resolve(tools[name].execute!(input, context));

afterEach(() => vi.useRealTimers());

describe("Lance terminal policy", () => {
  it("restores a session-local plan without requiring all steps to finish", async () => {
    const root = mkdtempSync(join(tmpdir(), "lance-plan-"));
    const otherRoot = mkdtempSync(join(tmpdir(), "lance-other-plan-"));
    try {
      const first = new LanceRuntime({ interactive: true }, undefined, root);
      const plan = {
        explanation: "Scratchpad: notes.md; first hypothesis rejected",
        plan: [{ step: "Check the second hypothesis", status: "pending" }],
      };
      await execute(first.tools({}), "update_plan", plan);
      first.finish();
      const resumed = new LanceRuntime({}, undefined, root);
      expect(resumed.continuationContext()).toContain("notes.md");
      expect(resumed.continuationContext()).toContain(
        "Check the second hypothesis",
      );
      const other = new LanceRuntime({}, undefined, otherRoot);
      expect(other.continuationContext()).toBe("");
      other.finish();
      const tools = resumed.tools({});
      await execute(tools, "finish_task", {
        summary: "Objective achieved through a different approach",
      }).catch(() => {});
      await expect(
        execute(tools, "update_plan", { plan: [] }),
      ).rejects.toThrow();
      const doGenerate = vi.fn();
      expect(() =>
        resumed.runContextCompaction(async () =>
          resumed.middleware.wrapGenerate!({ doGenerate } as never),
        ),
      ).toThrow();
      expect(doGenerate).not.toHaveBeenCalled();
      expect(
        JSON.parse(readFileSync(join(root, "lance-plan.json"), "utf8")),
      ).toEqual(plan);
      resumed.finish();
      expect(resumed.metrics("m").outcome).toBe("completed");
    } finally {
      rmSync(root, { recursive: true, force: true });
      rmSync(otherRoot, { recursive: true, force: true });
    }
  });

  it("admits only host-scoped compaction and fences a late physical request", async () => {
    const runtime = new LanceRuntime();
    const doGenerate = vi.fn(async () => ({
      usage: {
        inputTokens: { total: 10, noCache: 10, cacheRead: 0, cacheWrite: 0 },
        outputTokens: { total: 5, text: 5, reasoning: undefined },
      },
    }));
    await expect(
      runtime.middleware.wrapGenerate!({ doGenerate } as never),
    ).rejects.toThrow("auxiliary");
    expect(doGenerate).not.toHaveBeenCalled();
    await runtime.runContextCompaction(async () =>
      runtime.middleware.wrapGenerate!({ doGenerate } as never),
    );
    let release!: () => void;
    const delayed = runtime.runContextCompaction(async () => {
      await new Promise<void>((resolve) => {
        release = resolve;
      });
      return runtime.middleware.wrapGenerate!({ doGenerate } as never);
    });
    runtime.stop("verified", "Objective verified");
    release();
    await expect(delayed).rejects.toThrow("Objective verified");
    expect(doGenerate).toHaveBeenCalledTimes(1);
    runtime.finish();
    expect(runtime.metrics("m")).toMatchObject({
      usage: { requests: 1 },
      compactionUsage: { requests: 1 },
      policyViolations: [
        { kind: "child_agent", name: "auxiliary_model" },
        { kind: "post_terminal_work", name: "compaction_model_request" },
      ],
    });
  });

  it("ends on the agent's completion request without a verifier or a flag", async () => {
    const runtime = new LanceRuntime();
    const command = vi.fn(async () => "unexpected");
    const tools = runtime.tools({
      execute_command: tool({ inputSchema: z.object({}), execute: command }),
    });
    await Promise.allSettled([
      execute(tools, "finish_task", {
        summary:
          "Finished testing the authorized endpoint; no issue reproduced.",
      }),
      execute(tools, "execute_command"),
    ]);
    runtime.finish();
    expect(command).not.toHaveBeenCalled();
    expect(runtime.metrics("m")).toMatchObject({
      outcome: "completed",
      modelSubmittedSuccess: true,
      harnessVerifiedSuccess: false,
      completion: { toolCalls: 1 },
      verification: null,
    });
  });

  it("stops on completion even when the external evaluator rejects the evidence", async () => {
    const runtime = new LanceRuntime({
      verifyObjective: async () => ({
        verified: false,
        objectiveComplete: false,
        verifierId: "eval",
      }),
    });
    await execute(runtime.tools({}), "finish_task", {
      summary: "Task complete",
      evidence: "candidate",
    }).catch(() => {});
    runtime.finish();
    expect(runtime.metrics("m")).toMatchObject({
      outcome: "completed",
      harnessVerifiedSuccess: false,
      verification: { verified: false },
      firstVerified: null,
    });
  });

  it("does not confuse a verified milestone with the complete objective", async () => {
    const runtime = new LanceRuntime({
      verifyObjective: async () => ({
        verified: true,
        objectiveComplete: false,
        verifierId: "milestone",
      }),
    });
    await execute(runtime.tools({}), "submit_objective", {
      evidence: "first milestone",
    });
    expect(runtime.terminal).toBe(false);
    expect(runtime.metrics("m")).toMatchObject({
      harnessVerifiedSuccess: false,
      firstVerified: null,
      verification: { verified: true, objectiveComplete: false },
    });
    runtime.finish();
  });

  it("admits no offensive requests while completion verification is pending", async () => {
    let resolve!: (value: { verified: boolean; verifierId: string }) => void;
    const runtime = new LanceRuntime({
      verifyObjective: () =>
        new Promise((r) => {
          resolve = r;
        }),
    });
    const completion = execute(runtime.tools({}), "finish_task", {
      summary: "Done",
      evidence: "candidate",
    }).catch(() => {});
    await Promise.resolve();
    const doStream = vi.fn();
    await expect(
      runtime.middleware.wrapStream!({ doStream } as never),
    ).rejects.toThrow("requested completion");
    expect(doStream).not.toHaveBeenCalled();
    resolve({ verified: false, verifierId: "eval" });
    await completion;
    runtime.finish();
    expect(runtime.metrics("m").outcome).toBe("completed");
  });

  it("persists resumable interactive turns and keeps headless model stops terminal", () => {
    const root = mkdtempSync(join(tmpdir(), "lance-conversation-"));
    try {
      for (let turn = 0; turn < 2; turn++) {
        const runtime = new LanceRuntime({ interactive: true });
        runtime.finish();
        runtime.persist(root, "model");
        expect(runtime.metrics("model").outcome).toBe("awaiting_input");
      }
      const turns = readFileSync(join(root, "lance-turns.jsonl"), "utf8")
        .trim()
        .split("\n")
        .map((line) => JSON.parse(line));
      expect(turns).toHaveLength(2);
      expect(turns[0]).toMatchObject({
        executionKind: "interactive_turn",
        outcome: "awaiting_input",
      });
      const headless = new LanceRuntime();
      headless.finish();
      headless.persist(root, "model");
      expect(headless.terminal).toBe(true);
      expect(headless.metrics("model")).toMatchObject({
        executionKind: "headless_attempt",
        outcome: "unsolved",
      });
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });

  it("keeps explicit non-solves, cancellation, and deadline exhaustion terminal in interactive mode", async () => {
    vi.useFakeTimers();
    const parent = new AbortController();
    const cancelled = new LanceRuntime({ interactive: true }, parent.signal);
    parent.abort();
    cancelled.finish();
    expect(cancelled.metrics("m").outcome).toBe("cancelled");
    const unsolved = new LanceRuntime({ interactive: true });
    await execute(unsolved.tools({}), "finish_unsolved", {
      reason: "No remaining leads",
    }).catch(() => {});
    unsolved.finish();
    expect(unsolved.metrics("m").outcome).toBe("unsolved");
    const deadline = new LanceRuntime({
      interactive: true,
      timeoutMs: 1000,
      shutdownReserveMs: 100,
    });
    deadline.start();
    await vi.advanceTimersByTimeAsync(900);
    deadline.finish();
    expect(deadline.metrics("m").outcome).toBe("deadline_exhausted");
    expect(vi.getTimerCount()).toBe(0);
  });

  it("denies both child spawning paths before invoking workers", async () => {
    const runtime = new LanceRuntime();
    const worker = vi.fn();
    await expect(runtime.spawner.spawn({} as never)).rejects.toThrow(
      "prohibits child",
    );
    await expect(
      runtime.spawner.spawnMany([1], worker, { concurrency: 1 }),
    ).rejects.toThrow("prohibits child");
    expect(worker).not.toHaveBeenCalled();
    expect(
      runtime.metrics("model").policyViolations.map((v) => v.kind),
    ).toEqual(["child_agent", "child_agent"]);
  });

  it("serializes a parallel tool batch and admits no work after verification", async () => {
    const verify = vi.fn(async () => ({
      verified: true,
      verifierId: "host-v1",
    }));
    const runtime = new LanceRuntime({ verifyObjective: verify });
    const command = vi.fn(async () => "should never run");
    const tools = runtime.tools({
      execute_command: tool({ inputSchema: z.object({}), execute: command }),
    });
    const results = await Promise.allSettled([
      execute(tools, "submit_objective", { evidence: "proof" }),
      execute(tools, "execute_command"),
    ]);
    expect(results[1].status).toBe("rejected");
    expect(command).not.toHaveBeenCalled();
    const doStream = vi.fn();
    await expect(
      runtime.middleware.wrapStream!({ doStream } as never),
    ).rejects.toThrow();
    expect(doStream).not.toHaveBeenCalled();
    runtime.finish();
    expect(runtime.metrics("model")).toMatchObject({
      outcome: "verified",
      modelSubmittedSuccess: true,
      harnessVerifiedSuccess: true,
      toolCalls: 1,
      firstCandidate: { toolCalls: 1 },
      firstVerified: { toolCalls: 1 },
    });
  });

  it("continues after rejected evidence and distinguishes an unverified claim", async () => {
    const runtime = new LanceRuntime({
      verifyObjective: async () => ({ verified: false, verifierId: "host" }),
    });
    await execute(runtime.tools({}), "submit_objective", { evidence: "wrong" });
    expect(runtime.terminal).toBe(false);
    runtime.finish();
    expect(runtime.metrics("m")).toMatchObject({
      outcome: "unsolved",
      modelSubmittedSuccess: true,
      harnessVerifiedSuccess: false,
      firstVerified: null,
    });
    const noVerifier = new LanceRuntime();
    await execute(noVerifier.tools({}), "submit_objective", {
      evidence: "claim",
    }).catch(() => {});
    expect(noVerifier.terminal).toBe(false);
    await execute(noVerifier.tools({}), "finish_task", {
      summary: "Finished",
    }).catch(() => {});
    noVerifier.finish();
    expect(noVerifier.metrics("m").outcome).toBe("completed");
  });

  it("ends a hung verifier before the hard deadline and ignores late confirmation", async () => {
    vi.useFakeTimers();
    let resolve!: (result: { verified: boolean; verifierId: string }) => void;
    const runtime = new LanceRuntime({
      timeoutMs: 1000,
      shutdownReserveMs: 100,
      verifyObjective: () =>
        new Promise((r) => {
          resolve = r;
        }),
    });
    runtime.start();
    const submission = execute(runtime.tools({}), "submit_objective", {
      evidence: "proof",
    }).catch(() => {});
    await vi.advanceTimersByTimeAsync(900);
    await submission;
    runtime.finish();
    resolve({ verified: true, verifierId: "late" });
    await Promise.resolve();
    expect(runtime.metrics("m")).toMatchObject({
      outcome: "deadline_exhausted",
      harnessVerifiedSuccess: false,
      elapsedMs: 900,
    });
    expect(runtime.signal.aborted).toBe(true);
    expect(vi.getTimerCount()).toBe(0);
  });

  it("distinguishes early non-solves and step exhaustion from deadline exhaustion", async () => {
    const runtime = new LanceRuntime();
    await execute(runtime.tools({}), "finish_unsolved", {
      reason: "No remaining leads",
    }).catch(() => {});
    runtime.finish();
    expect(runtime.metrics("m").outcome).toBe("unsolved");
    const limited = new LanceRuntime();
    for (let i = 0; i < LANCE_CONFIG.maxSteps; i++) limited.stepFinished();
    limited.finish();
    expect(limited.metrics("m").outcome).toBe("step_limit");
  });

  it("counts physical requests and cache-aware cost, including the success request", async () => {
    const runtime = new LanceRuntime({
      pricing: { input: 1, output: 2, cacheRead: 0.1, cacheWrite: 1.25 },
      verifyObjective: async () => ({ verified: true, verifierId: "host" }),
    });
    const response = await runtime.middleware.wrapStream!({
      doStream: async () => ({
        stream: new ReadableStream({
          start(controller) {
            controller.enqueue({
              type: "finish",
              usage: {
                inputTokens: { total: 100, cacheRead: 20, cacheWrite: 10 },
                outputTokens: { total: 5 },
              },
            });
            controller.close();
          },
        }),
      }),
    } as never);
    const reader = response.stream.getReader();
    while (!(await reader.read()).done) {}
    await execute(runtime.tools({}), "submit_objective", {
      evidence: "proof",
    }).catch(() => {});
    runtime.finish();
    expect(runtime.metrics("m").usageBeforeSuccess).toMatchObject({
      requests: 1,
      inputTokens: 100,
      outputTokens: 5,
      usageComplete: true,
      costUsd: 0.0000945,
    });
    const root = mkdtempSync(join(tmpdir(), "lance-metrics-"));
    try {
      runtime.persist(root, "m");
      expect(
        JSON.parse(readFileSync(join(root, "lance-result.json"), "utf8"))
          .configVersion,
      ).toBe(LANCE_CONFIG.version);
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });

  it("keeps unavailable usage and price explicit", async () => {
    const runtime = new LanceRuntime();
    await expect(
      runtime.middleware.wrapStream!({
        doStream: async () => {
          throw new Error("provider failed");
        },
      } as never),
    ).rejects.toThrow("provider failed");
    runtime.finish();
    expect(runtime.metrics("m").usage).toMatchObject({
      requests: 1,
      usageComplete: false,
      costUsd: null,
    });
  });
});
