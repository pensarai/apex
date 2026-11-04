import { afterEach, describe, expect, it, vi } from "vitest";
import { LanceRuntime } from "./lance";

afterEach(() => vi.useRealTimers());

async function request(
  runtime: LanceRuntime,
  source: "agent" | "compaction" | "judge",
  input: number | undefined,
  output: number,
) {
  const middleware =
    source === "judge" ? runtime.judgeMiddleware : runtime.middleware;
  const run = async () => {
    const response = await middleware.wrapStream!({
      doStream: async () => ({
        stream: new ReadableStream({
          start(controller) {
            controller.enqueue({
              type: "finish",
              usage: {
                inputTokens: { total: input, cacheRead: input },
                outputTokens: { total: output },
              },
            });
            controller.close();
          },
        }),
      }),
    } as never);
    const reader = response.stream.getReader();
    while (!(await reader.read()).done) {}
  };
  return source === "compaction" ? runtime.runContextCompaction(run) : run();
}

describe("Lance selected budget", () => {
  it("defaults to 200 steps without an implicit time limit", () => {
    vi.useFakeTimers();
    const runtime = new LanceRuntime();
    runtime.start();
    vi.advanceTimersByTime(3600000);
    for (let i = 0; i < 199; i++) runtime.stepFinished();
    expect(runtime.terminal).toBe(false);
    runtime.stepFinished();
    expect(runtime.metrics("m")).toMatchObject({
      outcome: "step_limit",
      steps: 200,
      deadlineAt: null,
      budget: { kind: "steps", limit: 200 },
    });
  });
  it("allows a step limit above 200", () => {
    const runtime = new LanceRuntime({
      budget: { kind: "steps", limit: 1000 },
    });
    for (let i = 0; i < 999; i++) runtime.stepFinished();
    expect(runtime.terminal).toBe(false);
    runtime.stepFinished();
    expect(runtime.metrics("m").outcome).toBe("step_limit");
  });
  it("time budgets do not stop at 200 steps and cancel at the soft deadline", () => {
    vi.useFakeTimers();
    const runtime = new LanceRuntime({
      budget: { kind: "time", limit: 10000 },
      shutdownReserveMs: 1000,
    });
    runtime.start();
    for (let i = 0; i < 201; i++) runtime.stepFinished();
    expect(runtime.terminal).toBe(false);
    vi.advanceTimersByTime(9000);
    expect(runtime.metrics("m").outcome).toBe("deadline_exhausted");
    expect(runtime.signal.aborted).toBe(true);
    runtime.finish();
  });
  it("counts cache-inclusive input and output across agent, compaction, and judge; fences the next request and tool", async () => {
    const runtime = new LanceRuntime({
      budget: { kind: "tokens", limit: 100 },
    });
    for (let i = 0; i < 201; i++) runtime.stepFinished();
    await request(runtime, "agent", 20, 10);
    await request(runtime, "compaction", 20, 10);
    await request(runtime, "judge", 30, 20);
    expect(runtime.metrics("m").usage).toMatchObject({
      inputTokens: 70,
      outputTokens: 40,
      usageComplete: true,
    });
    const next = vi.fn();
    await expect(
      runtime.middleware.wrapStream!({ doStream: next } as never),
    ).rejects.toThrow("token budget exhausted");
    expect(next).not.toHaveBeenCalled();
    await expect(
      runtime.tools({}).update_plan.execute!(
        { plan: [] },
        { toolCallId: "blocked", messages: [] },
      ),
    ).rejects.toThrow();
    expect(runtime.metrics("m").outcome).toBe("token_limit");
  });
  it("fails explicitly when a completed request omits token totals", async () => {
    const runtime = new LanceRuntime({
      budget: { kind: "tokens", limit: 100 },
    });
    await request(runtime, "agent", undefined, 10).catch(() => {});
    runtime.finish();
    expect(runtime.metrics("m")).toMatchObject({
      outcome: "error",
      usage: { usageComplete: false },
    });
    expect(runtime.metrics("m").reason).toContain("did not report token usage");
    expect(runtime.signal.aborted).toBe(true);
  });
  it.each([
    true,
    false,
  ])("preserves a judge verdict before enforcing an exhausted token budget: %s", async (verified) => {
    const runtime = new LanceRuntime({
      budget: { kind: "tokens", limit: 100 },
      verificationSource: "apex_judge",
      verifyObjective: async () => {
        await request(runtime, "judge", 100, 10);
        return { verified, verifierId: "judge-fixture" };
      },
    });
    await Promise.resolve(
      runtime.tools({}).submit_objective.execute!(
        { evidence: "candidate" },
        { toolCallId: "submit", messages: [] },
      ),
    ).catch(() => {});
    runtime.finish();
    expect(runtime.metrics("m")).toMatchObject({
      outcome: verified ? "judge_accepted" : "token_limit",
      verification: { verified, verifierId: "judge-fixture" },
      modelJudgedSuccess: verified,
      usage: { inputTokens: 100, outputTokens: 10, usageComplete: true },
    });
    const next = vi.fn();
    await expect(
      runtime.middleware.wrapStream!({ doStream: next } as never),
    ).rejects.toThrow();
    expect(next).not.toHaveBeenCalled();
  });
  it("rejects invalid limits and mixed budget types at the public runtime boundary", () => {
    for (const limit of [
      0,
      -1,
      1.5,
      Infinity,
      NaN,
      Number.MAX_SAFE_INTEGER + 1,
    ])
      expect(
        () => new LanceRuntime({ budget: { kind: "tokens", limit } }),
      ).toThrow();
    expect(
      () =>
        new LanceRuntime({
          budget: { kind: "steps", limit: 10 },
          timeoutMs: 1000,
        }),
    ).toThrow("Choose one");
  });
});
