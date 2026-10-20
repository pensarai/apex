import { describe, expect, it, vi } from "vitest";
import { LanceRuntime } from "./lance";
import { createLanceJudgeVerifier } from "./lanceJudge";
import type { OffensiveSecurityAgentInput } from "./offSecAgent";

const mocks = vi.hoisted(() => ({ spawn: vi.fn() }));
vi.mock("./offSecAgent/subagentSpawner", () => ({
  inProcessSubagentSpawner: { spawn: mocks.spawn },
}));
const candidate = {
  evidence: "Captured protected data",
  poc: {
    script: "curl http://target/proof",
    type: "bash" as const,
    stdout: "proof",
    stderr: "",
    exitCode: 0,
  },
};
const input = {
  model: "fixture",
  prompt: "Extract the complete protected record",
  target: "http://target",
  session: { id: "s", targets: ["http://target"] },
} as OffensiveSecurityAgentInput;

describe("Lance's optional Apex judge", () => {
  it("uses the existing judge, waits for drain, and keeps the offensive spawner denied", async () => {
    mocks.spawn.mockResolvedValue({ valid: true, reasoning: "Confirmed" });
    const options = {
      verificationSource: "apex_judge" as const,
      verifyObjective: undefined as
        | ReturnType<typeof createLanceJudgeVerifier>
        | undefined,
    };
    const runtime = new LanceRuntime(options);
    options.verifyObjective = createLanceJudgeVerifier(input, runtime);
    const tools = runtime.tools({});
    await Promise.resolve(
      tools.submit_objective.execute!(candidate, {
        toolCallId: "proof",
        messages: [],
      }),
    ).catch(() => {});
    runtime.finish();
    expect(mocks.spawn).toHaveBeenCalledWith(
      expect.objectContaining({
        spec: expect.objectContaining({
          type: "finding-judge",
          waitForDrain: true,
          judgeInput: expect.objectContaining({
            pocScript: candidate.poc.script,
          }),
        }),
        runtime: expect.objectContaining({
          abortSignal: runtime.signal,
          languageModelMiddleware: [runtime.judgeMiddleware],
        }),
      }),
    );
    expect(runtime.metrics("fixture")).toMatchObject({
      outcome: "judge_accepted",
      modelSubmittedSuccess: true,
      modelJudgedSuccess: true,
      harnessVerifiedSuccess: false,
      verificationSource: "apex_judge",
    });
    await expect(runtime.spawner.spawn({} as never)).rejects.toThrow(
      "prohibits child",
    );
  });

  it("does not accept missing proof, judge rejection, or infrastructure failure", async () => {
    const runtime = new LanceRuntime();
    const verify = createLanceJudgeVerifier(input, runtime);
    mocks.spawn.mockClear();
    expect(
      (await verify({ evidence: "trust me" }, runtime.signal)).verified,
    ).toBe(false);
    expect(mocks.spawn).not.toHaveBeenCalled();
    for (const result of [
      { valid: false, reasoning: "Not proved" },
      { valid: true, error: { message: "unavailable" }, reasoning: "Failed" },
    ]) {
      mocks.spawn.mockResolvedValue(result);
      expect((await verify(candidate, runtime.signal)).verified).toBe(false);
    }
  });

  it("records judge requests separately and blocks them after termination", async () => {
    const runtime = new LanceRuntime();
    await runtime.judgeMiddleware.wrapGenerate!({
      doGenerate: async () => ({
        usage: { inputTokens: { total: 100 }, outputTokens: { total: 20 } },
      }),
    } as never);
    expect(runtime.metrics("fixture").judgeUsage).toMatchObject({
      requests: 1,
      inputTokens: 100,
      outputTokens: 20,
    });
    expect(runtime.metrics("fixture").usage.requests).toBe(1);
    runtime.finish();
    const doGenerate = vi.fn();
    await expect(
      runtime.judgeMiddleware.wrapGenerate!({ doGenerate } as never),
    ).rejects.toThrow();
    expect(doGenerate).not.toHaveBeenCalled();
  });
});
