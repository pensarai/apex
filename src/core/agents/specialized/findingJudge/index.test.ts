import { beforeEach, describe, expect, it, vi } from "vitest";
import type { FindingJudgeInput } from "./types";

const mocks = vi.hoisted(() => ({
  consume: vi.fn(),
  constructorArgs: vi.fn(),
}));

vi.mock("./agent", () => ({
  FINDING_JUDGE_ACTIVE_TOOLS: [
    "execute_command",
    "http_request",
    "read_file",
    "list_files",
    "grep",
    "web_search",
    "get_page",
    "response",
  ],
  FindingJudgeAgent: vi.fn().mockImplementation((args) => {
    mocks.constructorArgs(args);
    return {
      consume: mocks.consume,
    };
  }),
}));

const { createJudgeFailureResult, judgeFinding } = await import("./index");

function makeInput(): FindingJudgeInput {
  return {
    pocScript: 'echo "real evidence"',
    pocType: "bash",
    pocPath: "pocs/poc_real.sh",
    target: "https://example.com",
    pocOutput: {
      stdout: "real evidence",
      stderr: "",
      exitCode: 0,
    },
    claim: {
      title: "Exposed Data",
      description: "Sensitive data is exposed.",
      impact: "Attackers can read sensitive data.",
      evidence: "real evidence",
      endpoint: "https://example.com/api/data",
      vulnerabilityClass: "information-disclosure",
    },
  };
}

function makeContext() {
  return {
    model: "test-model",
    session: {
      id: "session-1",
      rootPath: "/tmp/session",
      pocsPath: "/tmp/session/pocs",
      findingsPath: "/tmp/session/findings",
      logsPath: "/tmp/session/logs",
      targets: ["https://example.com"],
      config: {},
    },
    target: "https://example.com",
  } as Parameters<typeof judgeFinding>[1];
}

describe("judgeFinding", () => {
  beforeEach(() => {
    mocks.consume.mockReset();
    mocks.constructorArgs.mockReset();
  });

  it("returns the completed agent judgment with verification metadata", async () => {
    mocks.consume.mockResolvedValue({
      valid: true,
      findingType: "vulnerability",
      confidence: 0.92,
      reasoning: "The rerun reproduced the leaked data from the target.",
      concerns: [],
      verificationSteps: ["Reran the POC."],
      toolEvidence: ["stdout included leaked data."],
      reproducedPoc: true,
      webResearchUsed: false,
      limitations: [],
    });

    const result = await judgeFinding(makeInput(), makeContext());

    expect(result.valid).toBe(true);
    expect(result.confidence).toBe(0.92);
    expect(result.verificationSteps).toEqual(["Reran the POC."]);
    expect(mocks.constructorArgs).toHaveBeenCalledWith(
      expect.objectContaining({
        model: "test-model",
        target: "https://example.com",
      }),
    );
  });

  it("forwards the caller-provided subagentId to the judge agent", async () => {
    mocks.consume.mockResolvedValue({
      valid: true,
      findingType: "vulnerability",
      confidence: 0.9,
      reasoning: "ok",
      concerns: [],
      verificationSteps: [],
      toolEvidence: [],
      reproducedPoc: true,
      webResearchUsed: false,
      limitations: [],
    });

    await judgeFinding(makeInput(), {
      ...makeContext(),
      subagentId: "pentest-agent-worker-1-finding-judge-1",
    });

    expect(mocks.constructorArgs).toHaveBeenCalledWith(
      expect.objectContaining({
        subagentId: "pentest-agent-worker-1-finding-judge-1",
      }),
    );
  });

  it("rejects the finding as unverified when the judge agent fails", async () => {
    mocks.consume.mockRejectedValue(new Error("provider overloaded"));

    const result = await judgeFinding(makeInput(), makeContext());

    expect(result.valid).toBe(false);
    expect(result.findingType).toBe("informational");
    expect(result.confidence).toBe(0.4);
    expect(result.reasoning).toContain("Rejecting");
    expect(result.concerns).toEqual(
      expect.arrayContaining([
        expect.stringContaining("infrastructure failed"),
      ]),
    );
    expect(result.error?.message).toBe("provider overloaded");
  });

  it("creates explicit unverified rejection diagnostics", () => {
    const result = createJudgeFailureResult(
      Object.assign(new Error("rate limited"), { status: 429 }),
      "test-model",
    );

    expect(result.valid).toBe(false);
    expect(result.confidence).toBeLessThan(0.5);
    expect(result.error?.message).toContain("[status=429]");
    expect(result.limitations?.[0]).toContain("No independent judge");
  });
});
