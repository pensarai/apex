import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { LanguageModelV3StreamPart } from "@ai-sdk/provider";
import { simulateReadableStream } from "ai";
import { MockLanguageModelV3 } from "ai/test";
import { afterEach, describe, expect, it, vi } from "vitest";
import { ApprovalGate } from "../operator/approvalGate";
import type { SessionInfo } from "../session";

const state = vi.hoisted(() => ({
  model: null as MockLanguageModelV3 | null,
}));
vi.mock("./utils", async (original) => ({
  ...(await original<Record<string, unknown>>()),
  getProviderModel: () => state.model,
}));

import { OffensiveSecurityAgent } from "../agents/offSecAgent";
import { inProcessSubagentSpawner } from "../agents/offSecAgent/subagentSpawner";

const usage = {
  inputTokens: { total: 100, noCache: 100, cacheRead: 0, cacheWrite: 0 },
  outputTokens: { total: 10, text: 10, reasoning: undefined },
};
const roots: string[] = [];
afterEach(() => {
  for (const root of roots.splice(0))
    rmSync(root, { recursive: true, force: true });
  vi.clearAllMocks();
});

function agent(options: Record<string, unknown> = {}) {
  const root = mkdtempSync(join(tmpdir(), "lance-sdk-"));
  roots.push(root);
  return new OffensiveSecurityAgent({
    mode: "lance",
    prompt: "Capture the flag",
    model: "claude-sonnet-4-5",
    activeTools: [],
    session: {
      id: "ses_lance",
      version: "1",
      time: { created: Date.now(), updated: Date.now() },
      logsPath: join(root, "logs"),
      rootPath: root,
      config: {},
      targets: [],
      findingsPath: join(root, "findings"),
      scratchpadPath: join(root, "scratchpad"),
      pocsPath: join(root, "pocs"),
    } as SessionInfo,
    sandbox: {
      type: "linux",
      execute: async () => {
        throw new Error("Unexpected shell execution");
      },
    },
    ...options,
  });
}

function stream(chunks: LanguageModelV3StreamPart[]) {
  return {
    stream: simulateReadableStream({
      chunks,
      initialDelayInMs: null,
      chunkDelayInMs: null,
    }),
  };
}

describe("Lance with the real AI SDK loop", () => {
  it("keeps conversations open and waits for new user input after verified success", async () => {
    let turn = 0;
    const doStream = vi.fn(async () => {
      turn++;
      return stream(
        turn !== 3
          ? [
              { type: "text-start", id: "reply" },
              {
                type: "text-delta",
                id: "reply",
                delta:
                  turn === 1 ? "What is the target?" : "What is the objective?",
              },
              { type: "text-end", id: "reply" },
              {
                type: "finish",
                finishReason: { unified: "stop", raw: "stop" },
                usage,
              },
            ]
          : [
              {
                type: "tool-call",
                toolCallId: "proof",
                toolName: "submit_objective",
                input: '{"evidence":"proof"}',
              },
              {
                type: "finish",
                finishReason: { unified: "tool-calls", raw: "tool_calls" },
                usage,
              },
            ],
      );
    });
    state.model = new MockLanguageModelV3({ doStream });
    const lance = {
      interactive: true,
      verifyObjective: async () => ({ verified: true, verifierId: "host" }),
    };
    const first = agent({ prompt: "hello there!", lance });
    await first.consume();
    expect(first.lanceRuntime!.metrics("m").outcome).toBe("awaiting_input");
    const messages = (prompt: string) => [
      ...JSON.parse(
        readFileSync(join(first.session.rootPath, "messages.json"), "utf8"),
      ),
      { role: "user", content: prompt },
    ];
    const second = agent({
      session: first.session,
      messages: messages("http://example.test"),
      prompt: "http://example.test",
      lance,
    });
    await second.consume();
    expect(second.lanceRuntime!.metrics("m").outcome).toBe("awaiting_input");
    const third = agent({
      session: first.session,
      messages: messages("Capture the flag"),
      prompt: "Capture the flag",
      lance,
    });
    await third.consume();
    expect(third.lanceRuntime!.metrics("m")).toMatchObject({
      outcome: "verified",
      harnessVerifiedSuccess: true,
    });
    expect(JSON.stringify(state.model.doStreamCalls[1].prompt)).toContain(
      "What is the target?",
    );
    expect(JSON.stringify(state.model.doStreamCalls[2].prompt)).toContain(
      "What is the objective?",
    );
    expect(() =>
      agent({ session: first.session, prompt: "One more thing" }),
    ).toThrow("terminal");
    expect(doStream).toHaveBeenCalledTimes(3);
    const followUp = agent({
      session: first.session,
      messages: messages("Explain the result"),
      prompt: "Explain the result",
      lance,
    });
    await followUp.consume();
    expect(followUp.lanceRuntime!.metrics("m").outcome).toBe("awaiting_input");
    expect(doStream).toHaveBeenCalledTimes(4);
  });

  it("never invokes the Finding Judge when the judge setting is disabled", async () => {
    const spawn = vi.spyOn(inProcessSubagentSpawner, "spawn");
    state.model = new MockLanguageModelV3({
      doStream: async () =>
        stream([
          {
            type: "tool-call",
            toolCallId: "proof",
            toolName: "finish_task",
            input: JSON.stringify({
              summary: "Finished the requested test",
              evidence: "claim",
              poc: {
                script: "echo proof",
                type: "bash",
                stdout: "proof",
                stderr: "",
                exitCode: 0,
              },
            }),
          },
          {
            type: "finish",
            finishReason: { unified: "tool-calls", raw: "tool_calls" },
            usage,
          },
        ]),
    });
    try {
      const running = agent({ findingPolicy: "external" });
      await running.consume();
      expect(spawn).not.toHaveBeenCalled();
      expect(running.lanceRuntime?.metrics("m")).toMatchObject({
        outcome: "completed",
        judgeUsage: { requests: 0 },
        harnessVerifiedSuccess: false,
      });
    } finally {
      spawn.mockRestore();
    }
  });

  it("uses the existing Finding Judge only when enabled and stops after its acceptance", async () => {
    let requests = 0;
    const doStream = vi.fn(async () => {
      const judging = requests++ > 0;
      return stream([
        {
          type: "tool-call",
          toolCallId: judging ? "verdict" : "proof",
          toolName: judging ? "response" : "submit_objective",
          input: JSON.stringify(
            judging
              ? {
                  result: {
                    valid: true,
                    findingType: "vulnerability",
                    confidence: 0.95,
                    reasoning: "Verified",
                    concerns: [],
                    verificationSteps: [],
                    toolEvidence: [],
                    reproducedPoc: true,
                    webResearchUsed: false,
                    limitations: [],
                  },
                }
              : {
                  evidence: "protected proof",
                  poc: {
                    script: "curl http://example.test/proof",
                    type: "bash",
                    stdout: "proof",
                    stderr: "",
                    exitCode: 0,
                  },
                },
          ),
        },
        {
          type: "finish",
          finishReason: { unified: "tool-calls", raw: "tool_calls" },
          usage,
        },
      ]);
    });
    state.model = new MockLanguageModelV3({ doStream });
    const running = agent({
      findingPolicy: "native",
      target: "http://example.test",
    });
    await running.consume();
    expect(doStream).toHaveBeenCalledTimes(2);
    expect(running.lanceRuntime?.metrics("m")).toMatchObject({
      outcome: "judge_accepted",
      modelJudgedSuccess: true,
      harnessVerifiedSuccess: false,
      judgeUsage: { requests: 1 },
    });
  });

  it("returns before the hard deadline when inference stalls", async () => {
    const doStream = vi.fn(async () => ({
      stream: new ReadableStream<LanguageModelV3StreamPart>(),
    }));
    state.model = new MockLanguageModelV3({ doStream });
    const running = agent({
      lance: { timeoutMs: 1500, shutdownReserveMs: 1200 },
    });
    await running.consume();
    const metrics = running.lanceRuntime!.metrics("m");
    expect(metrics.outcome).toBe("deadline_exhausted");
    expect(metrics.elapsedMs).toBeLessThan(1500);
    expect(metrics.usage.usageComplete).toBe(false);
    expect(doStream).toHaveBeenCalledTimes(1);
  });

  it("cancels pending approval without executing or leaving a timer behind", async () => {
    state.model = new MockLanguageModelV3({
      doStream: async () =>
        stream([
          { type: "stream-start", warnings: [] },
          {
            type: "tool-call",
            toolCallId: "approval",
            toolName: "execute_command",
            input: JSON.stringify({
              command: "echo forbidden",
              toolCallDescription: "approval test",
            }),
          },
          {
            type: "finish",
            finishReason: { unified: "tool-calls", raw: "tool_calls" },
            usage,
          },
        ]),
    });
    const gate = new ApprovalGate({ requireApproval: true });
    const execute = vi.fn();
    const requested = vi.fn();
    gate.on("approval-needed", requested);
    const running = agent({
      activeTools: ["execute_command"],
      approvalGate: gate,
      sandbox: { type: "linux", execute },
      lance: { timeoutMs: 1500, shutdownReserveMs: 1200 },
    });
    await running.consume();
    expect(requested).toHaveBeenCalledTimes(1);
    expect(execute).not.toHaveBeenCalled();
    expect(gate.getPendingApprovals()).toEqual([]);
    expect(running.lanceRuntime!.metrics("m").outcome).toBe(
      "deadline_exhausted",
    );
  });

  it.each([
    "submit_objective",
    "finish_task",
  ])("stops same-response work and subsequent requests after %s", async (completionTool) => {
    const doStream = vi.fn(async () =>
      stream([
        { type: "stream-start", warnings: [] },
        {
          type: "tool-call",
          toolCallId: "proof",
          toolName: completionTool,
          input: JSON.stringify(
            completionTool === "finish_task"
              ? { summary: "Requested test is complete" }
              : { evidence: "FLAG{proof}" },
          ),
        },
        {
          type: "tool-call",
          toolCallId: "late",
          toolName: "execute_command",
          input: JSON.stringify({
            command: "echo should-not-run",
            toolCallDescription: "late work",
          }),
        },
        {
          type: "finish",
          finishReason: { unified: "tool-calls", raw: "tool_calls" },
          usage,
        },
      ]),
    );
    const doGenerate = vi.fn();
    state.model = new MockLanguageModelV3({ doStream, doGenerate });
    const running = agent({
      lance: {
        verifyObjective: async () => ({
          verified: true,
          verifierId: "test-host",
        }),
      },
    });
    await running.consume();
    expect(doStream).toHaveBeenCalledTimes(1);
    expect(doGenerate).not.toHaveBeenCalled();
    expect(running.lanceRuntime?.metrics("m")).toMatchObject({
      outcome: completionTool === "finish_task" ? "completed" : "verified",
      toolCalls: 1,
      usage: { requests: 1 },
    });
  });

  it("does not repair forbidden tools with another model", async () => {
    let step = 0;
    const doStream = vi.fn(async () =>
      stream(
        step++ === 0
          ? [
              { type: "stream-start", warnings: [] },
              {
                type: "tool-call",
                toolCallId: "forbidden",
                toolName: "spawn_pentest_agent",
                input: "{}",
              },
              {
                type: "finish",
                finishReason: { unified: "tool-calls", raw: "tool_calls" },
                usage,
              },
            ]
          : [
              {
                type: "finish",
                finishReason: { unified: "stop", raw: "stop" },
                usage,
              },
            ],
      ),
    );
    const doGenerate = vi.fn();
    state.model = new MockLanguageModelV3({ doStream, doGenerate });
    const running = agent();
    await running.consume();
    expect(doGenerate).not.toHaveBeenCalled();
    expect(running.lanceRuntime?.metrics("m").policyViolations).toMatchObject([
      { kind: "forbidden_tool", name: "spawn_pentest_agent" },
    ]);
  });

  it("compacts repeatedly with the same model, restores the latest plan, and meters all work", async () => {
    let summaries = 0;
    let steps = 0;
    const doGenerate = vi.fn(async () => ({
      content: [
        {
          type: "text" as const,
          text: `summary-${++summaries}: stay within example.test`,
        },
      ],
      finishReason: { unified: "stop" as const, raw: "stop" },
      usage,
      warnings: [],
    }));
    const doStream = vi.fn(async () =>
      stream(
        ++steps === 1
          ? [
              { type: "text-start", id: "long" },
              {
                type: "text-delta",
                id: "long",
                delta: "observation ".repeat(80_000),
              },
              { type: "text-end", id: "long" },
              {
                type: "tool-call",
                toolCallId: "plan",
                toolName: "update_plan",
                input: JSON.stringify({
                  explanation:
                    "Evidence and failed probes are in scratchpad.md",
                  plan: [
                    {
                      step: "Verify the remaining hypothesis",
                      status: "in_progress",
                    },
                  ],
                }),
              },
              {
                type: "finish",
                finishReason: { unified: "tool-calls", raw: "tool_calls" },
                usage,
              },
            ]
          : [
              {
                type: "tool-call",
                toolCallId: "done",
                toolName: "finish_task",
                input: JSON.stringify({ summary: "Done", evidence: "proof" }),
              },
              {
                type: "finish",
                finishReason: { unified: "tool-calls", raw: "tool_calls" },
                usage,
              },
            ],
      ),
    );
    state.model = new MockLanguageModelV3({ doStream, doGenerate });
    const running = agent({
      messages: [
        {
          role: "user",
          content:
            "Capture the objective on example.test. " +
            "history ".repeat(100_000),
        },
      ],
      lance: {
        pricing: { input: 1, output: 2, cacheRead: 0, cacheWrite: 0 },
        verifyObjective: async () => ({ verified: true, verifierId: "host" }),
      },
    });
    await running.consume();
    expect(doGenerate).toHaveBeenCalledTimes(2);
    expect(doStream).toHaveBeenCalledTimes(2);
    for (const request of state.model.doGenerateCalls)
      expect(request.toolChoice).toEqual({ type: "none" });
    const continued = JSON.stringify(state.model.doStreamCalls[1].prompt);
    expect(continued).toContain("summary-2");
    expect(continued).not.toContain("summary-1");
    expect(continued).toContain("Verify the remaining hypothesis");
    expect(continued).toContain("scratchpad.md");
    expect(running.lanceRuntime?.metrics("m")).toMatchObject({
      outcome: "verified",
      usage: {
        requests: 4,
        inputTokens: 400,
        outputTokens: 40,
        costUsd: 0.00048,
      },
      usageBeforeSuccess: { requests: 4 },
      compactionUsage: {
        requests: 2,
        inputTokens: 200,
        outputTokens: 20,
        costUsd: 0.00024,
      },
      judgeUsage: { requests: 0 },
      policyViolations: [],
    });
    const persisted = readFileSync(
      join(running.session.rootPath, "messages.json"),
      "utf8",
    );
    expect(persisted.includes("summary-2")).toBe(true);
    expect(persisted).toContain("scratchpad.md");
  });

  it("cancels a stalled compaction before the deadline without resuming inference", async () => {
    const doGenerate = vi.fn(() => new Promise<never>(() => {}));
    const doStream = vi.fn();
    state.model = new MockLanguageModelV3({ doGenerate, doStream });
    const running = agent({
      messages: [{ role: "user", content: "history ".repeat(100_000) }],
      lance: { timeoutMs: 1500, shutdownReserveMs: 1200 },
    });
    await running.consume();
    expect(doGenerate).toHaveBeenCalledTimes(1);
    expect(doStream).not.toHaveBeenCalled();
    expect(running.lanceRuntime!.metrics("m")).toMatchObject({
      outcome: "deadline_exhausted",
      compactionUsage: { requests: 1, usageComplete: false, costUsd: null },
    });
    expect(running.lanceRuntime!.metrics("m").elapsedMs).toBeLessThan(1500);
  });

  it("ends gracefully when compaction cannot fit, without a reset that discards progress", async () => {
    const doGenerate = vi.fn(async () => {
      throw new Error("maximum context length exceeded");
    });
    const doStream = vi.fn();
    state.model = new MockLanguageModelV3({ doGenerate, doStream });
    const running = agent({
      messages: [{ role: "user", content: "history ".repeat(100_000) }],
    });
    await running.consume();
    expect(doGenerate.mock.calls.length).toBeGreaterThan(0);
    expect(doGenerate.mock.calls.length).toBeLessThanOrEqual(8);
    expect(doStream).not.toHaveBeenCalled();
    expect(running.lanceRuntime!.metrics("m").outcome).toBe(
      "context_exhausted",
    );
  });
});
