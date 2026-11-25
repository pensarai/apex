import { mkdirSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { LanguageModelV3StreamPart } from "@ai-sdk/provider";
import { simulateReadableStream, stepCountIs } from "ai";
import { MockLanguageModelV3 } from "ai/test";
import { afterEach, describe, expect, it, vi } from "vitest";
import { z } from "zod";
import { AgentEventBus, type BackgroundJobState } from "../../eventBus";
import type { FindingJudgeResult } from "../specialized/findingJudge";
import { OffensiveSecurityAgent } from "./offensiveSecurityAgent";
import type { OffensiveSecurityAgentInput } from "./types";

const state: {
  model?: MockLanguageModelV3;
  judge?: () => Promise<FindingJudgeResult>;
} = {};
vi.mock("../specialized/findingJudge", async () => ({
  ...(await vi.importActual<typeof import("../specialized/findingJudge")>(
    "../specialized/findingJudge",
  )),
  judgeFinding: () => state.judge!(),
}));
vi.mock("../../ai/utils", async () => ({
  ...(await vi.importActual<typeof import("../../ai/utils")>("../../ai/utils")),
  getProviderModel: () => state.model,
}));

const roots: string[] = [];
afterEach(() => {
  for (const root of roots.splice(0))
    rmSync(root, { recursive: true, force: true });
});
const usage = {
  inputTokens: { total: 100, noCache: 100, cacheRead: 0, cacheWrite: 0 },
  outputTokens: { total: 10, text: 10, reasoning: undefined },
};
function response(chunks: LanguageModelV3StreamPart[], tools = false) {
  return {
    stream: simulateReadableStream<LanguageModelV3StreamPart>({
      chunks: [
        { type: "stream-start", warnings: [] },
        ...chunks,
        {
          type: "finish",
          finishReason: {
            unified: tools ? "tool-calls" : "stop",
            raw: tools ? "tool_calls" : "stop",
          },
          usage,
        },
      ],
    }),
  };
}
function textResponse(text: string) {
  return response([
    { type: "text-start", id: "text" },
    { type: "text-delta", id: "text", delta: text },
    { type: "text-end", id: "text" },
  ]);
}
function command(id: string, command: string, background = false) {
  return response(
    [
      {
        type: "tool-call",
        toolCallId: id,
        toolName: "execute_command",
        input: JSON.stringify({ command, background, toolCallDescription: id }),
      },
    ],
    true,
  );
}
function makeAgent(extra: Partial<OffensiveSecurityAgentInput<void>> = {}) {
  const rootPath = mkdtempSync(join(tmpdir(), "apex-background-agent-"));
  roots.push(rootPath);
  for (const dir of ["pocs", "findings", "logs"])
    mkdirSync(join(rootPath, dir));
  return new OffensiveSecurityAgent({
    prompt: "Run a slow scan, continue other work and report the completion",
    model: "claude-haiku-4-5",
    toolProtocol: "direct",
    activeTools: ["execute_command", "command_job"],
    stopWhen: stepCountIs(10),
    session: {
      id: "ses_background",
      rootPath,
      targets: ["https://example.com"],
      pocsPath: join(rootPath, "pocs"),
      findingsPath: join(rootPath, "findings"),
      logsPath: join(rootPath, "logs"),
      scratchpadPath: rootPath,
    },
    ...extra,
  } as OffensiveSecurityAgentInput<void>);
}

describe("managed command agent lifecycle", () => {
  it("continues foreground work and wakes after a text-only answer with persisted results", async () => {
    let calls = 0;
    state.model = new MockLanguageModelV3({
      doStream: async ({ prompt }) => {
        calls++;
        if (calls === 1)
          return command("slow", "sleep 0.6; printf background-finished", true);
        if (calls === 2) return command("other", "printf foreground-finished");
        if (calls === 3) {
          expect(JSON.stringify(prompt)).toContain("foreground-finished");
          expect(JSON.stringify(prompt)).not.toContain(
            "Background command completed",
          );
          return textResponse("Continuing once the scan finishes.");
        }
        expect(calls).toBe(4);
        expect(JSON.stringify(prompt)).toContain(
          "Background command completed",
        );
        expect(JSON.stringify(prompt)).toContain("background-finished");
        return textResponse("Scan result received.");
      },
    });
    const agent = makeAgent();
    await agent.consume();
    expect(calls).toBe(4);
    const messages = readFileSync(
      join(agent.session.rootPath, "messages.json"),
      "utf8",
    );
    expect(messages).toContain("Background command completed");
    expect(messages).toContain("foreground-finished");
    expect(messages).toContain("Scan result received.");
  });

  it("retains a completion injected between tool steps in later model context", async () => {
    let calls = 0;
    state.model = new MockLanguageModelV3({
      doStream: async ({ prompt }) => {
        calls++;
        if (calls === 1)
          return command("slow", "sleep 0.1; printf bg-result", true);
        if (calls === 2) return command("other", "sleep 0.3; printf fg-result");
        expect(JSON.stringify(prompt)).toContain(
          "Background command completed",
        );
        if (calls === 3) return command("third", "printf third-result");
        expect(calls).toBe(4);
        expect(
          JSON.stringify(prompt).match(/Background command completed/g),
        ).toHaveLength(1);
        return textResponse("All done.");
      },
    });
    await makeAgent().consume();
    expect(calls).toBe(4);
  });

  it("honors the step limit without waiting for or restarting on background completion", async () => {
    let calls = 0;
    state.model = new MockLanguageModelV3({
      doStream: async () => {
        calls++;
        return command("slow", "sleep 30", true);
      },
    });
    await makeAgent({ stopWhen: stepCountIs(1) }).consume();
    expect(calls).toBe(1);
  });

  it("stops an idle background wait when the turn is cancelled", async () => {
    const controller = new AbortController();
    let calls = 0;
    state.model = new MockLanguageModelV3({
      doStream: async () => {
        calls++;
        if (calls === 1) return command("slow", "sleep 30", true);
        setTimeout(() => controller.abort(new Error("stop turn")), 100);
        return textResponse("Waiting for completion.");
      },
    });
    await expect(
      makeAgent({ abortSignal: controller.signal }).consume(),
    ).rejects.toThrow("stop turn");
    expect(calls).toBe(2);
  });
});

describe("background verdict agent lifecycle", () => {
  it.each([
    undefined,
    "pentest-worker",
  ])("delivers verdicts to %s and prevents premature structured completion", async (subagentId) => {
    let release: ((result: FindingJudgeResult) => void) | undefined;
    state.judge = () =>
      new Promise((resolve) => {
        release = resolve;
      });
    const bus = new AgentEventBus();
    const updates: BackgroundJobState[] = [];
    bus.on("background-job", (job) => updates.push(job));
    let calls = 0;
    const finalResponse = (summary: string) =>
      response(
        [
          {
            type: "tool-call",
            toolCallId: `response-${calls}`,
            toolName: "response",
            input: JSON.stringify({ result: { summary } }),
          },
        ],
        true,
      );
    state.model = new MockLanguageModelV3({
      doStream: async ({ prompt }) => {
        calls++;
        if (calls === 1)
          return response(
            [
              {
                type: "tool-call",
                toolCallId: "document",
                toolName: "document_vulnerability",
                input: JSON.stringify({
                  title: "Test claim",
                  description: "Fixture claim",
                  impact: "Fixture impact",
                  evidence: "Fixture evidence",
                  materiality: {
                    exploitPath: "Fixture",
                    securityImpact: "Fixture",
                    affectedAssetOrAbusePath: "Fixture",
                    falsePositiveRationale: "Fixture",
                  },
                  endpoint: "https://example.com",
                  remediation: "Fixture",
                  toolCallDescription: "Validate fixture",
                  pocName: "fixture",
                  pocType: "bash",
                  pocContent: "printf fixture",
                  pocDescription: "Fixture",
                  credentialIds: [],
                }),
              },
            ],
            true,
          );
        if (calls === 2) {
          await vi.waitFor(() => expect(release).toBeDefined());
          expect(JSON.stringify(prompt)).toContain('"status":"running"');
          return command("independent", "printf independent-work");
        }
        if (calls === 3) return finalResponse("Premature report");
        if (calls === 4) {
          expect(JSON.stringify(prompt)).toContain(
            "Background jobs still have pending results",
          );
          expect(JSON.stringify(prompt)).toContain("independent-work");
          setTimeout(
            () =>
              release!({
                valid: false,
                findingType: "vulnerability",
                confidence: 0.9,
                reasoning: "Impact not demonstrated",
                concerns: [],
                verificationSteps: [],
                toolEvidence: [],
                reproducedPoc: false,
                webResearchUsed: false,
                limitations: [],
              }),
            30,
          );
          return textResponse("Waiting for the verdict.");
        }
        expect(calls).toBe(5);
        expect(JSON.stringify(prompt)).toContain(
          "Background document_vulnerability completed",
        );
        expect(JSON.stringify(prompt)).toContain("Impact not demonstrated");
        return finalResponse("Claim rejected; report updated.");
      },
    });
    const agent = makeAgent({
      subagentId,
      eventBus: bus,
      activeTools: ["document_vulnerability", "execute_command", "response"],
      responseSchema: z.object({ summary: z.string() }),
    });
    expect(await agent.consume()).toEqual({
      summary: "Claim rejected; report updated.",
    });
    await agent.drained;
    expect(calls).toBe(5);
    expect(updates[0]).toMatchObject({
      toolName: "document_vulnerability",
      status: "running",
      subagentId,
    });
    expect(updates.at(-1)).toMatchObject({
      status: "completed",
      success: false,
    });
    expect(
      readFileSync(
        join(
          agent.session.rootPath,
          ...(subagentId ? ["subagents", subagentId] : []),
          "messages.json",
        ),
        "utf8",
      ),
    ).toContain("Impact not demonstrated");
  });
});
