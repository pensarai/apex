import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import { readGoalFile } from "../../../goals";
import type { SessionInfo } from "../../../session";
import { writeRecord } from "../../offSecAgent/tools/topologyRecords";
import {
  type GeneralizedAttackSurfaceAgentInput,
  type GeneralizedAttackSurfaceResult,
  generalizedAttackSurfaceDefinition,
  runGeneralizedReconToReport,
} from "./generalizedAgent";
import { bindGoalReport } from "./reconGoal";

const roots: string[] = [];
afterEach(() => {
  for (const root of roots.splice(0))
    rmSync(root, { recursive: true, force: true });
});
function input(): GeneralizedAttackSurfaceAgentInput {
  const rootPath = mkdtempSync(join(tmpdir(), "recon-goal-"));
  roots.push(rootPath);
  return {
    target: "https://app.example",
    model: "claude-sonnet-4-5",
    goal: {
      objective:
        "Map the supplied application and check all supported threats and controls.",
      maxRounds: 3,
    },
    session: {
      id: "ses_goal",
      rootPath,
      targets: ["https://app.example"],
    } as SessionInfo,
  };
}
type Turn = {
  claim?: boolean;
  quote?: string;
  success?: boolean;
  report?: boolean;
  mutate?: boolean;
  tools?: number;
};
function scripted(turns: Turn[]) {
  const calls: GeneralizedAttackSurfaceAgentInput[] = [];
  const drain = vi.fn(async () => {});
  const factory = (i: GeneralizedAttackSurfaceAgentInput) => ({
    abortAndDrain: drain,
    consume: async () => {
      const turn = turns[calls.length] ?? {};
      calls.push(i);
      assert(i.goalTurn);
      assert(i.messages);
      const root = i.session.rootPath;
      const report = { summary: { analysisComplete: true }, targets: [] };
      if (turn.report) {
        writeFileSync(
          join(root, "attack-surface-results.json"),
          JSON.stringify(report),
        );
        bindGoalReport(root, i.goalTurn);
      }
      if (turn.mutate)
        writeRecord(root, "ses_goal", "component", "new-service", {
          id: "new-service",
          name: "New service",
          kind: "application",
        });
      writeFileSync(
        join(root, "messages.json"),
        JSON.stringify([
          ...i.messages,
          {
            role: "tool",
            content: [
              {
                type: "tool-result",
                toolCallId: `t${calls.length}`,
                toolName: "read_file",
                output: {
                  type: "json",
                  value: {
                    success: turn.success !== false,
                    content: "Reviewed current source",
                  },
                },
              },
            ],
          },
        ]),
      );
      return {
        results: turn.report ? report : null,
        targets: [],
        resultsPath: join(root, "attack-surface-results.json"),
        assetsPath: join(root, "assets"),
        goalTurnFacts: {
          outcome: "completed",
          automatic: i.goalTurn.rounds > 0,
          heldCallCount: 0,
          toolCallCount: turn.tools ?? 1,
          updateCall: turn.claim
            ? {
                status: "complete",
                summary: "Mapped and reviewed",
                evidence: [
                  {
                    tool: "read_file",
                    quote: turn.quote ?? "Reviewed current source",
                  },
                ],
              }
            : null,
        },
      } as GeneralizedAttackSurfaceResult;
    },
  });
  return { calls, drain, factory };
}

describe("persistent-goal recon", () => {
  it("continues past report creation until an evidence-checked completion claim", async () => {
    const i = input();
    const s = scripted([{ report: true }, { report: true, claim: true }]);
    const result = await runGeneralizedReconToReport(i, s.factory);
    expect(s.calls).toHaveLength(2);
    expect(result.goal?.status).toBe("complete");
    expect(result.goal?.completion?.evidence[0]).toMatch(
      /^local:ses_goal\/m\d+\/p0$/,
    );
    expect(s.calls[1]?.messages?.some((m) => m.role === "tool")).toBe(true);
    expect(s.drain).toHaveBeenCalledTimes(2);
  });
  it.each([
    { quote: "fabricated evidence" },
    { success: false },
  ])("rejects a bad citation and continues: %j", async (bad) => {
    const s = scripted([
      { report: true, claim: true, ...bad },
      { report: true, claim: true },
    ]);
    await runGeneralizedReconToReport(input(), s.factory);
    expect(s.calls).toHaveLength(2);
    expect(JSON.stringify(s.calls[1]?.messages)).toContain(
      "completion claim was not accepted",
    );
  });
  it("rejects a completion claim whose topology changed after the report", async () => {
    const s = scripted([
      { report: true, claim: true, mutate: true },
      { report: true, claim: true },
    ]);
    await runGeneralizedReconToReport(input(), s.factory);
    expect(s.calls).toHaveLength(2);
    expect(JSON.stringify(s.calls[1]?.messages)).toContain(
      "topology changed after the report",
    );
  });
  it("ends blocked at the round limit and gives exactly one wrap-up turn", async () => {
    const i = input();
    assert(i.goal);
    i.goal.maxRounds = 1;
    const s = scripted([{ claim: true }]);
    await expect(runGeneralizedReconToReport(i, s.factory)).rejects.toThrow(
      "Recon goal blocked: rounds",
    );
    expect(s.calls).toHaveLength(2);
    expect(s.calls[1]?.goalTurn?.status).toBe("blocked");
    expect(s.calls[1]?.stepLimit).toBe(1);
    expect(readGoalFile(i.session.rootPath)?.status).toBe("blocked");
  });
  it("preserves active goals on cancellation and resumes the same objective", async () => {
    const i = input();
    const controller = new AbortController();
    i.abortSignal = controller.signal;
    await expect(
      runGeneralizedReconToReport(i, () => ({
        consume: async () => {
          controller.abort();
          throw new Error("cancelled");
        },
      })),
    ).rejects.toThrow("cancelled");
    const before = readGoalFile(i.session.rootPath);
    assert(before);
    expect(before.status).toBe("active");
    const s = scripted([{ report: true, claim: true }]);
    const result = await runGeneralizedReconToReport(
      { ...i, abortSignal: undefined },
      s.factory,
    );
    expect(result.goal?.id).toBe(before.id);
    expect(result.goal?.status).toBe("complete");
  });
  it("persists provider failures as blocked and drains the agent", async () => {
    const i = input();
    const drain = vi.fn(async () => {});
    await expect(
      runGeneralizedReconToReport(i, () => ({
        consume: async () => {
          throw new Error("provider unavailable");
        },
        abortAndDrain: drain,
      })),
    ).rejects.toThrow("provider unavailable");
    expect(readGoalFile(i.session.rootPath)?.reason).toBe("turn_failed");
    expect(drain).toHaveBeenCalledOnce();
  });

  it("retains the original evidence window when an active goal resumes", async () => {
    const i = input();
    const controller = new AbortController();
    const first = scripted([{ report: true }]);
    await expect(
      runGeneralizedReconToReport(
        { ...i, abortSignal: controller.signal },
        (turn) => {
          if (first.calls.length === 0) return first.factory(turn);
          return {
            consume: async () => {
              controller.abort();
              throw new Error("cancelled");
            },
          };
        },
      ),
    ).rejects.toThrow("cancelled");
    expect(readGoalFile(i.session.rootPath)?.rounds).toBe(1);
    const resumed = scripted([{ report: true, claim: true, success: false }]);
    const result = await runGeneralizedReconToReport(i, resumed.factory);
    expect(result.goal?.status).toBe("complete");
    expect(resumed.calls).toHaveLength(1);
    expect(
      resumed.calls[0]?.messages?.filter(
        (m) => typeof m.content === "string" && m.content.startsWith("Goal: "),
      ),
    ).toHaveLength(1);
  });
  it("keeps goals and audit workers mutually exclusive", async () => {
    const i = input();
    i.completion = { version: 1, mode: "enforce" };
    const factory = vi.fn();
    await expect(runGeneralizedReconToReport(i, factory)).rejects.toThrow(
      "not both",
    );
    expect(factory).not.toHaveBeenCalled();
  });
  it("rechecks the output when resuming a completed goal", async () => {
    const i = input();
    const s = scripted([{ report: true, claim: true }]);
    await runGeneralizedReconToReport(i, s.factory);
    const reportPath = join(i.session.rootPath, "attack-surface-results.json");
    const report = JSON.parse(readFileSync(reportPath, "utf8"));
    report.targets.push({ target: "https://provider.example" });
    writeFileSync(reportPath, JSON.stringify(report));
    await expect(runGeneralizedReconToReport(i, s.factory)).rejects.toThrow(
      "stale output",
    );
    expect(s.calls).toHaveLength(1);
  });
  it("offers update_goal only to the goal turn and only read access to its wrap-up", async () => {
    const i = input();
    const s = scripted([{ report: true, claim: true }]);
    await runGeneralizedReconToReport(i, s.factory);
    const turn = s.calls[0];
    assert(turn?.goalTurn);
    assert(generalizedAttackSurfaceDefinition.createState);
    const state = generalizedAttackSurfaceDefinition.createState(turn);
    expect(
      generalizedAttackSurfaceDefinition.activeTools(turn, state),
    ).toContain("update_goal");
    expect(
      generalizedAttackSurfaceDefinition.activeTools(
        { ...turn, goalTurn: { ...turn.goalTurn, status: "blocked" } },
        state,
      ),
    ).toEqual(["read_file"]);
    expect(
      generalizedAttackSurfaceDefinition.activeTools(i, state),
    ).not.toContain("update_goal");
  });
});
