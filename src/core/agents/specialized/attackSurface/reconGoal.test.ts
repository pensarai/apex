import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import { readGoalFile } from "../../../goals";
import type { SessionInfo } from "../../../session";
import {
  loadTopology,
  writeRecord,
} from "../../offSecAgent/tools/topologyRecords";
import {
  type GeneralizedAttackSurfaceAgentInput,
  type GeneralizedAttackSurfaceResult,
  generalizedAttackSurfaceDefinition,
  runGeneralizedReconToReport,
} from "./generalizedAgent";
import { bindGoalReport, type ReconGoalJournal } from "./reconGoal";

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
  incomplete?: boolean;
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
      const report = {
        summary: { analysisComplete: !turn.incomplete },
        targets: [],
      };
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
  it("replays into fresh scratch with the same objective and no repeated model work", async () => {
    const entries: { key: string; value: unknown }[] = [];
    let cursor = 0;
    const journal: ReconGoalJournal = {
      async runStep<T>(key: string, run: () => Promise<T>): Promise<T> {
        const entry = entries[cursor++];
        if (entry) {
          expect(entry.key).toBe(key);
          return structuredClone(entry.value) as T;
        }
        const value = await run();
        entries.push({ key, value: structuredClone(value) });
        return value;
      },
    };
    const i = { ...input(), goalJournal: journal };
    const controller = new AbortController();
    const first = scripted([{ report: true }]);
    let modelCalls = 0;
    await expect(
      runGeneralizedReconToReport(
        { ...i, abortSignal: controller.signal },
        (turn) => ({
          consume: async () => {
            if (turn.goalTurn?.rounds === 1) {
              controller.abort();
              throw new Error("executor stopped");
            }
            await journal.runStep("model", async () => ++modelCalls);
            return first.factory(turn).consume();
          },
        }),
      ),
    ).rejects.toThrow("executor stopped");
    const original = readGoalFile(i.session.rootPath);
    expect(original?.rounds).toBe(1);
    cursor = 0;
    const resumed = scripted([{ report: true }, { report: true, claim: true }]);
    const result = await runGeneralizedReconToReport(
      { ...i, session: { ...i.session, rootPath: input().session.rootPath } },
      (turn) => ({
        consume: async () => {
          await journal.runStep("model", async () => ++modelCalls);
          return resumed.factory(turn).consume();
        },
      }),
    );
    expect(result.goal?.id).toBe(original?.id);
    expect(result.goal?.status).toBe("complete");
    expect(result.goal?.rounds).toBe(2);
    expect(modelCalls).toBe(2);
    expect(resumed.calls).toHaveLength(2);
    expect(resumed.calls[0]?.messages?.some((m) => m.role === "tool")).toBe(
      false,
    );
    expect(resumed.calls[1]?.messages?.some((m) => m.role === "tool")).toBe(
      true,
    );

    cursor = 0;
    await expect(
      runGeneralizedReconToReport(
        { ...i, target: "https://changed.example" },
        resumed.factory,
      ),
    ).rejects.toThrow("scope changed during replay");
  });

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

  it("binds at report execution so later indirect writes cannot refresh the binding", async () => {
    const i = input();
    const s = scripted([{ report: true, claim: true }]);
    await runGeneralizedReconToReport(i, s.factory);
    const turn = s.calls[0];
    assert(turn);
    assert(generalizedAttackSurfaceDefinition.createState);
    assert(generalizedAttackSurfaceDefinition.extraTools);
    const state = generalizedAttackSurfaceDefinition.createState(turn);
    const tools = generalizedAttackSurfaceDefinition.extraTools(turn, state);
    assert(tools);
    const reportTool = tools.create_attack_surface_report;
    assert(reportTool?.execute);
    await reportTool.execute(
      {
        summary: { analysisComplete: true, totalAssets: 0, totalDomains: 0 },
        targets: [],
        discoveredAssets: [],
        keyFindings: [],
        toolCallDescription: "Report",
      },
      { toolCallId: "report-via-exec", messages: [] },
    );
    const refreshed = await runGeneralizedReconToReport(i, s.factory);
    expect(refreshed.goal?.status).toBe("complete");
    expect(s.calls).toHaveLength(1);
    writeRecord(
      i.session.rootPath,
      "worker",
      "component",
      "late-worker-write",
      {
        id: "late-worker-write",
        name: "Worker dependency",
        kind: "application",
      },
    );
    await expect(runGeneralizedReconToReport(i, s.factory)).rejects.toThrow(
      "stale output",
    );
  });

  it("continues when the report explicitly marks analysis incomplete", async () => {
    const s = scripted([
      { report: true, claim: true, incomplete: true },
      { report: true, claim: true },
    ]);
    await runGeneralizedReconToReport(input(), s.factory);
    expect(s.calls).toHaveLength(2);
    expect(JSON.stringify(s.calls[1]?.messages)).toContain(
      "marks analysis incomplete",
    );
  });

  it("uses caller history before an on-disk transcript exists", async () => {
    const i = input();
    i.messages = [
      { role: "user", content: "Keep the customer integration scope" },
    ];
    const s = scripted([{ report: true, claim: true }]);
    await runGeneralizedReconToReport(i, s.factory);
    expect(s.calls[0]?.messages?.[0]).toEqual(i.messages[0]);
  });

  it("resumes an update without reseeding and rejects changed update inputs", async () => {
    const baseline = input().session.rootPath;
    writeRecord(baseline, "baseline", "component", "service", {
      id: "service",
      name: "Service",
      kind: "application",
    });
    const i = input();
    i.update = { baselineSessionRoot: baseline, trigger: { kind: "schedule" } };
    const controller = new AbortController();
    await expect(
      runGeneralizedReconToReport(
        { ...i, abortSignal: controller.signal },
        () => ({
          consume: async () => {
            controller.abort();
            throw new Error("cancelled");
          },
        }),
      ),
    ).rejects.toThrow("cancelled");
    expect(loadTopology(i.session.rootPath).components).toHaveLength(1);
    const s = scripted([{ report: true, claim: true }]);
    await expect(
      runGeneralizedReconToReport(
        {
          ...i,
          update: {
            baselineSessionRoot: baseline,
            trigger: {
              kind: "scope",
              addedOrigins: ["https://new.example"],
              addedRepositories: [],
            },
          },
        },
        s.factory,
      ),
    ).rejects.toThrow("scope or update changed");
    expect(s.calls).toHaveLength(0);
    const result = await runGeneralizedReconToReport(i, s.factory);
    expect(result.goal?.status).toBe("complete");
    expect(s.calls[0]?.updateBrief).toContain("scheduled re-check");
    expect(loadTopology(i.session.rootPath).components).toHaveLength(1);
  });

  it("fails before dispatch when a durable host has not supplied persistence", async () => {
    const i = input();
    i.contextRecorder = {} as NonNullable<typeof i.contextRecorder>;
    const factory = vi.fn();
    await expect(runGeneralizedReconToReport(i, factory)).rejects.toThrow(
      "durable hosts must supply",
    );
    expect(factory).not.toHaveBeenCalled();
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
