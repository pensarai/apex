import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import type { FindingsRegistry } from "../findings/registry";
import type { SessionInfo } from "../session";
import { runEngagementLead } from "./engagementLead";
import { buildEngagementState } from "./engagementState";

type PlannerInput = {
  extraTools: {
    read_file: {
      execute: (input: {
        path: string;
        startLine: number;
        endLine: number;
      }) => Promise<unknown>;
    };
  };
};

const mocks = vi.hoisted(() => ({
  consume: vi.fn(),
  abortAndDrain: vi.fn(),
  startPlannedMissions: vi.fn(),
  dispose: vi.fn(),
}));

vi.mock("../agents/offSecAgent", () => ({
  OffensiveSecurityAgent: class {
    constructor(private readonly input: PlannerInput) {}
    consume() {
      return mocks.consume(this.input);
    }
    abortAndDrain = mocks.abortAndDrain;
  },
}));

vi.mock("./engagementTools", () => ({
  ENGAGEMENT_TOOL_NAMES: [],
  createEngagementTools: () => ({
    tools: {},
    startPlannedMissions: mocks.startPlannedMissions,
    dispose: mocks.dispose,
  }),
  findEngagementChainCoverageGaps: vi.fn(),
  formatEngagementChainCoverageGaps: vi.fn(),
}));

const directories: string[] = [];
afterEach(() => {
  vi.resetAllMocks();
  for (const path of directories.splice(0))
    rmSync(path, { recursive: true, force: true });
});

function setup() {
  const rootPath = mkdtempSync(join(tmpdir(), "apex-lead-planning-"));
  directories.push(rootPath);
  const target = "https://example.test";
  const targets = [
    { target: `${target}/a`, objectives: ["Test authorization"] },
    { target: `${target}/b`, objectives: ["Test authorization"] },
  ];
  const session = {
    id: "session-test",
    rootPath,
    config: { engagementCoverageMode: "grouped" },
  } as SessionInfo;
  return {
    rootPath,
    target,
    targets,
    run: () =>
      runEngagementLead({
        workflow: { target, model: "test-model", session },
        targets,
        findingsRegistry: {} as FindingsRegistry,
      }),
  };
}

describe("engagement planning completion boundary", () => {
  it("fails before dispatch when the planner ends without a valid ready plan", async () => {
    const { rootPath, run } = setup();
    mocks.consume.mockResolvedValue(undefined);

    await expect(run()).rejects.toThrow();

    expect(mocks.startPlannedMissions).not.toHaveBeenCalled();
    expect(mocks.dispose).toHaveBeenCalledOnce();
    expect(mocks.abortAndDrain).toHaveBeenCalledOnce();
    const metrics = JSON.parse(
      readFileSync(
        join(rootPath, "coordination/engagement-run-metrics.json"),
        "utf8",
      ),
    );
    expect(metrics.status).toBe("failed");
  });

  it("validates and seals a ready artifact even when the planner omits its final response", async () => {
    const { rootPath, target, targets, run } = setup();
    const planPath = join(rootPath, "coordination/engagement-plan.json");
    mocks.consume.mockImplementation(async (input: PlannerInput) => {
      await input.extraTools.read_file.execute({
        path: "coordination/engagement-planning-manifest.json",
        startLine: 1,
        endLine: 10_000,
      });
      const draft = JSON.parse(readFileSync(planPath, "utf8"));
      const state = buildEngagementState(target, targets);
      writeFileSync(
        planPath,
        JSON.stringify({
          version: 1,
          status: "ready",
          contractHash: draft.contractHash,
          missions: [
            {
              id: "authorization-flow",
              purpose: "Test authorization across the related resources",
              rationale: "One actor crosses the same authorization boundary",
              requirements: state.coverage.map(
                ({ targetId, objectiveId }, index) => ({
                  id: `authorization-${index}`,
                  description: "Unauthorized access must be rejected",
                  rationale: "Related resources have the same access policy",
                  coverage: [{ targetId, objectiveId }],
                }),
              ),
            },
          ],
        }),
      );
    });
    mocks.startPlannedMissions.mockImplementation(() => {
      expect(JSON.parse(readFileSync(planPath, "utf8")).status).toBe("sealed");
      throw new Error("Dispatch reached after sealing");
    });

    await expect(run()).rejects.toThrow("Dispatch reached after sealing");
    expect(mocks.startPlannedMissions).toHaveBeenCalledOnce();
  });
});
