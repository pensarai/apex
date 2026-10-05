import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import type { FindingsRegistry } from "../findings/registry";
import type { SessionInfo } from "../session";
import { runEngagementLead } from "./engagementLead";
import { buildEngagementState } from "./engagementState";
import type { EngagementSurfaceProvider } from "./engagementSurface";

type PlannerInput = {
  prompt: string;
  extraTools: {
    get_engagement_target?: {
      execute: (input: { targetId: string }) => Promise<unknown>;
    };
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
    takeLeadHandoffs: () => [],
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

function setup(surfaceProvider?: EngagementSurfaceProvider) {
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
        surfaceProvider,
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
    mocks.consume.mockImplementation(async () => {
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

  it("expands unreviewed consolidation before dispatch and keeps the full surface out of agent prompts", async () => {
    const getTarget = vi.fn();
    const { rootPath, target, targets, run } = setup({
      search: vi.fn(),
      getTarget,
    });
    const planPath = join(rootPath, "coordination/engagement-plan.json");
    mocks.consume.mockImplementationOnce(async (input: PlannerInput) => {
      expect(input.prompt).toContain("on demand");
      expect(input.prompt).not.toContain("Test authorization");
      for (const target of targets)
        expect(input.prompt).not.toContain(target.target);
      const draft = JSON.parse(readFileSync(planPath, "utf8"));
      const state = buildEngagementState(target, targets);
      const requirements = [
        {
          id: "authorization",
          description: "Unauthorized access must be rejected",
          rationale: "Each resource needs its own authorization observation",
          equivalenceBasis: {
            trustBoundary: "User to resource ownership",
            authenticationState: "Owner and peer users",
            expectedBehavior: "Only owners can read the resource",
            evidencePlan: "Compare access for this resource's owner and peer",
          },
          nonConsolidationReason:
            "Unreviewed ownership context could distinguish the resource policies",
          coverage: state.coverage.map(({ targetId, objectiveId }) => ({
            targetId,
            objectiveId,
          })),
        },
      ];
      writeFileSync(
        planPath,
        JSON.stringify({
          version: 2,
          status: "ready",
          contractHash: draft.contractHash,
          requirements,
          missions: [
            {
              id: "authorization-flow",
              purpose: "Test both resource boundaries independently",
              rationale: "Share actor setup, not coverage credit",
              requirementIds: requirements.map((item) => item.id),
            },
          ],
          consolidationReview: {
            status: "complete",
            summary: "Ownership-policy equivalence remains unverified",
          },
        }),
      );
    });
    mocks.startPlannedMissions.mockImplementation(() => {
      const plan = JSON.parse(readFileSync(planPath, "utf8"));
      expect(plan.status).toBe("sealed");
      expect(plan.requirements).toHaveLength(2);
      expect(plan.missions).toMatchObject([
        {
          id: "authorization-flow",
          requirementIds: ["authorization_source_1", "authorization_source_2"],
        },
      ]);
      return Promise.resolve();
    });
    mocks.consume.mockImplementationOnce(async (input: PlannerInput) => {
      expect(input.prompt).toContain('"targetCount": 2');
      expect(input.prompt).not.toContain("Test authorization");
      for (const target of targets)
        expect(input.prompt).not.toContain(target.target);
      throw new Error("Lead reached with a compact prompt");
    });

    await expect(run()).rejects.toThrow("Lead reached with a compact prompt");
    expect(mocks.startPlannedMissions).toHaveBeenCalledOnce();
    expect(getTarget).not.toHaveBeenCalled();
  });
});
