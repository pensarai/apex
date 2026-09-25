import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";

const constructorCalls: Array<Record<string, unknown>> = [];
const fastStrikeCalls: Array<Record<string, unknown>> = [];
const groupedCalls: Array<Record<string, unknown>> = [];
let groupedFailureAfterReport: unknown;
let groupedFailureBeforeReport: unknown;

vi.mock("../agents/offSecAgent", () => ({
  OffensiveSecurityAgent: class {
    constructor(private readonly input: Record<string, unknown>) {
      groupedCalls.push(input);
    }
    async consume() {
      const prompt = this.input.prompt as string;
      const extraTools = this.input.extraTools as Record<
        string,
        {
          execute: (
            input: Record<string, unknown>,
            context: { toolCallId: string; messages: never[] },
          ) => Promise<unknown>;
        }
      >;
      const canonical = prompt.includes("Canonical mission requirements:");
      const serialized = prompt
        .split(
          canonical
            ? "Canonical mission requirements:\n\n"
            : "Legacy coverage contract:\n\n",
        )[1]
        ?.split("\n\nAuthorized target")[0];
      const contract = JSON.parse(serialized ?? "[]") as Array<
        | { targetId: string; objectiveId: string }
        | {
            id: string;
            coverage: Array<{ targetId: string; objectiveId: string }>;
          }
      >;
      const report = canonical
        ? extraTools.report_engagement_mission_progress
        : extraTools.report_engagement_coverage;
      if (groupedFailureBeforeReport) throw groupedFailureBeforeReport;
      await report?.execute(
        canonical
          ? {
              requirementResults: contract.map((requirement) => ({
                requirementId: "id" in requirement ? requirement.id : "missing",
                status: "exhausted",
                summary: "Bounded flow checks completed",
                evidence: [],
              })),
              toolCallDescription: "record canonical mission progress",
            }
          : {
              obligationResults: contract.map((cell) => ({
                ...cell,
                status: "exhausted",
                summary: "Bounded flow checks completed",
                evidence: [],
              })),
              toolCallDescription: "record completed grouped coverage",
            },
        { toolCallId: "report-1", messages: [] },
      );
      if (groupedFailureAfterReport) throw groupedFailureAfterReport;
      return {
        summary: "Related flow tested",
      };
    }
  },
}));

vi.mock("../agents/specialized/pentest/agent", () => ({
  TargetedPentestAgent: class {
    constructor(input: Record<string, unknown>) {
      constructorCalls.push(input);
    }
    async consume() {
      return {
        findings: [],
        objectiveResults: [
          {
            objective: "Test authorization",
            completed: true,
            result: "No bypass after bounded testing",
          },
        ],
      };
    }
  },
}));

vi.mock("./fastStrike", () => ({
  runFastStrikeObjective: async (input: Record<string, unknown>) => {
    fastStrikeCalls.push(input);
    const messages = [
      ...((input.messages as Array<Record<string, unknown>> | undefined) ?? [
        {
          role: "user",
          content: [{ type: "text", text: "Initial fast-strike mission" }],
        },
      ]),
      {
        role: "assistant",
        content: [{ type: "text", text: "Bounded paths tested" }],
      },
    ];
    const onStepFinish = input.onStepFinish as
      | ((event: { response: { messages: unknown[] } }) => void)
      | undefined;
    onStepFinish?.({ response: { messages } });
    return {
      status: "exhausted",
      summary: "Bounded paths tested",
      evidence: [],
      findings: [],
    };
  },
}));

import type { Finding } from "../agents/offSecAgent";
import type { AIModel } from "../ai";
import { AgentEventBus } from "../eventBus";
import type { FindingsRegistry } from "../findings/registry";
import type { SessionInfo } from "../session";
import type {
  EngagementMissionCoverage,
  EngagementMissionRequirement,
} from "./engagementMissions";
import { buildEngagementState, EngagementStore } from "./engagementState";
import {
  createEngagementTools,
  formatEngagementError,
} from "./engagementTools";

const directories: string[] = [];

afterEach(() => {
  constructorCalls.length = 0;
  fastStrikeCalls.length = 0;
  groupedCalls.length = 0;
  groupedFailureAfterReport = undefined;
  groupedFailureBeforeReport = undefined;
  for (const directory of directories.splice(0)) {
    rmSync(directory, { recursive: true, force: true });
  }
});

function makeRuntime(grouped = false, findings: Finding[] = []) {
  const rootPath = mkdtempSync(join(tmpdir(), "apex-engagement-tools-"));
  directories.push(rootPath);
  const session = {
    id: "session-test",
    rootPath,
    findingsPath: join(rootPath, "findings"),
    pocsPath: join(rootPath, "pocs"),
    config: grouped ? { engagementCoverageMode: "grouped" } : {},
  } as unknown as SessionInfo;
  const seed = buildEngagementState("https://example.test", [
    {
      target: "https://example.test/api/users/{id}",
      objectives: ["Test authorization"],
    },
    ...(grouped
      ? [
          {
            target: "https://example.test/api/users/{id}/mfa",
            objectives: ["Test authorization"],
          },
        ]
      : []),
  ]);
  const store = EngagementStore.open(rootPath, seed);
  const findingsRegistry = {
    getFindings: () => findings,
    getCanonicalFindings: () => findings,
    resolveFindingId: (id: string) => id,
    applyConsolidation: () => undefined,
  } as unknown as FindingsRegistry;
  const runtime = createEngagementTools({
    input: {
      target: "https://example.test",
      model: "test-model" as AIModel,
      session,
    },
    store,
    findingsRegistry,
    eventBus: new AgentEventBus(),
    leadAgentId: "engagement-lead",
    workerModel: grouped
      ? { model: "worker-model" as AIModel, enableThinking: false }
      : undefined,
    engagementTargetIds: ["target-1"],
    surfaceTools: {
      search_engagement_surface: { execute: vi.fn() } as never,
    },
  });
  return {
    tools: runtime.tools,
    startPlannedMissions: runtime.startPlannedMissions,
    planMissions: (
      definitions: Array<{
        purpose: string;
        rationale: string;
        singletonJustification?: string;
        coverage?: EngagementMissionCoverage[];
        requirements?: EngagementMissionRequirement[];
        supportingTargetIds?: string[];
        prerequisiteMissionIds?: string[];
        contextTargetIds?: string[];
      }>,
    ) => {
      store.saveMissions({ planningStatus: "pending", missions: [] });
      store.recordInspectedTargets(seed.targets.map((target) => target.id));
      definitions.forEach((definition, index) => {
        const coverage =
          definition.requirements?.flatMap(
            (requirement) => requirement.coverage,
          ) ??
          definition.coverage ??
          [];
        store.defineMission({
          id: `mission-${index + 1}`,
          workerId: `worker-${index + 1}`,
          purpose: definition.purpose,
          rationale: definition.rationale,
          singletonJustification: definition.singletonJustification,
          coverage,
          requirements: definition.requirements,
          supportingTargetIds: definition.supportingTargetIds ?? [],
          prerequisiteMissionIds: definition.prerequisiteMissionIds ?? [],
          contextTargetIds: definition.contextTargetIds ?? [],
          status: "planned",
          createdAt: new Date().toISOString(),
        });
      });
      return store.setMissionPlanningComplete();
    },
    store,
    seed,
  };
}

async function executeTool(
  value: unknown,
  input: Record<string, unknown>,
): Promise<Record<string, unknown>> {
  const executable = value as {
    execute: (
      input: Record<string, unknown>,
      context: { toolCallId: string; messages: never[] },
    ) => Promise<Record<string, unknown>>;
  };
  return executable.execute(input, { toolCallId: "call-1", messages: [] });
}

async function waitForWorker(tools: Record<string, unknown>, workerId: string) {
  await executeTool(tools.wait_for_engagement_workers, {
    workerIds: [workerId],
    timeoutMs: 100,
    toolCallDescription: "wait for resumed worker",
  });
}

describe("engagement worker tools", () => {
  it("preserves structured worker errors without object coercion", () => {
    expect(
      formatEngagementError({
        code: "stream_terminated",
        message: "Stream terminated unexpectedly",
      }),
    ).toBe(
      '{"code":"stream_terminated","message":"Stream terminated unexpectedly"}',
    );
  });

  it("pages the coordination state while preserving objective coverage", async () => {
    const { tools, seed } = makeRuntime();
    const result = await executeTool(tools.read_engagement_state, {
      includeInbox: false,
      limit: 1,
      offset: 0,
      toolCallDescription: "read the first coordination page",
    });

    expect(result.pagination).toEqual({
      offset: 0,
      limit: 1,
      serviceTotal: 1,
      objectiveTotal: 1,
      workerTotal: 0,
      findingTotal: 0,
      chainTotal: 0,
    });
    expect(result.state).toMatchObject({
      services: seed.services,
      objectives: seed.objectives,
      coverage: seed.coverage,
      workerCounts: { running: 0, completed: 0, failed: 0 },
    });
    expect(result.state).not.toHaveProperty("targets");
    expect(result.state).not.toHaveProperty("workers");
    expect(result.inbox).toEqual([]);
  });

  it("records a durable chain linked to accepted findings", async () => {
    const finding: Finding = {
      id: "finding-1",
      title: "Cross-user file disclosure",
      severity: "HIGH",
      description: "A user can read another user's file.",
      impact: "Non-public file disclosure.",
      evidence: "HTTP 200 with the victim file.",
      endpoint: "/api/v1/files/{id}",
      pocPath: "pocs/file.sh",
      remediation: "Enforce ownership.",
    };
    const { tools, store, seed } = makeRuntime(false, [finding]);
    const result = await executeTool(tools.record_engagement_chain, {
      title: "Low-privilege user reaches another user's files",
      status: "impact-proven",
      severity: "HIGH",
      description:
        "An authenticated user enumerates and retrieves a peer file.",
      impact: "Cross-tenant data disclosure.",
      remediation: "Enforce object ownership on file reads.",
      findingIds: ["finding-1"],
      capabilityIds: [],
      impactProofIds: [],
      objectiveIds: [seed.objectives[0]?.id],
      serviceIds: [seed.services[0]?.id],
      targetIds: [seed.targets[0]?.id],
      evidence: ["finding-1"],
      steps: [
        {
          title: "Authenticate as the low-privilege actor",
          description: "Establish the source-user session.",
          findingIds: [],
          capabilityIds: [],
          evidence: ["authenticated-session"],
        },
        {
          title: "Read peer file",
          description: "Request a file ID owned by another user.",
          findingIds: ["finding-1"],
          capabilityIds: [],
          evidence: ["HTTP 200"],
        },
      ],
      toolCallDescription: "record the proven file-access chain",
    });

    expect(result.success).toBe(true);
    expect(store.snapshot().chains).toMatchObject([
      {
        title: "Low-privilege user reaches another user's files",
        status: "impact-proven",
        findingIds: ["finding-1"],
      },
    ]);
    expect(result).not.toHaveProperty("chain.toolCallDescription");
  });

  it("rejects chain relations to unknown findings", async () => {
    const { tools } = makeRuntime();
    await expect(
      executeTool(tools.record_engagement_chain, {
        title: "Unknown finding chain",
        status: "exhausted",
        description: "A test relation.",
        impact: "No impact reached.",
        findingIds: ["missing-finding"],
        steps: [],
        toolCallDescription: "record chain",
      }),
    ).rejects.toThrow("unknown findings");
  });

  it("requires a dedicated chain for every canonical finding before closing chain exploration", async () => {
    const findings: Finding[] = [
      {
        id: "finding-1",
        title: "Session survives logout",
        severity: "HIGH",
        description: "A stolen token remains valid after logout.",
        impact: "Persistent account access.",
        evidence: "The old token returned HTTP 200.",
        endpoint: "/api/v1/auths/signout",
        pocPath: "pocs/logout.sh",
        remediation: "Revoke sessions server-side.",
      },
      {
        id: "finding-2",
        title: "Weak passwords accepted",
        severity: "MEDIUM",
        description: "Accounts accept empty passwords.",
        impact: "Guessable account credentials.",
        evidence: "Empty-password signin returned HTTP 200.",
        endpoint: "/api/v1/auths/signin",
        pocPath: "pocs/password.sh",
        remediation: "Enforce password strength.",
      },
    ];
    const { tools, store, seed } = makeRuntime(false, findings);
    for (const service of seed.services) {
      store.markServiceBaseline(service.id, "explored", "Baseline complete");
    }
    for (const cell of seed.coverage) {
      store.markObjectiveCoverage({
        ...cell,
        status: "exhausted",
        summary: "Testing complete",
      });
    }
    const proof = store.addImpactProof({
      description: "The signed-out token still reads the account",
      objectiveIds: [],
      serviceIds: [],
      targetIds: [],
      findingIds: ["finding-1"],
      capabilityIds: [],
      artifactPaths: [],
      observationRefs: [],
    });

    await executeTool(tools.record_engagement_chain, {
      title: "Weak password to persistent session",
      status: "blocked",
      description: "Combines both accepted findings.",
      impact: "Persistent access if a victim uses a weak password.",
      findingIds: ["finding-1", "finding-2"],
      capabilityIds: [],
      impactProofIds: [],
      objectiveIds: [],
      serviceIds: [],
      targetIds: [],
      evidence: ["finding-1", "finding-2"],
      steps: [
        {
          title: "Use both primitives",
          description: "Attempt the composite path.",
          findingIds: ["finding-1", "finding-2"],
          evidence: ["finding-1", "finding-2"],
        },
      ],
      blocker: "No weak-password victim account exists.",
      toolCallDescription: "record composite chain",
    });

    await expect(
      executeTool(tools.update_engagement_coverage, {
        kind: "chain",
        chainStatus: "exhausted",
        summary: "Chain exploration complete",
        evidence: [],
        toolCallDescription: "close chain exploration",
      }),
    ).rejects.toThrow(
      "Canonical findings without a dedicated attacker-path chain: finding-1, finding-2",
    );
    await expect(
      executeTool(tools.update_engagement_coverage, {
        kind: "chain",
        chainStatus: "exhausted",
        summary: "Chain exploration complete",
        evidence: [],
        toolCallDescription: "close chain exploration",
      }),
    ).rejects.toThrow("Impact proofs not represented in a chain");

    for (const finding of findings) {
      const impactProofIds = finding.id === "finding-1" ? [proof.id] : [];
      await executeTool(tools.record_engagement_chain, {
        title: `${finding.title} attacker path`,
        status: "impact-proven",
        severity: finding.severity,
        description: finding.description,
        impact: finding.impact,
        findingIds: [finding.id],
        capabilityIds: [],
        impactProofIds,
        objectiveIds: [],
        serviceIds: [],
        targetIds: [],
        evidence: [finding.id],
        steps: [
          {
            title: "Meet the prerequisite",
            description: "Establish the attacker position.",
            findingIds: [finding.id],
            impactProofIds,
            evidence: [finding.id],
          },
          {
            title: "Exercise the finding",
            description: finding.impact,
            findingIds: [finding.id],
            evidence: [finding.id],
          },
        ],
        toolCallDescription: "record dedicated finding chain",
      });
    }

    const closed = await executeTool(tools.update_engagement_coverage, {
      kind: "chain",
      chainStatus: "impact-proven",
      summary: "Every accepted finding has an attacker path",
      evidence: ["finding-1", "finding-2"],
      toolCallDescription: "close chain exploration",
    });
    expect(closed.success).toBe(true);
    expect(store.snapshot().chains).toHaveLength(3);
  });

  it("persists objective coverage and resumes the same worker thread", async () => {
    const { tools, store, seed } = makeRuntime();
    const serviceId = seed.services[0]?.id as string;
    const objectiveId = seed.objectives[0]?.id as string;
    const spawned = await executeTool(tools.spawn_engagement_worker, {
      mission: "Test the object authorization boundary",
      serviceIds: [serviceId],
      targetIds: [seed.targets[0]?.id as string],
      objectiveIds: [objectiveId],
      capabilityIds: [],
      mode: "targeted",
      toolCallDescription: "spawn authorization worker",
    });

    expect(spawned.success).toBe(true);
    expect(store.snapshot().coverage[0]?.status).toBe("exhausted");
    const workerId = spawned.workerId as string;

    const followedUp = await executeTool(tools.follow_up_engagement_worker, {
      workerId,
      message: "Recheck using the sibling account discovered by the lead.",
      toolCallDescription: "resume authorization worker",
    });
    expect(followedUp.success).toBe(true);
    expect(followedUp.accepted).toBe(true);
    await waitForWorker(tools, workerId);
    expect(constructorCalls).toHaveLength(2);
    expect(constructorCalls[0]).toMatchObject({
      toolProtocol: undefined,
      engagementTargetIds: ["target-1"],
    });
    const resumedMessages = constructorCalls[1]?.messages as Array<{
      role: string;
      content: Array<{ type: string; text: string }>;
    }>;
    expect(resumedMessages.at(-1)?.content[0]?.text).toContain(
      "sibling account",
    );
    expect(
      store.snapshot().workers.filter((worker) => worker.id === workerId),
    ).toHaveLength(1);
  });

  it("passes the preserved conversation into fast-strike follow-ups", async () => {
    const { tools, store, seed } = makeRuntime();
    const serviceId = seed.services[0]?.id as string;
    const objectiveId = seed.objectives[0]?.id as string;
    const spawned = await executeTool(tools.spawn_engagement_worker, {
      mission: "Prove the concrete authorization impact",
      serviceIds: [serviceId],
      targetIds: [seed.targets[0]?.id as string],
      objectiveIds: [objectiveId],
      capabilityIds: [],
      mode: "fast-strike",
      toolCallDescription: "spawn impact worker",
    });
    const workerId = spawned.workerId as string;

    await executeTool(tools.follow_up_engagement_worker, {
      workerId,
      message: "Reuse the first attempt and try the sibling account.",
      toolCallDescription: "resume impact worker",
    });
    await waitForWorker(tools, workerId);

    expect(fastStrikeCalls).toHaveLength(2);
    const resumedMessages = fastStrikeCalls[1]?.messages as Array<{
      role: string;
      content: Array<{ type: string; text: string }>;
    }>;
    expect(
      resumedMessages.some((message) =>
        message.content.some((part) => part.text === "Bounded paths tested"),
      ),
    ).toBe(true);
    expect(resumedMessages.at(-1)?.content[0]?.text).toContain(
      "sibling account",
    );
    expect(store.snapshot().workers).toMatchObject([
      { id: workerId, status: "completed" },
    ]);
  });

  it("runs one model-planned grouped mission with exact per-target results", async () => {
    const { planMissions, startPlannedMissions, store, seed } =
      makeRuntime(true);
    const coverage = seed.coverage.map(({ targetId, objectiveId }) => ({
      targetId,
      objectiveId,
    }));
    planMissions([
      {
        purpose: "Test the user authorization and MFA flow",
        rationale: "The endpoints share authentication and user state",
        coverage,
        contextTargetIds: seed.targets.map((target) => target.id),
      },
    ]);
    await startPlannedMissions();

    expect(groupedCalls[0]).toMatchObject({
      model: "worker-model",
      enableThinking: false,
    });
    expect(store.snapshot().coverage).toHaveLength(2);
    expect(
      store.snapshot().coverage.every((cell) => cell.status === "exhausted"),
    ).toBe(true);
    expect(store.snapshot().missions).toMatchObject({
      planningStatus: "complete",
      missions: [{ status: "completed", coverage }],
    });
  });

  it("reports one canonical requirement while preserving its source coverage", async () => {
    const { planMissions, startPlannedMissions, store, seed } =
      makeRuntime(true);
    for (const target of seed.targets) {
      store.recordContextRead(target.id, {
        status: "read",
        version: `version-${target.id}`,
        complete: true,
        hasProductContext: true,
      });
    }
    const coverage = seed.coverage.map(({ targetId, objectiveId }) => ({
      targetId,
      objectiveId,
    }));
    planMissions([
      {
        purpose: "Review the shared user authorization boundary",
        rationale: "Both endpoints share documented ownership semantics",
        requirements: [
          {
            id: "user-owner-boundary",
            description:
              "User resources enforce their documented owner boundary",
            rationale:
              "Same identity, resource, and expected authorization behavior",
            coverage,
          },
        ],
        contextTargetIds: seed.targets.map((target) => target.id),
      },
    ]);
    await startPlannedMissions();

    expect(groupedCalls[0]?.extraTools).toHaveProperty(
      "report_engagement_mission_progress",
    );
    expect(store.snapshot().coverage).toHaveLength(2);
    expect(
      store.snapshot().coverage.every((cell) => cell.status === "exhausted"),
    ).toBe(true);
    expect(store.snapshot().missions?.missions[0]?.requirements).toMatchObject([
      { id: "user-owner-boundary", coverage },
    ]);
  });

  it("preserves reported coverage when the final worker stream fails", async () => {
    groupedFailureAfterReport = {
      code: "stream_terminated",
      message: "Stream terminated unexpectedly",
    };
    const { planMissions, startPlannedMissions, store, seed } =
      makeRuntime(true);
    planMissions([
      {
        purpose: "Test the related authentication flow",
        rationale: "The endpoints share authentication state",
        coverage: seed.coverage.map(({ targetId, objectiveId }) => ({
          targetId,
          objectiveId,
        })),
      },
    ]);

    await startPlannedMissions();

    expect(
      store.snapshot().coverage.every((cell) => cell.status === "exhausted"),
    ).toBe(true);
    expect(store.snapshot().missions?.missions[0]?.status).toBe("completed");
    expect(store.snapshot().workers[0]?.summary).toContain(
      '"code":"stream_terminated"',
    );
  });

  it("reclaims needs-lead coverage when a failed grouped worker resumes", async () => {
    groupedFailureBeforeReport = {
      code: "provider_unavailable",
      message: "Provider connection interrupted",
    };
    const { tools, planMissions, startPlannedMissions, store, seed } =
      makeRuntime(true);
    const coverage = seed.coverage.map(({ targetId, objectiveId }) => ({
      targetId,
      objectiveId,
    }));
    planMissions([
      {
        purpose: "Test the related authentication flow",
        rationale: "The endpoints share authentication state",
        coverage,
      },
    ]);

    await startPlannedMissions();

    expect(
      store.snapshot().coverage.every((cell) => cell.status === "needs-lead"),
    ).toBe(true);
    expect(store.snapshot().missions?.missions[0]?.status).toBe("failed");

    groupedFailureBeforeReport = undefined;
    await executeTool(tools.follow_up_engagement_worker, {
      workerId: "worker-1",
      message: "Resume the interrupted mission and finish its requirements.",
      toolCallDescription: "resume failed grouped worker",
    });
    await waitForWorker(tools, "worker-1");

    expect(
      store.snapshot().coverage.every((cell) => cell.status === "exhausted"),
    ).toBe(true);
    expect(store.snapshot().missions?.missions[0]?.status).toBe("completed");
  });

  it("refuses to seal a grouped plan that omits coverage", async () => {
    const { planMissions, seed } = makeRuntime(true);
    expect(() =>
      planMissions([
        {
          purpose: "Test only one part of the flow",
          rationale: "Initial bounded mission",
          singletonJustification:
            "This test intentionally exercises one target",
          coverage: [
            {
              targetId: seed.targets[0]?.id as string,
              objectiveId: seed.objectives[0]?.id as string,
            },
          ],
        },
      ]),
    ).toThrow("omits 1 required coverage obligation");
  });
});
