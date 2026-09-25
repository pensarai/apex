import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { ModelMessage } from "ai";
import { afterEach, describe, expect, it } from "vitest";
import type { SwarmTarget } from "../session/persistence";
import {
  AgentMailbox,
  buildEngagementState,
  DEFAULT_ENGAGEMENT_BASELINE_OBJECTIVE,
  EngagementStore,
  restoreEngagementState,
} from "./engagementState";

const directories: string[] = [];

function temporaryDirectory(): string {
  const directory = mkdtempSync(join(tmpdir(), "apex-engagement-"));
  directories.push(directory);
  return directory;
}

afterEach(() => {
  for (const directory of directories.splice(0)) {
    rmSync(directory, { recursive: true, force: true });
  }
});

const targets: SwarmTarget[] = [
  {
    target: "https://app.example.test/api/users/{id}",
    objectives: ["Test object authorization"],
  },
  {
    target: "https://app.example.test/login",
    objectives: ["Test session handling"],
  },
  {
    target: "https://admin.example.test/graphql",
    objectives: ["Test object authorization"],
  },
];

describe("buildEngagementState", () => {
  it("groups endpoints into services and maps objectives to relevant services", () => {
    const state = buildEngagementState("https://app.example.test", targets);
    expect(state.services).toHaveLength(2);
    expect(state.objectives).toHaveLength(2);
    const authorization = state.objectives.find((objective) =>
      objective.text.includes("authorization"),
    );
    expect(authorization?.relevantServiceIds).toHaveLength(2);
    expect(state.coverage).toHaveLength(3);
  });

  it("creates one coverage cell per target-local objective", () => {
    const state = buildEngagementState("https://app.example.test", [
      {
        target: "https://app.example.test/api/users/{id}",
        objectives: ["Test object authorization"],
      },
      {
        target: "https://app.example.test/api/projects/{id}",
        objectives: ["Test object authorization"],
      },
      {
        target: "https://app.example.test/health",
        objectives: [],
      },
    ]);

    expect(state.services).toHaveLength(1);
    expect(state.objectives).toHaveLength(2);
    expect(state.coverage).toHaveLength(3);
    expect(
      state.targets.find((target) => target.target.endsWith("/health"))
        ?.objectiveIds,
    ).toEqual([
      state.objectives.find(
        (objective) => objective.text === DEFAULT_ENGAGEMENT_BASELINE_OBJECTIVE,
      )?.id,
    ]);
  });
});

describe("EngagementStore", () => {
  it("requires objective coverage, service exploration, chain exploration, and resolved capabilities", () => {
    const directory = temporaryDirectory();
    const store = EngagementStore.open(
      directory,
      buildEngagementState("https://app.example.test", targets),
    );
    const state = store.snapshot();
    expect(store.completion().complete).toBe(false);

    for (const service of state.services) {
      store.markServiceBaseline(service.id, "explored", "Baseline explored");
    }
    for (const coverage of state.coverage) {
      store.markObjectiveCoverage({
        targetId: coverage.targetId,
        objectiveId: coverage.objectiveId,
        serviceId: coverage.serviceId,
        status: "exhausted",
        summary: "Bounded paths tested",
      });
    }
    const capability = store.upsertCapability({
      label: "Reusable session",
      description: "Session accepted by the admin service",
      status: "confirmed",
      serviceIds: [state.services[0]?.id as string],
      targetIds: [state.targets[0]?.id as string],
      objectiveIds: [],
      evidence: ["call-1"],
      nextSteps: ["Attempt admin pivot"],
    });
    expect(store.completion()).toMatchObject({
      complete: false,
      unresolvedCapabilityIds: [capability.id],
    });

    store.upsertCapability({ ...capability, status: "blocked", nextSteps: [] });
    store.setChainExplore("exhausted", "No chain reached crown jewels");
    expect(store.completion().complete).toBe(true);
  });

  it("persists impact proofs and fails loudly on corrupt state", () => {
    const directory = temporaryDirectory();
    const seed = buildEngagementState("https://app.example.test", targets);
    const store = EngagementStore.open(directory, seed);
    const proof = store.addImpactProof({
      description: "Protected record returned through IDOR",
      objectiveIds: [seed.objectives[0]?.id as string],
      serviceIds: [seed.services[0]?.id as string],
      targetIds: [seed.targets[0]?.id as string],
      findingIds: ["finding-1"],
      capabilityIds: [],
      artifactPaths: ["pocs/idor.ts"],
      observationRefs: ["http_request:call-1"],
    });
    expect(store.snapshot().impactProofs[0]?.id).toBe(proof.id);

    const statePath = join(directory, "coordination", "engagement.json");
    expect(readFileSync(statePath, "utf8")).toContain("finding-1");
    writeFileSync(statePath, "not-json", "utf8");
    expect(() => EngagementStore.open(directory, seed)).toThrow();
  });

  it("persists first-class chain records and preserves their finding relations", () => {
    const directory = temporaryDirectory();
    const seed = buildEngagementState("https://app.example.test", targets);
    const store = EngagementStore.open(directory, seed);
    const chain = store.upsertChain({
      title: "Session weakness to protected record access",
      status: "impact-proven",
      severity: "HIGH",
      description: "A reusable session reaches a protected record.",
      impact: "Cross-user data disclosure.",
      remediation: "Bind resource access to the authenticated principal.",
      findingIds: ["finding-1"],
      capabilityIds: [],
      impactProofIds: [],
      objectiveIds: [seed.objectives[0]?.id as string],
      serviceIds: [seed.services[0]?.id as string],
      targetIds: [seed.targets[0]?.id as string],
      evidence: ["finding-1"],
      steps: [
        {
          title: "Obtain reusable session",
          description: "Authenticate as the low-privilege actor.",
          findingIds: [],
          capabilityIds: [],
          evidence: ["session-cookie-observed"],
        },
        {
          title: "Retrieve protected record",
          description: "Use the session against a sibling record.",
          findingIds: ["finding-1"],
          capabilityIds: [],
          evidence: ["HTTP 200"],
        },
      ],
    });

    expect(
      EngagementStore.open(directory, seed).snapshot().chains,
    ).toMatchObject([{ id: chain.id, findingIds: ["finding-1"] }]);
    expect(store.checkpoint().chains).toMatchObject([
      { id: chain.id, status: "impact-proven" },
    ]);
  });

  it("persists actor metadata and only prunes evidence-backed unavailable work", () => {
    const directory = temporaryDirectory();
    const seed = buildEngagementState("https://app.example.test", targets);
    const store = EngagementStore.open(directory, seed);
    store.saveModels({
      lead: { model: "gpt-5.6-sol" },
      worker: { model: "glm-5.3" },
      judge: { model: "judge-model", openAIReasoningEffort: "high" },
    });
    const target = seed.targets[0]!;
    const objectiveId = target.objectiveIds[0]!;
    store.configureActors([
      {
        id: "actor-user",
        label: "Standard user",
        role: "standard-user",
        status: "ready",
        credentialIds: ["cred-user"],
        targetIds: [target.id],
        serviceIds: [target.serviceId],
        provenance: "operator",
        verificationSummary: "Operator supplied the credential reference.",
        verifiedAt: new Date().toISOString(),
      },
    ]);
    const artifact = {
      version: 1 as const,
      status: "sealed" as const,
      contractHash: "contract",
      targetIds: seed.targets.map((item) => item.id),
      capabilities: [
        {
          id: "feature-tts",
          kind: "feature" as const,
          label: "Text to speech",
          status: "unavailable" as const,
          targetIds: [target.id],
          evidence: ["TTS provider is disabled in deployment settings"],
          summary: "TTS is disabled",
          observedAt: new Date().toISOString(),
        },
      ],
    };
    store.applyDeploymentPreflight(artifact, [
      {
        requirementId: "requirement-tts",
        status: "blocked",
        unavailableCapabilityIds: ["feature-tts"],
        unknownCapabilityIds: [],
        evidence: ["deployment-preflight:feature-tts:TTS disabled"],
        coverage: [{ targetId: target.id, objectiveId }],
      },
    ]);

    expect(store.snapshot().coverage[0]).toMatchObject({
      status: "blocked",
      evidence: ["deployment-preflight:feature-tts:TTS disabled"],
    });
    expect(store.checkpoint()).toMatchObject({
      version: 4,
      actors: { status: "complete" },
      deploymentPreflight: { contractHash: "contract" },
      models: {
        lead: { model: "gpt-5.6-sol" },
        worker: { model: "glm-5.3" },
        judge: { model: "judge-model", openAIReasoningEffort: "high" },
      },
    });
  });

  it("requires evidence references for impact claims", () => {
    const directory = temporaryDirectory();
    const seed = buildEngagementState("https://app.example.test", targets);
    const store = EngagementStore.open(directory, seed);
    const coverage = seed.coverage[0];
    if (!coverage) throw new Error("Expected coverage");

    expect(() =>
      store.markObjectiveCoverage({
        targetId: coverage.targetId,
        objectiveId: coverage.objectiveId,
        serviceId: coverage.serviceId,
        status: "impact-proven",
        summary: "Claim without evidence",
      }),
    ).toThrow("requires evidence");
    expect(() =>
      store.setChainExplore("impact-proven", "Claim without evidence"),
    ).toThrow("requires evidence");
    expect(() =>
      store.addImpactProof({
        description: "Claim without evidence",
        objectiveIds: [],
        serviceIds: [],
        targetIds: [],
        findingIds: [],
        capabilityIds: [],
        artifactPaths: [],
        observationRefs: [],
      }),
    ).toThrow("require at least one evidence reference");
  });

  it("journals evidence observations and restores them across host restarts", () => {
    const directory = temporaryDirectory();
    const seed = buildEngagementState("https://app.example.test", targets);
    const store = EngagementStore.open(directory, seed);

    store.recordEvidenceObservation({
      toolCallId: "call-before-restart",
      toolName: "http_request",
      subagentId: "worker-1",
      failed: false,
    });

    expect(store.checkpoint().evidenceObservations).toEqual([
      expect.objectContaining({ toolCallId: "call-before-restart" }),
    ]);
    expect(
      EngagementStore.open(directory, seed).snapshot().evidenceObservations,
    ).toEqual([
      expect.objectContaining({
        toolCallId: "call-before-restart",
        subagentId: "worker-1",
      }),
    ]);
  });

  it("validates coverage settlement batches before mutating any cell", () => {
    const directory = temporaryDirectory();
    const seed = buildEngagementState("https://app.example.test", targets);
    const store = EngagementStore.open(directory, seed);
    const cells = seed.coverage.slice(0, 2);
    const [first, second] = cells;
    if (!first || !second) throw new Error("Expected two coverage cells");
    store.claimCoverageCells({
      workerId: "worker-1",
      cells: cells.map(({ targetId, objectiveId }) => ({
        targetId,
        objectiveId,
      })),
    });

    expect(() =>
      store.settleCoverageCells([
        {
          ...first,
          workerId: "worker-1",
          status: "exhausted",
          summary: "Tested",
        },
        {
          ...second,
          workerId: "another-worker",
          status: "blocked",
          summary: "Blocked",
        },
      ]),
    ).toThrow("no longer owns coverage");
    expect(
      store
        .snapshot()
        .coverage.filter((cell) =>
          cells.some(
            (claimed) =>
              claimed.targetId === cell.targetId &&
              claimed.objectiveId === cell.objectiveId,
          ),
        ),
    ).toEqual([
      expect.objectContaining({ status: "running", workerId: "worker-1" }),
      expect.objectContaining({ status: "running", workerId: "worker-1" }),
    ]);
  });

  it("validates mission requirement batches before mutating any association", () => {
    const directory = temporaryDirectory();
    const seed = buildEngagementState("https://app.example.test", targets);
    const store = EngagementStore.open(directory, seed);
    const [first, second] = seed.coverage;
    if (!first || !second) throw new Error("Expected two coverage cells");
    store.claimCoverageCells({
      workerId: "worker-1",
      cells: [first, second].map(({ targetId, objectiveId }) => ({
        targetId,
        objectiveId,
      })),
    });

    expect(() =>
      store.settleMissionRequirements([
        {
          workerId: "worker-1",
          coverage: [first],
          status: "exhausted",
          summary: "Tested",
          evidence: [],
        },
        {
          workerId: "another-worker",
          coverage: [second],
          status: "blocked",
          summary: "Blocked",
          evidence: [],
        },
      ]),
    ).toThrow("no longer owns running coverage");
    expect(
      store
        .snapshot()
        .coverage.filter((cell) =>
          [first, second].some(
            (claimed) =>
              claimed.targetId === cell.targetId &&
              claimed.objectiveId === cell.objectiveId,
          ),
        ),
    ).toEqual([
      expect.objectContaining({ status: "running", workerId: "worker-1" }),
      expect.objectContaining({ status: "running", workerId: "worker-1" }),
    ]);
  });

  it("keeps chain exploration provisional until every mission is terminal", () => {
    const directory = temporaryDirectory();
    const seed = buildEngagementState("https://app.example.test", targets);
    const store = EngagementStore.open(directory, seed);
    for (const service of seed.services) {
      store.markServiceBaseline(service.id, "explored", "Baseline explored");
    }
    for (const coverage of seed.coverage) {
      store.markObjectiveCoverage({
        targetId: coverage.targetId,
        objectiveId: coverage.objectiveId,
        serviceId: coverage.serviceId,
        status: "exhausted",
        summary: "Bounded paths tested",
      });
    }
    store.saveMissions({
      planningStatus: "complete",
      missions: [
        {
          id: "mission-running",
          workerId: "worker-running",
          purpose: "Finish the remaining flow",
          rationale: "Coverage is recorded before worker finalization",
          coverage: [],
          supportingTargetIds: [],
          prerequisiteMissionIds: [],
          contextTargetIds: [],
          status: "running",
          createdAt: new Date().toISOString(),
        },
      ],
    });

    expect(() =>
      store.setChainExplore("impact-proven", "Impact path proven", ["chain-1"]),
    ).toThrow("missions and workers are terminal");

    store.setMissionStatus("mission-running", "completed");
    store.registerWorker({
      id: "worker-chain",
      mission: "Validate the impact path",
      mode: "chain",
      serviceIds: seed.services.map((service) => service.id),
      targetIds: seed.targets.map((target) => target.id),
      objectiveIds: seed.objectives.map((objective) => objective.id),
      capabilityIds: [],
    });
    store.startWorker("worker-chain");
    expect(() =>
      store.setChainExplore("impact-proven", "Impact path proven", ["chain-1"]),
    ).toThrow("missions and workers are terminal");

    store.completeWorker("worker-chain", "completed", "Impact validated");
    expect(
      store.setChainExplore("impact-proven", "Impact path proven", ["chain-1"]),
    ).toMatchObject({ status: "impact-proven" });
  });

  it("reopens coverage owned by workers interrupted across host restarts", () => {
    const directory = temporaryDirectory();
    const seed = buildEngagementState("https://app.example.test", targets);
    const store = EngagementStore.open(directory, seed);
    const serviceId = seed.services[0]?.id as string;
    const objectiveId = seed.objectives[0]?.id as string;
    store.registerWorker({
      id: "worker-objective",
      mission: "Test authorization",
      mode: "fast-strike",
      serviceIds: [serviceId],
      targetIds: [seed.targets[0]?.id as string],
      objectiveIds: [objectiveId],
      capabilityIds: [],
    });
    store.startWorker("worker-objective");
    store.markObjectiveCoverage({
      targetId: seed.targets[0]?.id as string,
      objectiveId,
      serviceId,
      status: "running",
      workerId: "worker-objective",
      summary: "Testing",
    });
    store.registerWorker({
      id: "worker-explore",
      mission: "Explore service",
      mode: "explore",
      serviceIds: [serviceId],
      targetIds: [seed.targets[0]?.id as string],
      objectiveIds: [],
      capabilityIds: [],
    });
    store.startWorker("worker-explore");
    store.markServiceBaseline(serviceId, "running", "Exploring");

    expect(store.reconcileInterruptedWorkers()).toEqual([
      "worker-objective",
      "worker-explore",
    ]);
    expect(store.snapshot()).toMatchObject({
      services: expect.arrayContaining([
        expect.objectContaining({ id: serviceId, baselineStatus: "pending" }),
      ]),
      coverage: expect.arrayContaining([
        expect.objectContaining({
          objectiveId,
          serviceId,
          status: "pending",
        }),
      ]),
      workers: expect.arrayContaining([
        expect.objectContaining({ id: "worker-objective", status: "failed" }),
        expect.objectContaining({ id: "worker-explore", status: "failed" }),
      ]),
    });

    expect(store.restartWorker("worker-objective")).toMatchObject({
      id: "worker-objective",
      status: "running",
      completedAt: undefined,
    });
  });
});

describe("restoreEngagementState", () => {
  it("restores a compact checkpoint from a Console text tool result", () => {
    const directory = temporaryDirectory();
    const original = buildEngagementState("https://app.example.test", targets);
    const store = EngagementStore.open(directory, original);
    const serviceId = original.services[0]?.id as string;
    store.markServiceBaseline(serviceId, "explored", "Baseline complete");
    const checkpoint = store.checkpoint();
    const messages: ModelMessage[] = [
      {
        role: "tool",
        content: [
          {
            type: "tool-result",
            toolCallId: "call-1",
            toolName: "update_engagement_coverage",
            output: {
              type: "text",
              value: JSON.stringify({ checkpoint, success: true }),
            },
          },
        ],
      },
    ];
    const resumedSeed = buildEngagementState(
      "https://new-host.example.test",
      targets,
    );

    const restored = restoreEngagementState(resumedSeed, messages);

    expect(restored.rootTarget).toBe("https://new-host.example.test");
    expect(
      restored.services.find((service) => service.id === serviceId),
    ).toMatchObject({
      baselineStatus: "explored",
      summary: "Baseline complete",
    });
  });

  it("migrates version-one service coverage by reopening target-local cells", () => {
    const original = buildEngagementState("https://app.example.test", targets);
    const checkpoint = EngagementStore.open(
      temporaryDirectory(),
      original,
    ).checkpoint();
    const legacyCheckpoint = {
      ...checkpoint,
      version: 1,
      objectives: undefined,
      coverage: checkpoint.coverage.map(
        ({ targetId: _targetId, attempts: _attempts, ...coverage }) => ({
          ...coverage,
          status: "exhausted" as const,
        }),
      ),
      capabilities: checkpoint.capabilities.map(
        ({ targetIds: _targetIds, ...capability }) => capability,
      ),
      impactProofs: checkpoint.impactProofs.map(
        ({ targetIds: _targetIds, ...proof }) => proof,
      ),
      workers: checkpoint.workers.map(
        ({ targetIds: _targetIds, capabilityIds: _capabilityIds, ...worker }) =>
          worker,
      ),
    };
    const messages = [
      {
        role: "tool",
        content: [
          {
            type: "tool-result",
            toolCallId: "call-legacy",
            toolName: "update_engagement_coverage",
            output: {
              type: "text",
              value: JSON.stringify({ checkpoint: legacyCheckpoint }),
            },
          },
        ],
      },
    ] as ModelMessage[];

    const restored = restoreEngagementState(original, messages);

    expect(restored.version).toBe(4);
    expect(restored.coverage).toHaveLength(original.coverage.length);
    expect(restored.coverage).toEqual(
      expect.arrayContaining(
        original.coverage.map((coverage) =>
          expect.objectContaining({
            targetId: coverage.targetId,
            objectiveId: coverage.objectiveId,
            attempts: 0,
            status: "pending",
          }),
        ),
      ),
    );
  });
});

describe("AgentMailbox", () => {
  it("delivers directed MESSAGE and FINAL_ANSWER records once", () => {
    const mailbox = new AgentMailbox(temporaryDirectory());
    mailbox.send({
      type: "MESSAGE",
      recipientAgentId: "worker-1",
      senderAgentId: "engagement-lead",
      taskName: "follow-up",
      payload: "Test the confirmed pivot",
    });
    mailbox.send({
      type: "FINAL_ANSWER",
      recipientAgentId: "engagement-lead",
      senderAgentId: "worker-1",
      taskName: "initial",
      payload: "Pivot confirmed",
      status: "completed",
    });

    expect(mailbox.take("worker-1").map((message) => message.type)).toEqual([
      "MESSAGE",
    ]);
    expect(mailbox.take("worker-1")).toEqual([]);
    expect(mailbox.take("engagement-lead")[0]?.type).toBe("FINAL_ANSWER");
  });
});
