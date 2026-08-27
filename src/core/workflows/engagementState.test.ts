import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { ModelMessage } from "ai";
import { afterEach, describe, expect, it } from "vitest";
import type { SwarmTarget } from "../session/persistence";
import {
  AgentMailbox,
  buildEngagementState,
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
    for (const objective of state.objectives) {
      store.markObjectiveCoverage({
        objectiveId: objective.id,
        serviceId: objective.relevantServiceIds[0] as string,
        status: "exhausted",
        summary: "Bounded paths tested",
      });
    }
    const capability = store.upsertCapability({
      label: "Reusable session",
      description: "Session accepted by the admin service",
      status: "confirmed",
      serviceIds: [state.services[0]?.id as string],
      objectiveIds: [],
      evidence: ["call-1"],
      nextSteps: ["Attempt admin pivot"],
    });
    store.setChainExplore("exhausted", "No chain reached crown jewels");
    expect(store.completion()).toMatchObject({
      complete: false,
      unresolvedCapabilityIds: [capability.id],
    });

    store.upsertCapability({ ...capability, status: "blocked", nextSteps: [] });
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
      objectiveIds: [objectiveId],
    });
    store.markObjectiveCoverage({
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
      objectiveIds: [],
    });
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
