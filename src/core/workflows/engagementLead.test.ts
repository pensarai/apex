import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { ToolSet } from "ai";
import { afterEach, describe, expect, it, vi } from "vitest";
import type { AgentEventBus } from "../eventBus";
import type { FindingsRegistry } from "../findings/registry";
import type { SessionInfo } from "../session";

const fake = vi.hoisted(() => ({
  consume: undefined as
    | undefined
    | ((input: Record<string, unknown>) => Promise<unknown>),
  construct: undefined as
    | undefined
    | ((input: Record<string, unknown>) => void),
}));

vi.mock("../agents/offSecAgent", () => ({
  OffensiveSecurityAgent: class {
    constructor(private readonly input: Record<string, unknown>) {
      fake.construct?.(input);
    }
    consume(): Promise<unknown> {
      if (!fake.consume) throw new Error("No fake engagement agent");
      return fake.consume(this.input);
    }
  },
}));

import { EngagementJournal } from "./engagementJournal";
import { runEngagementLead } from "./engagementLead";
import {
  ENGAGEMENT_PLAN_PATH,
  type EngagementTarget,
  engagementManifestHash,
  sealEngagementPlan,
  writeJsonAtomic,
} from "./engagementPlan";
import { createEngagementState } from "./engagementState";

const roots: string[] = [];
afterEach(() => {
  fake.consume = undefined;
  fake.construct = undefined;
  for (const root of roots.splice(0))
    rmSync(root, { recursive: true, force: true });
});

const candidates: EngagementTarget[] = [
  {
    id: "a",
    target: "https://a.example/api",
    objectives: [{ id: "auth", text: "Test auth" }],
  },
  {
    id: "b",
    target: "https://b.example/api",
    objectives: [{ id: "upload", text: "Test upload" }],
  },
];

function setup() {
  const rootPath = mkdtempSync(join(tmpdir(), "engagement-lead-"));
  roots.push(rootPath);
  const session = {
    id: "engagement-test",
    rootPath,
    findingsPath: join(rootPath, "findings"),
    pocsPath: join(rootPath, "pocs"),
    logsPath: join(rootPath, "logs"),
    scratchpadPath: join(rootPath, "scratchpad"),
    targets: ["https://a.example", "https://b.example"],
  } as SessionInfo;
  const workflow = {
    target: "https://a.example",
    model: "test" as never,
    session,
    prompt: "Test both apps",
    findingPolicy: "external" as const,
  };
  const plan = {
    version: 1,
    status: "ready",
    contractHash: engagementManifestHash(candidates),
    decisions: candidates.map((target) => ({
      targetId: target.id,
      scope: "in",
      reason: "Requested",
    })),
    missions: [
      {
        id: "auth",
        purpose: "Test auth",
        assignments: [{ targetId: "a", objectiveId: "auth" }],
        dependsOn: [],
      },
      {
        id: "upload",
        purpose: "Test upload",
        assignments: [{ targetId: "b", objectiveId: "upload" }],
        dependsOn: ["auth"],
      },
    ],
  };
  return { rootPath, workflow, plan };
}

function tools(input: Record<string, unknown>): ToolSet {
  return input.extraTools as ToolSet;
}

async function finishLead(input: Record<string, unknown>, summary = "done") {
  const state = (await tools(input).read_engagement_state?.execute?.(
    { offset: 0, limit: 50 },
    {} as never,
  )) as { missions: Array<{ id: string; status: string; attempt: number }> };
  for (const mission of [...state.missions].reverse()) {
    if (mission.status === "submitted")
      await tools(input).accept_engagement_result?.execute?.(
        {
          missionId: mission.id,
          attempt: mission.attempt,
          review: "Evidence inspected; no further validation needed",
        },
        {} as never,
      );
  }
  const latest = (await tools(input).read_engagement_state?.execute?.(
    { offset: 0, limit: 50 },
    {} as never,
  )) as { reviewedRevision: string };
  return {
    summary,
    coverageComplete: true,
    reviewedRevision: latest.reviewedRevision,
  };
}

describe("code-mode engagement lead", () => {
  it("restores journaled progress after a crash without accepting stale attempts", async () => {
    const { rootPath, workflow, plan } = setup();
    writeJsonAtomic(join(rootPath, ENGAGEMENT_PLAN_PATH), plan);
    const sealed = sealEngagementPlan(rootPath, candidates);
    const state = createEngagementState(sealed);
    const mission = state.missions[0];
    mission.status = "running";
    mission.attempt = 2;
    mission.progress = "Old checkpoint";
    writeJsonAtomic(
      join(rootPath, "coordination", "engagement-state.json"),
      state,
    );
    const journal = new EngagementJournal(rootPath);
    const event = {
      kind: "progress" as const,
      from: mission.workerId,
      missionId: mission.id,
      attempt: 2,
      text: "Latest journaled progress",
    };
    journal.append(event);
    journal.append({ ...event, attempt: 1, text: "Late old attempt" });
    journal.append({
      ...event,
      from: "reassigned-worker",
      text: "Wrong worker",
    });
    fake.consume = async (input) => {
      expect(input.subagentId).toBe("engagement-lead");
      const page = await tools(input).read_engagement_state?.execute?.(
        { offset: 0, limit: 1 },
        {} as never,
      );
      expect(page).toMatchObject({
        missions: [
          {
            id: "auth",
            status: "failed",
            progress: "Latest journaled progress",
          },
        ],
      });
      throw new Error("Review observed restored state");
    };
    await expect(
      runEngagementLead({
        workflow,
        candidates,
        findingsRegistry: {} as FindingsRegistry,
      }),
    ).rejects.toThrow("Review observed restored state");
  });

  it("persists routine progress in the journal without rewriting the full state", async () => {
    const { rootPath, workflow, plan } = setup();
    let release!: () => void;
    const progressed = new Promise<void>((resolve) => {
      release = resolve;
    });
    fake.consume = async (input) => {
      if (input.subagentId === "engagement-planner") {
        writeJsonAtomic(join(rootPath, ENGAGEMENT_PLAN_PATH), plan);
        return { summary: "planned", planComplete: true };
      }
      if (input.subagentId === "engagement-lead") {
        await progressed;
        throw new Error("Stop after progress");
      }
      const path = join(rootPath, "coordination", "engagement-state.json");
      const before = readFileSync(path, "utf8");
      await tools(input).update_engagement_progress?.execute?.(
        { text: "First boundary checked" },
        {} as never,
      );
      await tools(input).update_engagement_progress?.execute?.(
        { text: "Second boundary checked" },
        {} as never,
      );
      expect(readFileSync(path, "utf8")).toBe(before);
      expect(
        new EngagementJournal(rootPath)
          .read()
          .filter((event) => event.kind === "progress")
          .map((event) => event.text),
      ).toEqual(["First boundary checked", "Second boundary checked"]);
      release();
      throw new Error("Worker stopped");
    };
    await expect(
      runEngagementLead({
        workflow,
        candidates,
        findingsRegistry: {} as FindingsRegistry,
      }),
    ).rejects.toThrow("Stop after progress");
    const saved = JSON.parse(
      readFileSync(
        join(rootPath, "coordination", "engagement-state.json"),
        "utf8",
      ),
    );
    expect(saved.missions[0].progress).toBe("Second boundary checked");
  });

  it("lets the lead page in-scope context but rejects excluded and unknown targets", async () => {
    const { rootPath, workflow, plan } = setup();
    plan.decisions[1] = { targetId: "b", scope: "out", reason: "Narrow scope" };
    plan.missions = plan.missions.slice(0, 1);
    const context = "A target-specific threat model and research note";
    let leadReads = 0;
    fake.consume = async (input) => {
      if (input.subagentId === "engagement-planner") {
        writeJsonAtomic(join(rootPath, ENGAGEMENT_PLAN_PATH), plan);
        return { summary: "planned", planComplete: true };
      }
      if (input.subagentId === "engagement-lead") {
        expect(input.activeTools).toContain("read_engagement_context");
        const read = tools(input).read_engagement_context?.execute;
        const first = await read?.(
          { targetId: "a", offset: 0, limit: 12 },
          {} as never,
        );
        const second = await read?.(
          { targetId: "a", offset: 12, limit: 100 },
          {} as never,
        );
        expect(first).toMatchObject({
          text: context.slice(0, 12),
          nextOffset: 12,
        });
        expect(second).toMatchObject({
          text: context.slice(12),
          nextOffset: null,
        });
        await expect(
          read?.({ targetId: "b", offset: 0, limit: 12 }, {} as never),
        ).rejects.toThrow("outside the engagement scope");
        await expect(
          read?.({ targetId: "missing", offset: 0, limit: 12 }, {} as never),
        ).rejects.toThrow("outside the engagement scope");
        leadReads += 1;
        return finishLead(input);
      }
      return {
        summary: "tested",
        coverage: [
          {
            targetId: "a",
            objectiveId: "auth",
            status: "tested",
            summary: "checked",
            evidence: "Observed access denial",
          },
        ],
        reportedFindings: [],
      };
    };
    await runEngagementLead({
      workflow,
      candidates,
      provider: {
        getTarget: async (id) =>
          candidates.find((target) => target.id === id) ?? null,
        readContext: async (_id, offset, limit) => ({
          text: context.slice(offset, offset + limit),
          nextOffset: offset + limit < context.length ? offset + limit : null,
          totalChars: context.length,
          version: "v1",
        }),
      },
      findingsRegistry: {} as FindingsRegistry,
    });
    expect(leadReads).toBeGreaterThan(0);
  });

  it("seals the plan, dispatches bounded dependency workers, and rejects an early lead finish", async () => {
    const { rootPath, workflow, plan } = setup();
    const workers: string[] = [];
    let leadTurns = 0;
    let mailSeen = "";
    fake.consume = async (input) => {
      expect(input.findingPolicy).toBe("external");
      const id = String(input.subagentId);
      if (id === "engagement-planner") {
        expect(input.activeTools).toEqual([
          "read_engagement_manifest",
          "read_engagement_context",
          "write_engagement_plan",
          "response",
        ]);
        await tools(input).read_engagement_context?.execute?.(
          { targetId: "a", offset: 0, limit: 10 },
          {} as never,
        );
        await (input.onStepFinish as (event: unknown) => Promise<void>)({
          usage: { inputTokens: 15, outputTokens: 7 },
          response: { messages: [] },
        });
        writeJsonAtomic(join(rootPath, ENGAGEMENT_PLAN_PATH), plan);
        return { summary: "planned", planComplete: true };
      }
      if (id === "engagement-lead") {
        leadTurns += 1;
        if (leadTurns === 1) {
          const state = (await tools(input).read_engagement_state?.execute?.(
            { offset: 0, limit: 20 },
            {} as never,
          )) as { missions: Array<{ workerId: string }> };
          await tools(input).send_engagement_worker_message?.execute?.(
            {
              workerId: state.missions[0]?.workerId,
              text: "Check the auth boundary",
            },
            {} as never,
          );
        }
        return finishLead(input, "all covered");
      }
      workers.push(id);
      const targetId = id === workers[0] ? "a" : "b";
      expect(
        (input.session as SessionInfo).config?.scopeConstraints?.allowedHosts,
      ).toEqual([`${targetId}.example`]);
      if (targetId === "a") {
        await new Promise((resolve) => setTimeout(resolve, 5));
        mailSeen = String(
          (
            await (
              input.getPendingMessages as () => Promise<
                Array<{ content: unknown }>
              >
            )()
          )[0]?.content,
        );
        await expect(
          tools(input).read_engagement_context?.execute?.(
            { targetId: "b", offset: 0, limit: 10 },
            {} as never,
          ),
        ).rejects.toThrow("outside this mission");
        (input.eventBus as AgentEventBus).emit("tool-result", {
          toolCallId: "finding-1",
          toolName: "document_vulnerability",
          result: {
            type: "json",
            value: {
              success: true,
              finding: {
                title: "Auth bypass",
                endpoint: "https://a.example/api",
              },
            },
          },
          subagentId: id,
        });
      }
      return {
        summary: "tested",
        coverage: [
          {
            targetId,
            objectiveId: targetId === "a" ? "auth" : "upload",
            status: "tested",
            summary: "no issue",
            evidence: "HTTP 200 and denied cross-user access",
          },
        ],
        reportedFindings: [],
      };
    };
    const result = await runEngagementLead({
      workflow: { ...workflow, findingPolicy: "external" },
      candidates,
      findingsRegistry: {} as FindingsRegistry,
      concurrency: 1,
    });
    expect(result.objectiveResults).toHaveLength(2);
    expect(workers).toHaveLength(2);
    expect(leadTurns).toBeGreaterThan(1);
    expect(mailSeen).toContain("Check the auth boundary");
    expect(
      readFileSync(
        join(rootPath, "coordination", "engagement-journal.jsonl"),
        "utf8",
      ),
    ).toContain('"kind":"finding"');
    expect(
      JSON.parse(
        readFileSync(
          join(rootPath, "coordination", "engagement-planning-metrics.json"),
          "utf8",
        ),
      ),
    ).toMatchObject({
      modelCalls: 1,
      inputTokens: 15,
      outputTokens: 7,
      contextReads: 1,
    });
  });

  it("resumes a failed worker with its stable ID and persists complete coverage", async () => {
    const { rootPath, workflow, plan } = setup();
    const [firstCandidate, secondCandidate] = candidates as [
      EngagementTarget,
      EngagementTarget,
    ];
    const grpcCandidates: EngagementTarget[] = [
      {
        ...firstCandidate,
        grpc: {
          transport: "grpc",
          serviceFqn: "example.Accounts",
          method: "GetAccount",
        },
      },
      secondCandidate,
    ];
    plan.contractHash = engagementManifestHash(grpcCandidates);
    plan.decisions[1] = { targetId: "b", scope: "out", reason: "Narrow scope" };
    plan.missions = plan.missions.slice(0, 1);
    let attempts = 0;
    let resumed = "";
    fake.consume = async (input) => {
      const id = String(input.subagentId);
      if (id === "engagement-planner") {
        writeJsonAtomic(join(rootPath, ENGAGEMENT_PLAN_PATH), plan);
        return { summary: "planned", planComplete: true };
      }
      if (id === "engagement-lead") {
        await new Promise((resolve) => setTimeout(resolve, 1));
        const state = (await tools(input).read_engagement_state?.execute?.(
          { offset: 0, limit: 20 },
          {} as never,
        )) as { missions: Array<{ status: string; workerId: string }> };
        if (state.missions[0]?.status === "failed") {
          resumed = state.missions[0].workerId;
          await tools(input).follow_up_engagement_worker?.execute?.(
            { workerId: resumed, text: "Retry with the saved evidence" },
            {} as never,
          );
        }
        return finishLead(input);
      }
      attempts += 1;
      expect(input.grpc).toEqual(grpcCandidates[0]?.grpc);
      if (attempts === 1) throw new Error("temporary failure");
      expect(id).toBe(resumed);
      return {
        summary: "tested",
        coverage: [
          {
            targetId: "a",
            objectiveId: "auth",
            status: "tested",
            summary: "checked",
            evidence: "Observed access denial",
          },
        ],
        reportedFindings: [],
      };
    };
    const result = await runEngagementLead({
      workflow,
      candidates: grpcCandidates,
      findingsRegistry: {} as FindingsRegistry,
      concurrency: 1,
    });
    expect(attempts).toBe(2);
    expect(result.objectiveResults).toEqual([
      { objective: "Test auth", completed: true, result: "checked" },
    ]);
  });

  it("finishes when the lead resolves coverage for a pending dependent mission", async () => {
    const { rootPath, workflow, plan } = setup();
    let workerTurns = 0;
    fake.consume = async (input) => {
      if (input.subagentId === "engagement-planner") {
        writeJsonAtomic(join(rootPath, ENGAGEMENT_PLAN_PATH), plan);
        return { summary: "planned", planComplete: true };
      }
      if (input.subagentId === "engagement-lead") {
        await new Promise((resolve) => setTimeout(resolve, 1));
        const state = (await tools(input).read_engagement_state?.execute?.(
          { offset: 0, limit: 20 },
          {} as never,
        )) as {
          missions: Array<{ status: string }>;
        };
        expect(state.missions.map((mission) => mission.status)).toEqual([
          "failed",
          "pending",
        ]);
        for (const pair of [
          { targetId: "a", objectiveId: "auth" },
          { targetId: "b", objectiveId: "upload" },
        ]) {
          await tools(input).resolve_engagement_pair?.execute?.(
            {
              ...pair,
              status: "blocked",
              summary: "Blocked by the failed prerequisite",
              evidence: "The prerequisite mission failed terminally",
            },
            {} as never,
          );
        }
        await tools(input).cancel_engagement_mission?.execute?.(
          { missionId: "upload", reason: "Failed prerequisite" },
          {} as never,
        );
        return finishLead(input, "resolved");
      }
      workerTurns += 1;
      throw new Error("unrecoverable auth failure");
    };

    const result = await runEngagementLead({
      workflow,
      candidates,
      findingsRegistry: {} as FindingsRegistry,
      concurrency: 1,
    });

    expect(workerTurns).toBe(1);
    expect(result.objectiveResults).toEqual([
      {
        objective: "Test auth",
        completed: false,
        result: "Blocked by the failed prerequisite",
      },
      {
        objective: "Test upload",
        completed: false,
        result: "Blocked by the failed prerequisite",
      },
    ]);
  });

  it("forwards durable fields and lets hooks override agent settings", async () => {
    const { rootPath, workflow, plan } = setup();
    plan.decisions[1] = { targetId: "b", scope: "out", reason: "Narrow scope" };
    plan.missions = plan.missions.slice(0, 1);
    const languageModelMiddleware = vi.fn();
    const usageRecorder = vi.fn();
    const hookUsageRecorder = vi.fn();
    const streamIdFactory = vi.fn();
    const topLevelStep = vi.fn();
    const hookStep = vi.fn();
    const topLevelCache = vi.fn();
    const hookCache = vi.fn();
    const hookReasoning = { effort: "high" };

    fake.construct = (input) => {
      expect(input.languageModelMiddleware).toBe(languageModelMiddleware);
      expect(input.usageRecorder).toBe(hookUsageRecorder);
      expect(input.streamIdFactory).toBe(streamIdFactory);
      expect(input.onCacheMetrics).toBe(hookCache);
      expect(input.enableThinking).toBe(true);
      expect(input.thinkingEffort).toBe("high");
      expect(input.openAIReasoningEffort).toBe("high");
      expect(input.reasoning).toBe(hookReasoning);
    };
    fake.consume = async (input) => {
      if (input.subagentId === "engagement-planner") {
        await (input.onStepFinish as (event: unknown) => Promise<void>)({
          usage: { inputTokens: 1, outputTokens: 1 },
          response: { messages: [] },
        });
        writeJsonAtomic(join(rootPath, ENGAGEMENT_PLAN_PATH), plan);
        return { summary: "planned", planComplete: true };
      }
      if (input.subagentId === "engagement-lead") {
        await new Promise((resolve) => setTimeout(resolve, 1));
        expect(input.onStepFinish).toBe(hookStep);
        return finishLead(input);
      }
      expect(input.onStepFinish).toBe(hookStep);
      return {
        summary: "tested",
        coverage: [
          {
            targetId: "a",
            objectiveId: "auth",
            status: "tested",
            summary: "checked",
            evidence: "Observed access denial",
          },
        ],
        reportedFindings: [],
      };
    };

    await runEngagementLead({
      workflow: {
        ...workflow,
        languageModelMiddleware: languageModelMiddleware as never,
        usageRecorder: usageRecorder as never,
        streamIdFactory: streamIdFactory as never,
        onStepFinish: topLevelStep as never,
        onCacheMetrics: topLevelCache,
        enableThinking: false,
        thinkingEffort: "low",
        openAIReasoningEffort: "low",
        reasoning: { effort: "low" } as never,
        hooks: {
          usageRecorder: hookUsageRecorder,
          onStepFinish: hookStep,
          onCacheMetrics: hookCache,
          enableThinking: true,
          thinkingEffort: "high",
          openAIReasoningEffort: "high",
          reasoning: hookReasoning,
        } as never,
      },
      candidates,
      findingsRegistry: {} as FindingsRegistry,
      concurrency: 1,
    });

    expect(hookStep).toHaveBeenCalledOnce();
    expect(topLevelStep).not.toHaveBeenCalled();
  });

  it("rejects an event wait when the signal was already aborted", async () => {
    const { rootPath, workflow, plan } = setup();
    plan.decisions[1] = { targetId: "b", scope: "out", reason: "Narrow scope" };
    plan.missions = plan.missions.slice(0, 1);
    const abort = new AbortController();
    let markWorkerStarted!: () => void;
    const workerStarted = new Promise<void>((resolve) => {
      markWorkerStarted = resolve;
    });
    let releaseWorker!: () => void;
    const workerStopped = new Promise<void>((resolve) => {
      releaseWorker = resolve;
    });
    fake.consume = async (input) => {
      if (input.subagentId === "engagement-planner") {
        writeJsonAtomic(join(rootPath, ENGAGEMENT_PLAN_PATH), plan);
        return { summary: "planned", planComplete: true };
      }
      if (input.subagentId !== "engagement-lead") {
        markWorkerStarted();
        await workerStopped;
        throw new Error("Worker stopped after cancellation");
      }
      await workerStarted;
      abort.abort(new Error("Engagement cancelled"));
      let timer: ReturnType<typeof setTimeout> | undefined;
      try {
        await Promise.race([
          tools(input).wait_for_engagement_event?.execute?.({}, {} as never),
          new Promise<never>((_, reject) => {
            timer = setTimeout(
              () => reject(new Error("Wait ignored abort")),
              50,
            );
          }),
        ]);
        throw new Error("Event wait unexpectedly resolved");
      } finally {
        clearTimeout(timer);
        releaseWorker();
      }
    };
    await expect(
      runEngagementLead({
        workflow: { ...workflow, abortSignal: abort.signal },
        candidates,
        findingsRegistry: {} as FindingsRegistry,
        concurrency: 1,
      }),
    ).rejects.toThrow("Engagement cancelled");
  });

  it("clears a worker that fails during synchronous construction", async () => {
    const { rootPath, workflow, plan } = setup();
    plan.decisions[1] = { targetId: "b", scope: "out", reason: "Narrow scope" };
    plan.missions = plan.missions.slice(0, 1);
    const abort = new AbortController();
    const timer = setTimeout(
      () => abort.abort(new Error("worker never cleared")),
      500,
    );
    let leadTurns = 0;
    fake.construct = (input) => {
      if (String(input.subagentId).startsWith("engagement-worker-"))
        throw new Error("worker setup failed");
    };
    fake.consume = async (input) => {
      if (input.subagentId === "engagement-planner") {
        writeJsonAtomic(join(rootPath, ENGAGEMENT_PLAN_PATH), plan);
        return { summary: "planned", planComplete: true };
      }
      leadTurns += 1;
      return { summary: "unresolved", coverageComplete: false };
    };
    try {
      await expect(
        runEngagementLead({
          workflow: { ...workflow, abortSignal: abort.signal },
          candidates,
          findingsRegistry: {} as FindingsRegistry,
          concurrency: 1,
        }),
      ).rejects.toThrow("repeatedly ended before terminal mission coverage");
      expect(leadTurns).toBeGreaterThanOrEqual(3);
    } finally {
      clearTimeout(timer);
    }
  });

  it("returns a finding once after following up a completed worker", async () => {
    const { rootPath, workflow, plan } = setup();
    plan.decisions[1] = { targetId: "b", scope: "out", reason: "Narrow scope" };
    plan.missions = plan.missions.slice(0, 1);
    let workerTurns = 0;
    let followed = false;
    fake.consume = async (input) => {
      if (input.subagentId === "engagement-planner") {
        writeJsonAtomic(join(rootPath, ENGAGEMENT_PLAN_PATH), plan);
        return { summary: "planned", planComplete: true };
      }
      if (input.subagentId === "engagement-lead") {
        await new Promise((resolve) => setTimeout(resolve, 1));
        const state = (await tools(input).read_engagement_state?.execute?.(
          { offset: 0, limit: 20 },
          {} as never,
        )) as { missions: Array<{ status: string; workerId: string }> };
        const mission = state.missions[0];
        if (!followed && mission?.status === "submitted") {
          followed = true;
          await tools(input).follow_up_engagement_worker?.execute?.(
            { workerId: mission.workerId, text: "Confirm the finding" },
            {} as never,
          );
          return { summary: "following up", coverageComplete: false };
        }
        return finishLead(input);
      }
      workerTurns += 1;
      return {
        summary: "tested",
        coverage: [
          {
            targetId: "a",
            objectiveId: "auth",
            status: "tested",
            summary: "checked",
            evidence: "Observed access denial",
          },
        ],
        reportedFindings: ["Auth bypass with cross-user access"],
      };
    };
    const result = await runEngagementLead({
      workflow,
      candidates,
      findingsRegistry: {} as FindingsRegistry,
      concurrency: 1,
    });
    expect(workerTurns).toBe(2);
    expect(result.reportedFindings).toEqual([
      "Auth bypass with cross-user access",
    ]);
  });
});

describe("engagement completion barriers", () => {
  it("queues follow-ups behind other workers at the configured cap", async () => {
    const { rootPath, workflow, plan } = setup();
    plan.missions[1].dependsOn = [];
    let running = 0;
    let peak = 0;
    let followed = false;
    let release!: () => void;
    const gate = new Promise<void>((resolve) => {
      release = resolve;
    });
    fake.consume = async (input) => {
      if (input.subagentId === "engagement-planner") {
        writeJsonAtomic(join(rootPath, ENGAGEMENT_PLAN_PATH), plan);
        return { summary: "planned", planComplete: true };
      }
      if (input.subagentId === "engagement-lead") {
        await new Promise((resolve) => setTimeout(resolve, 5));
        const state = (await tools(input).read_engagement_state?.execute?.(
          { offset: 0, limit: 20 },
          {} as never,
        )) as { missions: Array<{ status: string; workerId: string }> };
        if (
          !followed &&
          state.missions[0].status === "submitted" &&
          state.missions[1].status === "running"
        ) {
          followed = true;
          await tools(input).follow_up_engagement_worker?.execute?.(
            { workerId: state.missions[0].workerId, text: "Validate chain" },
            {} as never,
          );
          expect(running).toBe(1);
          release();
        }
        return finishLead(input);
      }
      const first = String(input.prompt).startsWith("Mission auth:");
      running++;
      peak = Math.max(peak, running);
      if (!first) await gate;
      running--;
      return {
        summary: "done",
        coverage: [
          {
            targetId: first ? "a" : "b",
            objectiveId: first ? "auth" : "upload",
            status: "tested",
            summary: "checked",
            evidence: "HTTP access-denied response",
          },
        ],
        reportedFindings: [],
      };
    };
    await runEngagementLead({
      workflow,
      candidates,
      findingsRegistry: {} as FindingsRegistry,
      concurrency: 1,
    });
    expect(followed).toBe(true);
    expect(peak).toBe(1);
  });

  it("rejects a completion decision when material evidence arrives after review", async () => {
    const { rootPath, workflow, plan } = setup();
    plan.missions[1].dependsOn = [];
    let turns = 0;
    fake.consume = async (input) => {
      if (input.subagentId === "engagement-planner") {
        writeJsonAtomic(join(rootPath, ENGAGEMENT_PLAN_PATH), plan);
        return { summary: "planned", planComplete: true };
      }
      if (input.subagentId === "engagement-lead") {
        turns++;
        await new Promise((resolve) => setTimeout(resolve, 1));
        const result = await finishLead(input);
        if (turns === 1) {
          await tools(input).post_engagement_board?.execute?.(
            { text: "A new cross-service observation requires review" },
            {} as never,
          );
        }
        return result;
      }
      const first = String(input.prompt).startsWith("Mission auth:");
      return {
        summary: "tested",
        coverage: [
          {
            targetId: first ? "a" : "b",
            objectiveId: first ? "auth" : "upload",
            status: "tested",
            summary: "checked",
            evidence: "HTTP request/response evidence",
          },
        ],
        reportedFindings: [],
      };
    };
    await runEngagementLead({
      workflow,
      candidates,
      findingsRegistry: {} as FindingsRegistry,
    });
    expect(turns).toBe(2);
  });

  it("stops at the user deadline with submitted results unlanded and preserves the deadline on resume", async () => {
    const { rootPath, workflow, plan } = setup();
    plan.missions[1].dependsOn = [];
    let workerCalls = 0;
    fake.consume = async (input) => {
      if (input.subagentId === "engagement-planner") {
        writeJsonAtomic(join(rootPath, ENGAGEMENT_PLAN_PATH), plan);
        return { summary: "planned", planComplete: true };
      }
      if (input.subagentId === "engagement-lead") {
        const signal = input.abortSignal as AbortSignal;
        await new Promise<void>((_, reject) => {
          if (signal.aborted) reject(signal.reason);
          else
            signal.addEventListener("abort", () => reject(signal.reason), {
              once: true,
            });
        });
      }
      workerCalls++;
      const first = String(input.prompt).startsWith("Mission auth:");
      return {
        summary: "Requires lead review",
        coverage: [
          {
            targetId: first ? "a" : "b",
            objectiveId: first ? "auth" : "upload",
            status: "tested",
            summary: "checked",
            evidence: "HTTP request/response evidence",
          },
        ],
        reportedFindings: [],
      };
    };
    const deadlineAt = new Date(Date.now() + 50).toISOString();
    const result = await runEngagementLead({
      workflow: { ...workflow, deadlineAt },
      candidates,
      findingsRegistry: {} as FindingsRegistry,
    });
    expect(result.assessment.status).toBe("deadline");
    expect(result.assessment.landed).toEqual([]);
    expect(
      result.assessment.coverage.every((cell) => cell.status === "unresolved"),
    ).toBe(true);
    expect(result.assessment.unfinishedMissions).toHaveLength(2);
    expect(result.assessment.unfinishedMissions[0].result?.summary).toBe(
      "Requires lead review",
    );
    const resumed = await runEngagementLead({
      workflow: {
        ...workflow,
        deadlineAt: new Date(Date.now() + 10000).toISOString(),
      },
      candidates,
      findingsRegistry: {} as FindingsRegistry,
    });
    expect(resumed.assessment.deadlineAt).toBe(deadlineAt);
    expect(workerCalls).toBe(2);
  });
});
