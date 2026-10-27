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
}));

vi.mock("../agents/offSecAgent", () => ({
  OffensiveSecurityAgent: class {
    constructor(private readonly input: Record<string, unknown>) {}
    consume(): Promise<unknown> {
      if (!fake.consume) throw new Error("No fake engagement agent");
      return fake.consume(this.input);
    }
  },
}));

import { runEngagementLead } from "./engagementLead";
import {
  ENGAGEMENT_PLAN_PATH,
  type EngagementTarget,
  engagementManifestHash,
  writeJsonAtomic,
} from "./engagementPlan";

const roots: string[] = [];
afterEach(() => {
  fake.consume = undefined;
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

describe("code-mode engagement lead", () => {
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
        return { summary: "all covered", coverageComplete: true };
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
        return { summary: "done", coverageComplete: true };
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
});
