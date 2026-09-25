import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";

const constructorCalls: Array<Record<string, unknown>> = [];
const fastStrikeCalls: Array<Record<string, unknown>> = [];

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

import type { AIModel } from "../ai";
import { AgentEventBus } from "../eventBus";
import type { FindingsRegistry } from "../findings/registry";
import type { SessionInfo } from "../session";
import { buildEngagementState, EngagementStore } from "./engagementState";
import { createEngagementTools } from "./engagementTools";

const directories: string[] = [];

afterEach(() => {
  constructorCalls.length = 0;
  fastStrikeCalls.length = 0;
  for (const directory of directories.splice(0)) {
    rmSync(directory, { recursive: true, force: true });
  }
});

function makeRuntime() {
  const rootPath = mkdtempSync(join(tmpdir(), "apex-engagement-tools-"));
  directories.push(rootPath);
  const session = {
    id: "session-test",
    rootPath,
    findingsPath: join(rootPath, "findings"),
    pocsPath: join(rootPath, "pocs"),
    config: {},
  } as unknown as SessionInfo;
  const seed = buildEngagementState("https://example.test", [
    {
      target: "https://example.test/api/users/{id}",
      objectives: ["Test authorization"],
    },
  ]);
  const store = EngagementStore.open(rootPath, seed);
  const findingsRegistry = {
    getFindings: () => [],
  } as unknown as FindingsRegistry;
  const tools = createEngagementTools({
    input: {
      target: "https://example.test",
      model: "test-model" as AIModel,
      session,
    },
    store,
    findingsRegistry,
    eventBus: new AgentEventBus(),
    leadAgentId: "engagement-lead",
    engagementTargetIds: ["target-1"],
    surfaceTools: {
      search_engagement_surface: { execute: vi.fn() } as never,
    },
  });
  return { tools, store, seed };
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

describe("engagement worker tools", () => {
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
    });
    expect(result.state).toMatchObject({
      services: seed.services,
      objectives: seed.objectives,
      coverage: seed.coverage,
    });
    expect(result.inbox).toEqual([]);
  });

  it("persists objective coverage and resumes the same worker thread", async () => {
    const { tools, store, seed } = makeRuntime();
    const serviceId = seed.services[0]?.id as string;
    const objectiveId = seed.objectives[0]?.id as string;
    const spawned = await executeTool(tools.spawn_engagement_worker, {
      mission: "Test the object authorization boundary",
      serviceIds: [serviceId],
      objectiveIds: [objectiveId],
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
    expect(constructorCalls).toHaveLength(2);
    expect(constructorCalls[0]).toMatchObject({
      toolProtocol: undefined,
      engagementTargetIds: ["target-1"],
      directTools: ["search_engagement_surface"],
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
      objectiveIds: [objectiveId],
      mode: "fast-strike",
      toolCallDescription: "spawn impact worker",
    });
    const workerId = spawned.workerId as string;

    await executeTool(tools.follow_up_engagement_worker, {
      workerId,
      message: "Reuse the first attempt and try the sibling account.",
      toolCallDescription: "resume impact worker",
    });

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
});
