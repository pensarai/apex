import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";

const constructorCalls: Array<Record<string, unknown>> = [];

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

import type { AIModel } from "../ai";
import { AgentEventBus } from "../eventBus";
import type { FindingsRegistry } from "../findings/registry";
import type { SessionInfo } from "../session";
import { buildEngagementState, EngagementStore } from "./engagementState";
import { createEngagementTools } from "./engagementTools";

const directories: string[] = [];

afterEach(() => {
  constructorCalls.length = 0;
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
});
