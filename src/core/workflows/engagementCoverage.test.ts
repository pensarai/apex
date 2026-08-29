import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";

const agentCalls: Array<Record<string, unknown>> = [];
const assignmentAttempts = new Map<string, number>();
let alwaysIncomplete = false;

vi.mock("../agents/specialized/pentest/agent", () => ({
  TargetedPentestAgent: class {
    constructor(private readonly input: Record<string, unknown>) {
      agentCalls.push(input);
    }

    async consume() {
      const objectives = this.input.objectives as string[];
      return {
        findings: [],
        objectiveResults: objectives.map((objective) => {
          const attempts = (assignmentAttempts.get(objective) ?? 0) + 1;
          assignmentAttempts.set(objective, attempts);
          const completed = alwaysIncomplete
            ? false
            : !objective.includes("target-0:") || attempts > 1;
          return {
            objective,
            completed,
            result: completed ? "Bounded testing complete" : "Try again",
          };
        }),
      };
    }
  },
}));

import type { AIModel } from "../ai";
import { AgentEventBus } from "../eventBus";
import type { FindingsRegistry } from "../findings/registry";
import type { SessionInfo } from "../session";
import {
  buildEngagementCoverageBatches,
  runDeterministicEngagementCoverage,
} from "./engagementCoverage";
import { buildEngagementState, EngagementStore } from "./engagementState";
import { EngagementWorkerPool } from "./engagementWorkerPool";

const directories: string[] = [];

afterEach(() => {
  agentCalls.length = 0;
  assignmentAttempts.clear();
  alwaysIncomplete = false;
  for (const directory of directories.splice(0)) {
    rmSync(directory, { recursive: true, force: true });
  }
});

function runtime(targetCount: number) {
  const rootPath = mkdtempSync(join(tmpdir(), "apex-engagement-coverage-"));
  directories.push(rootPath);
  const session = {
    id: "session-coverage",
    rootPath,
    findingsPath: join(rootPath, "findings"),
    pocsPath: join(rootPath, "pocs"),
    config: {},
  } as unknown as SessionInfo;
  const seed = buildEngagementState(
    "https://example.test",
    Array.from({ length: targetCount }, (_, index) => ({
      id: `target-${index}`,
      target: `https://example.test/api/${index}`,
      objectives: ["Test authorization"],
    })),
  );
  return {
    session,
    seed,
    store: EngagementStore.open(rootPath, seed),
    findingsRegistry: {
      getFindings: () => [],
    } as unknown as FindingsRegistry,
  };
}

describe("deterministic engagement coverage", () => {
  it("groups identical endpoint-local objectives into batches of six", () => {
    const { seed } = runtime(7);
    expect(
      buildEngagementCoverageBatches(seed).map((batch) => batch.cells.length),
    ).toEqual([6, 1]);
  });

  it("retries one incomplete cell as a singleton and completes the service", async () => {
    const { session, store, findingsRegistry } = runtime(7);
    const checkpoints: number[] = [];
    await runDeterministicEngagementCoverage({
      workflow: {
        target: "https://example.test",
        model: "test-model" as AIModel,
        session,
      },
      store,
      pool: new EngagementWorkerPool(1),
      findingsRegistry,
      eventBus: new AgentEventBus(),
      leadAgentId: session.id,
      engagementTargetIds: store.snapshot().targets.map((target) => target.id),
      onCheckpoint: (checkpoint) => {
        checkpoints.push(checkpoint.version);
      },
    });

    const state = store.snapshot();
    expect(agentCalls).toHaveLength(3);
    expect(state.coverage).toHaveLength(7);
    expect(state.coverage.every((cell) => cell.status === "exhausted")).toBe(
      true,
    );
    expect(
      state.coverage.find((cell) => cell.targetId === "target-0")?.attempts,
    ).toBe(2);
    expect(state.services[0]?.baselineStatus).toBe("explored");
    expect(checkpoints).toHaveLength(3);
  });

  it("hands a cell to the lead after the singleton retry fails", async () => {
    alwaysIncomplete = true;
    const { session, store, findingsRegistry } = runtime(1);
    await runDeterministicEngagementCoverage({
      workflow: {
        target: "https://example.test",
        model: "test-model" as AIModel,
        session,
      },
      store,
      pool: new EngagementWorkerPool(1),
      findingsRegistry,
      eventBus: new AgentEventBus(),
      leadAgentId: session.id,
      engagementTargetIds: ["target-0"],
    });

    expect(store.snapshot().coverage[0]).toMatchObject({
      targetId: "target-0",
      status: "needs-lead",
      attempts: 2,
    });
    expect(store.completion().missingCoverageCellIds).toHaveLength(1);
  });
});
