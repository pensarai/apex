import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { SessionInfo } from "../session";

const mocks = vi.hoisted(() => ({
  targetedInputs: [] as Array<Record<string, unknown>>,
  fastStrikeInputs: [] as Array<Record<string, unknown>>,
  registry: {
    groupByRootCause: vi.fn(async () => {}),
    getFindings: vi.fn(() => []),
  },
}));

vi.mock("../agents/specialized/pentest/agent", () => ({
  buildPentestSystemPrompt: () => "test system prompt",
  TargetedPentestAgent: class {
    readonly userPrompt = "test user prompt";

    constructor(private readonly input: Record<string, unknown>) {
      mocks.targetedInputs.push(input);
    }

    async consume() {
      await (
        this.input.onStepFinish as
          | ((event: unknown) => Promise<void> | void)
          | undefined
      )?.({ usage: { inputTokens: 10 }, response: { messages: [] } });
      (this.input.onCacheMetrics as ((metrics: unknown) => void) | undefined)?.(
        { cacheReadInputTokens: 8, cacheCreationInputTokens: 2 },
      );
      return { findings: [], findingsPath: "", pocsPath: "" };
    }
  },
}));

vi.mock("../agents/offSecAgent", () => ({
  PLAN_MODE_TOOL_NAMES: [],
  defineAgent: (def: unknown) => def,
  AgentRuntime: class {},
  OffensiveSecurityAgent: class {
    constructor(private readonly input: Record<string, unknown>) {
      mocks.fastStrikeInputs.push(input);
    }

    async consume() {
      await (
        this.input.onStepFinish as
          | ((event: unknown) => Promise<void> | void)
          | undefined
      )?.({ usage: { inputTokens: 10 }, response: { messages: [] } });
      (this.input.onCacheMetrics as ((metrics: unknown) => void) | undefined)?.(
        { cacheReadInputTokens: 8, cacheCreationInputTokens: 2 },
      );
      return { solved: true, summary: "done" };
    }
  },
}));

vi.mock("../findings/registry", () => ({
  FindingsRegistry: {
    fromDirectory: () => mocks.registry,
  },
}));

import { runFastStrike } from "./fastStrike";
import { type PentestWorkflowInput, runPentestSwarm } from "./pentest";

let rootPath: string;
let session: SessionInfo;

beforeEach(() => {
  rootPath = mkdtempSync(join(tmpdir(), "usage-forwarding-"));
  session = {
    id: "ses_usage_forwarding",
    version: "test",
    targets: ["https://example.com"],
    time: { created: 0, updated: 0 },
    rootPath,
    logsPath: join(rootPath, "logs"),
    findingsPath: join(rootPath, "findings"),
    scratchpadPath: join(rootPath, "scratchpad"),
    pocsPath: join(rootPath, "pocs"),
  } as SessionInfo;
});

afterEach(() => {
  mocks.targetedInputs.length = 0;
  mocks.fastStrikeInputs.length = 0;
  vi.clearAllMocks();
  rmSync(rootPath, { recursive: true, force: true });
});

describe("pentest usage callback forwarding", () => {
  it("forwards step and cache usage through the pentest swarm", async () => {
    const onStepFinish = vi.fn();
    const onCacheMetrics = vi.fn();

    await runPentestSwarm({
      targets: [
        { target: "https://example.com", objectives: ["Test the target"] },
      ],
      model: {} as PentestWorkflowInput["model"],
      session,
      findingsRegistry: mocks.registry as never,
      onStepFinish,
      onCacheMetrics,
    });

    expect(onStepFinish).toHaveBeenCalledOnce();
    expect(onCacheMetrics).toHaveBeenCalledWith({
      cacheReadInputTokens: 8,
      cacheCreationInputTokens: 2,
    });
    expect(mocks.targetedInputs[0]?.forwardUsageCallbacksToSpawnedAgents).toBe(
      true,
    );
  });

  it("forwards durable AI hooks through the pentest swarm", async () => {
    const languageModelMiddleware = {
      __sentinel: "mw",
    } as unknown as PentestWorkflowInput["languageModelMiddleware"];
    const usageRecorder = {
      __sentinel: "usage",
    } as unknown as PentestWorkflowInput["usageRecorder"];
    const streamIdFactory = (() =>
      "sid") as unknown as PentestWorkflowInput["streamIdFactory"];

    await runPentestSwarm({
      targets: [
        { target: "https://example.com", objectives: ["Test the target"] },
      ],
      model: {} as PentestWorkflowInput["model"],
      session,
      findingsRegistry: mocks.registry as never,
      languageModelMiddleware,
      usageRecorder,
      streamIdFactory,
    });

    expect(mocks.targetedInputs[0]?.languageModelMiddleware).toBe(
      languageModelMiddleware,
    );
    expect(mocks.targetedInputs[0]?.usageRecorder).toBe(usageRecorder);
    expect(mocks.targetedInputs[0]?.streamIdFactory).toBe(streamIdFactory);
  });

  it("forwards step and cache usage through fast strike", async () => {
    const onStepFinish = vi.fn();
    const onCacheMetrics = vi.fn();

    await runFastStrike({
      target: "https://example.com",
      model: {} as PentestWorkflowInput["model"],
      session,
      onStepFinish,
      onCacheMetrics,
    });

    expect(onStepFinish).toHaveBeenCalledOnce();
    expect(onCacheMetrics).toHaveBeenCalledWith({
      cacheReadInputTokens: 8,
      cacheCreationInputTokens: 2,
    });
  });
});
