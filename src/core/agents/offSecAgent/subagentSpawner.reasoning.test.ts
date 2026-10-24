import { beforeEach, describe, expect, it, vi } from "vitest";
import type { ReasoningSetting } from "../../ai";
import type { SessionInfo } from "../../session";
import {
  inProcessSubagentSpawner,
  type SubagentSpec,
  type SubagentType,
} from "./subagentSpawner";
import { delegateAuth } from "./tools/delegateAuth";
import { runAttackSurface } from "./tools/runAttackSurface";
import { generateThreatModelForEndpoint } from "./tools/threatModelGenerator";
import type { ToolContext } from "./tools/types";

const mocks = vi.hoisted(() => {
  const received = new Map<string, Record<string, unknown>>();
  const agent = (type: string, result: unknown) =>
    class {
      drained = Promise.resolve();
      constructor(input: Record<string, unknown>) {
        received.set(type, input);
      }
      async consume() {
        return result;
      }
    };
  return { received, agent };
});
vi.mock("../specialized/pentest/agent", () => ({
  TargetedPentestAgent: mocks.agent("pentest", { findings: [] }),
}));
vi.mock("../specialized/codeAgent/agent", () => ({
  CodeAgent: mocks.agent("code", {
    exposure: 1,
    dataSensitivity: 1,
    functionCriticality: 1,
    securityIndicators: 1,
    businessLogic: "fixture",
    threatModel: "fixture",
    pentestObjectives: [],
  }),
}));
vi.mock("../specialized/whiteboxAttackSurface", () => ({
  WhiteboxAttackSurfaceAgent: mocks.agent("whitebox-attack-surface", {
    apps: [],
    summary: {},
  }),
}));
vi.mock("../specialized/reconWorker/agent", () => ({
  ReconWorkerAgent: mocks.agent("recon-worker", undefined),
}));
vi.mock("../specialized/attackSurface/blackboxAgent", () => ({
  BlackboxAttackSurfaceAgent: mocks.agent("blackbox-attack-surface", {
    targets: [],
  }),
}));
vi.mock("../specialized/authenticationAgent/agent", () => ({
  runAuthenticationAgent: async (input: Record<string, unknown>) => {
    mocks.received.set("authentication", input);
    return { success: false, summary: "fixture" };
  },
}));
vi.mock("../specialized/findingJudge", () => ({
  judgeFinding: async (_: unknown, input: Record<string, unknown>) => {
    mocks.received.set("finding-judge", input);
    return { verdict: "confirmed" };
  },
}));

const specs = {
  pentest: {
    type: "pentest",
    target: "https://example.test",
    objectives: ["test"],
  },
  code: { type: "code", codebasePath: "/fixture", objective: "test" },
  "recon-worker": {
    type: "recon-worker",
    goal: "test",
    target: "https://example.test",
  },
  "whitebox-attack-surface": {
    type: "whitebox-attack-surface",
    codebasePath: "/fixture",
  },
  "blackbox-attack-surface": {
    type: "blackbox-attack-surface",
    target: "https://example.test",
  },
  authentication: { type: "authentication", target: "https://example.test" },
  "finding-judge": { type: "finding-judge", judgeInput: {} as never },
} satisfies { [T in SubagentType]: Extract<SubagentSpec, { type: T }> };

const selections = [
  { model: "gpt-6.1-sol", reasoning: "low" },
  { model: "claude-sonnet-4-5", reasoning: "disabled" },
  { model: "gpt-5.1", reasoning: "none" },
] satisfies Array<{ model: string; reasoning: ReasoningSetting }>;

beforeEach(() => mocks.received.clear());

describe.each(Object.values(specs))("$type child reasoning", (spec) => {
  it.each(selections)("preserves $model / $reasoning", async (selection) => {
    await inProcessSubagentSpawner.spawn({
      spec,
      runtime: { session: { id: "root" } as SessionInfo, ...selection },
    });
    expect(mocks.received.get(spec.type)).toMatchObject(selection);
  });
  it("converts legacy inputs before constructing the child", async () => {
    await inProcessSubagentSpawner.spawn({
      spec,
      runtime: {
        session: { id: "root" } as SessionInfo,
        model: "concentrate:glm-5.3",
        openAIReasoningEffort: "xhigh",
      },
    });
    expect(mocks.received.get(spec.type)).toMatchObject({
      model: "concentrate:glm-5.3",
      reasoning: "max",
    });
    expect(mocks.received.get(spec.type)).not.toHaveProperty(
      "openAIReasoningEffort",
    );
  });
});

describe.each(
  selections,
)("delegating tools with $model / $reasoning", (selection) => {
  const context = () =>
    ({
      ...selection,
      session: { id: "root" } as SessionInfo,
      agentCwd: "/fixture",
      subagentSpawner: inProcessSubagentSpawner,
    }) as ToolContext;
  const options = { toolCallId: "call-child", messages: [] };
  it.each([
    "whitebox",
    "blackbox",
  ])("run_attack_surface %s reaches the child", async (mode) => {
    await runAttackSurface(context()).execute?.(
      {
        target: "https://example.test",
        cwd: mode === "whitebox" ? "/fixture" : undefined,
        toolCallDescription: "test",
      },
      options,
    );
    expect(mocks.received.get(`${mode}-attack-surface`)).toMatchObject(
      selection,
    );
  });
  it("delegate_to_auth_subagent reaches the child", async () => {
    await delegateAuth(context()).execute?.(
      {
        target: "https://example.test",
        reason: "test",
        toolCallDescription: "test",
      },
      options,
    );
    expect(mocks.received.get("authentication")).toMatchObject(selection);
  });
  it("endpoint threat modeling reaches its code child", async () => {
    const result = await generateThreatModelForEndpoint(context(), {
      appName: "fixture",
      routePath: "/test",
      description: "test",
    });
    expect(result).not.toBeNull();
    expect(mocks.received.get("code")).toMatchObject(selection);
  });
});
