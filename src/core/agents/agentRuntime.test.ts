/**
 * Proves the design-doc §3.5 contract: every hook in {@link AgentHooks} is
 * spread, in one place, from a specialized agent's input into the underlying
 * `OffensiveSecurityAgent` constructor. Before this file existed,
 * `AuthenticationAgent` dropped five of these hooks, `FindingJudgeAgent` four,
 * `BenchmarkComparisonAgent` eight, and `VulnerabilityReproductionAgent`
 * accepted `smsInbox`/`emailAdapterFor` by type and silently dropped them —
 * each by hand-copying fields into its own constructor and forgetting one.
 * `AgentRuntime` removes the hand-copy entirely, so this test exercises the
 * ONE place every specialized agent now goes through.
 */
import { describe, expect, expectTypeOf, it, vi } from "vitest";

const constructorCalls = vi.hoisted(() => [] as Array<Record<string, unknown>>);

vi.mock("./offSecAgent/offensiveSecurityAgent", () => ({
  OffensiveSecurityAgent: class {
    constructor(input: Record<string, unknown>) {
      constructorCalls.push(input);
    }
  },
}));

import type { ToolSet } from "ai";
import type { AIModel } from "../ai";
import {
  AgentRuntime,
  assembleAgentHooks,
  type RequiredAgentHooks,
} from "./agentRuntime";
import { defineAgent } from "./defineAgent";
import type { AgentHooks, SpecializedAgentInput } from "./offSecAgent/types";

function fakeTool(): ToolSet[string] {
  // biome-ignore lint/suspicious/noExplicitAny: a fake ToolSet entry only ever needs identity for equality checks
  return {} as any;
}

interface FakeOpts extends SpecializedAgentInput {
  objective: string;
}

function buildHooks() {
  return {
    backends: { fs: {}, command: {}, http: {}, browser: {}, inbox: {} },
    subagentSpawner: { spawnMany: vi.fn() },
    languageModelMiddleware: { wrapGenerate: vi.fn() },
    usageRecorder: vi.fn(),
    streamIdFactory: vi.fn(() => "id"),
    smsInbox: { reserve: vi.fn(), list: vi.fn() },
    emailAdapterFor: vi.fn(() => null),
    abortSignal: new AbortController().signal,
    extraTools: { extra_tool: {} },
    sandbox: { kind: "fake-sandbox" },
    // biome-ignore lint/suspicious/noExplicitAny: test doubles for opaque host-injected interfaces
  } as unknown as Required<AgentHooks> & Record<string, any>;
}

describe("AgentRuntime — hook forwarding (design doc §3.5)", () => {
  it("spreads every AgentHooks field from opts into the OffensiveSecurityAgent constructor", () => {
    constructorCalls.length = 0;
    const hooks = buildHooks();

    const opts: FakeOpts = {
      model: "test-model" as AIModel,
      session: {
        rootPath: "/tmp/session",
        targets: [],
        findingsPath: "/tmp/session/findings",
        pocsPath: "/tmp/session/pocs",
        // biome-ignore lint/suspicious/noExplicitAny: minimal SessionInfo stand-in
      } as any,
      objective: "do the thing",
      ...hooks,
    };

    const def = defineAgent<FakeOpts, void>({
      name: "test-agent",
      role: "worker",
      prompt: (o) => o.objective,
      activeTools: () => ["response"],
    });

    new AgentRuntime(def, opts);

    expect(constructorCalls).toHaveLength(1);
    const forwarded = constructorCalls[0]!;

    for (const key of Object.keys(hooks) as (keyof typeof hooks)[]) {
      // extraTools is merged into a fresh object (see the dedicated test
      // below); every other hook is forwarded by reference, unmodified.
      if (key === "extraTools") {
        expect(forwarded[key]).toEqual(hooks[key]);
        continue;
      }
      expect(forwarded[key]).toBe(hooks[key]);
    }
  });

  it("merges a definition's own extraTools with the caller's, rather than replacing them", () => {
    constructorCalls.length = 0;
    const callerTool = fakeTool();
    const opts: FakeOpts = {
      model: "test-model" as AIModel,
      // biome-ignore lint/suspicious/noExplicitAny: minimal SessionInfo stand-in
      session: { rootPath: "/tmp", targets: [] } as any,
      objective: "x",
      extraTools: { caller_tool: callerTool },
    };

    const definitionTool = fakeTool();
    const def = defineAgent<FakeOpts, void>({
      name: "test-agent",
      role: "worker",
      prompt: (o) => o.objective,
      activeTools: () => ["response"],
      extraTools: () => ({ definition_tool: definitionTool }),
    });

    new AgentRuntime(def, opts);

    const forwarded = constructorCalls[0]!;
    expect(forwarded.extraTools).toEqual({
      caller_tool: callerTool,
      definition_tool: definitionTool,
    });
  });

  it("lets an AgentDefinition's stopWhen override the caller's, matching pre-A7 pentest/whitebox behavior", () => {
    constructorCalls.length = 0;
    const callerStopWhen = () => false;
    const opts: FakeOpts = {
      model: "test-model" as AIModel,
      // biome-ignore lint/suspicious/noExplicitAny: minimal SessionInfo stand-in
      session: { rootPath: "/tmp", targets: [] } as any,
      objective: "x",
      stopWhen: callerStopWhen,
    };

    const definitionStopWhen = () => true;
    const def = defineAgent<FakeOpts, void>({
      name: "test-agent",
      role: "worker",
      prompt: (o) => o.objective,
      activeTools: () => ["response"],
      stopWhen: () => definitionStopWhen,
    });

    new AgentRuntime(def, opts);

    expect(constructorCalls[0]!.stopWhen).toBe(definitionStopWhen);
  });

  it("falls back to the caller's stopWhen when the definition declares none", () => {
    constructorCalls.length = 0;
    const callerStopWhen = () => false;
    const opts: FakeOpts = {
      model: "test-model" as AIModel,
      // biome-ignore lint/suspicious/noExplicitAny: minimal SessionInfo stand-in
      session: { rootPath: "/tmp", targets: [] } as any,
      objective: "x",
      stopWhen: callerStopWhen,
    };

    const def = defineAgent<FakeOpts, void>({
      name: "test-agent",
      role: "worker",
      prompt: (o) => o.objective,
      activeTools: () => ["response"],
    });

    new AgentRuntime(def, opts);

    expect(constructorCalls[0]!.stopWhen).toBe(callerStopWhen);
  });
});

describe("assembleAgentHooks — compile-time completeness (design doc §3.5, Appendix F)", () => {
  it("returns every AgentHooks field at runtime", () => {
    const hooks = buildHooks();
    const assembled = assembleAgentHooks(hooks);

    expect(Object.keys(assembled).sort()).toEqual(
      [
        "backends",
        "subagentSpawner",
        "languageModelMiddleware",
        "usageRecorder",
        "streamIdFactory",
        "smsInbox",
        "emailAdapterFor",
        "abortSignal",
        "extraTools",
        "sandbox",
      ].sort(),
    );
  });

  it("type-checks: omitting a hook from the RequiredAgentHooks literal is a compile error", () => {
    // A complete literal type-checks.
    const complete: RequiredAgentHooks = {
      backends: undefined,
      subagentSpawner: undefined,
      languageModelMiddleware: undefined,
      usageRecorder: undefined,
      streamIdFactory: undefined,
      smsInbox: undefined,
      emailAdapterFor: undefined,
      abortSignal: undefined,
      extraTools: undefined,
      sandbox: undefined,
    };
    expectTypeOf(complete).toEqualTypeOf<RequiredAgentHooks>();

    // @ts-expect-error — RequiredAgentHooks.sandbox is a required key even
    // though its value may be `undefined`; omitting the key entirely (not
    // just its value) is what a hand-copied field list used to get wrong.
    const missingSandbox: RequiredAgentHooks = {
      backends: undefined,
      subagentSpawner: undefined,
      languageModelMiddleware: undefined,
      usageRecorder: undefined,
      streamIdFactory: undefined,
      smsInbox: undefined,
      emailAdapterFor: undefined,
      abortSignal: undefined,
      extraTools: undefined,
    };
    expect(missingSandbox).toBeDefined();
  });
});
