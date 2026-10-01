import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const constructorCalls = vi.hoisted(() => [] as Array<Record<string, unknown>>);

vi.mock("../offSecAgent/offensiveSecurityAgent", () => ({
  OffensiveSecurityAgent: class {
    constructor(input: Record<string, unknown>) {
      constructorCalls.push(input);
    }
  },
}));

import {
  BenchmarkComparisonAgent,
  type BenchmarkComparisonAgentInput,
  benchmarkComparisonDefinition,
} from "./benchmarkComparisonAgent";

let repoPath: string;
let sessionRootPath: string;

beforeEach(() => {
  repoPath = mkdtempSync(join(tmpdir(), "benchmark-repo-"));
  sessionRootPath = mkdtempSync(join(tmpdir(), "benchmark-session-"));
  mkdirSync(join(repoPath, "expected_results"), { recursive: true });
  writeFileSync(
    join(repoPath, "expected_results", "expected.json"),
    JSON.stringify({ title: "SQL Injection", severity: "HIGH" }),
  );
});

afterEach(() => {
  rmSync(repoPath, { recursive: true, force: true });
  rmSync(sessionRootPath, { recursive: true, force: true });
});

function makeOpts(): BenchmarkComparisonAgentInput {
  return {
    model: "test-model",
    // biome-ignore lint/suspicious/noExplicitAny: minimal SessionInfo stand-in
    session: { rootPath: sessionRootPath, targets: [] } as any,
    repoPath,
  };
}

describe("benchmarkComparisonDefinition — golden prompt/toolset (design doc §3.5)", () => {
  it("exposes only the single comparison-results tool", () => {
    const opts = makeOpts();
    expect(benchmarkComparisonDefinition.activeTools(opts, undefined)).toEqual([
      "provide_comparison_results",
    ]);
  });

  it("includes the expected findings loaded from repoPath in the prompt", () => {
    const opts = makeOpts();
    const prompt = benchmarkComparisonDefinition.prompt(opts, undefined);

    expect(prompt).toContain("SQL Injection");
    expect(prompt).toContain("Expected Findings");
    expect(prompt).toContain("Actual Findings");
  });
});

describe("BenchmarkComparisonAgent hook forwarding (design doc §3.5)", () => {
  it("forwards every AgentHooks field the pre-A7 constructor dropped", () => {
    constructorCalls.length = 0;

    const backends = { fs: {}, command: {}, http: {}, browser: {}, inbox: {} };
    const subagentSpawner = { spawnMany: vi.fn() };
    const languageModelMiddleware = { wrapGenerate: vi.fn() };
    const usageRecorder = vi.fn();
    const streamIdFactory = vi.fn(() => "id");
    const smsInbox = { reserve: vi.fn(), list: vi.fn() };
    const emailAdapterFor = vi.fn(() => null);
    const sandbox = { kind: "fake-sandbox" };
    const extraTools = { extra_tool: {} };

    new BenchmarkComparisonAgent({
      ...makeOpts(),
      // biome-ignore lint/suspicious/noExplicitAny: fake ToolBackends stand-in
      backends: backends as any,
      // biome-ignore lint/suspicious/noExplicitAny: fake SubagentSpawner stand-in
      subagentSpawner: subagentSpawner as any,
      // biome-ignore lint/suspicious/noExplicitAny: fake LanguageModelMiddleware stand-in
      languageModelMiddleware: languageModelMiddleware as any,
      usageRecorder,
      streamIdFactory,
      smsInbox,
      emailAdapterFor,
      // biome-ignore lint/suspicious/noExplicitAny: fake UnifiedSandbox stand-in
      sandbox: sandbox as any,
      // biome-ignore lint/suspicious/noExplicitAny: fake ToolSet stand-in
      extraTools: extraTools as any,
    });

    expect(constructorCalls).toHaveLength(1);
    const forwarded = constructorCalls[0]!;
    expect(forwarded.backends).toBe(backends);
    expect(forwarded.subagentSpawner).toBe(subagentSpawner);
    expect(forwarded.languageModelMiddleware).toBe(languageModelMiddleware);
    expect(forwarded.usageRecorder).toBe(usageRecorder);
    expect(forwarded.streamIdFactory).toBe(streamIdFactory);
    expect(forwarded.smsInbox).toBe(smsInbox);
    expect(forwarded.emailAdapterFor).toBe(emailAdapterFor);
    expect(forwarded.sandbox).toBe(sandbox);
    expect(forwarded.extraTools).toEqual(extraTools);
  });
});
