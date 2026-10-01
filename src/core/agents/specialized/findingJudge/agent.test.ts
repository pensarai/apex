import { describe, expect, it, vi } from "vitest";

const constructorCalls = vi.hoisted(() => [] as Array<Record<string, unknown>>);

vi.mock("../../offSecAgent/offensiveSecurityAgent", () => ({
  OffensiveSecurityAgent: class {
    constructor(input: Record<string, unknown>) {
      constructorCalls.push(input);
    }
  },
}));

import {
  FindingJudgeAgent,
  type FindingJudgeAgentInput,
  findingJudgeDefinition,
} from "./agent";

function makeOpts(
  overrides: Partial<FindingJudgeAgentInput> = {},
): FindingJudgeAgentInput {
  return {
    model: "test-model",
    session: {
      rootPath: "/tmp/session",
      targets: ["https://example.com"],
      // biome-ignore lint/suspicious/noExplicitAny: minimal SessionInfo stand-in
    } as any,
    finding: {
      pocScript: 'echo "evidence"',
      pocType: "bash",
      pocOutput: { stdout: "evidence", stderr: "", exitCode: 0 },
      claim: {
        title: "Exposed data",
        description: "desc",
        impact: "impact",
        evidence: "evidence",
        endpoint: "https://example.com/api",
      },
    },
    ...overrides,
  };
}

describe("findingJudgeDefinition — golden prompt/toolset (design doc §3.5)", () => {
  it("keeps the fixed judge toolset for a given input", () => {
    const opts = makeOpts();
    expect(findingJudgeDefinition.activeTools(opts, undefined)).toEqual([
      "execute_command",
      "http_request",
      "read_file",
      "list_files",
      "grep",
      "web_search",
      "get_page",
      "response",
    ]);
  });

  it("defaults the subagent id/name, unchanged for the same input", () => {
    const opts = makeOpts();
    expect(findingJudgeDefinition.subagentId?.(opts, undefined)).toBe(
      "finding-judge",
    );
    expect(findingJudgeDefinition.subagentName?.(opts, undefined)).toBe(
      "Finding Judge",
    );
  });

  it("resolves target from the finding when set", () => {
    const opts = makeOpts();
    opts.finding.target = "https://example.com/reported-endpoint";
    expect(findingJudgeDefinition.target?.(opts, undefined)).toBe(
      "https://example.com/reported-endpoint",
    );
  });

  it("falls back to the session's first target when the finding has none", () => {
    const opts = makeOpts();
    expect(opts.finding.target).toBeUndefined();
    expect(findingJudgeDefinition.target?.(opts, undefined)).toBe(
      "https://example.com",
    );
  });
});

describe("FindingJudgeAgent hook forwarding (design doc §3.5)", () => {
  it("forwards extraTools, subagentSpawner, smsInbox and emailAdapterFor — the hooks the pre-A7 constructor dropped", () => {
    constructorCalls.length = 0;

    const extraTools = { extra_tool: {} };
    const subagentSpawner = { spawnMany: vi.fn() };
    const smsInbox = { reserve: vi.fn(), list: vi.fn() };
    const emailAdapterFor = vi.fn(() => null);

    new FindingJudgeAgent(
      makeOpts({
        // biome-ignore lint/suspicious/noExplicitAny: fake ToolSet stand-in
        extraTools: extraTools as any,
        // biome-ignore lint/suspicious/noExplicitAny: fake SubagentSpawner stand-in
        subagentSpawner: subagentSpawner as any,
        smsInbox,
        emailAdapterFor,
      }),
    );

    expect(constructorCalls).toHaveLength(1);
    const forwarded = constructorCalls[0]!;
    expect(forwarded.extraTools).toEqual(extraTools);
    expect(forwarded.subagentSpawner).toBe(subagentSpawner);
    expect(forwarded.smsInbox).toBe(smsInbox);
    expect(forwarded.emailAdapterFor).toBe(emailAdapterFor);
  });
});
