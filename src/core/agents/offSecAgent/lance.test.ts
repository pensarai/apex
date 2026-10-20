import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import type { StreamResponseOpts } from "../../ai";
import { LANCE_CONFIG, LANCE_SYSTEM_PROMPT } from "../lance";

const observed = vi.hoisted(() => ({ streams: [] as StreamResponseOpts[] }));
vi.mock("../../ai", async (original) => ({
  ...(await original<Record<string, unknown>>()),
  streamResponse: (options: StreamResponseOpts) => {
    observed.streams.push(options);
    return { fullStream: (async function* () {})() };
  },
}));

import type { SessionInfo } from "../../session";
import { OffensiveSecurityAgent } from "./offensiveSecurityAgent";

const roots: string[] = [];
function input() {
  const root = mkdtempSync(join(tmpdir(), "lance-harness-"));
  roots.push(root);
  return {
    mode: "lance" as const,
    model: "fixture",
    prompt: "Capture the flag",
    activeTools: ["spawn_pentest_agent", "document_vulnerability"],
    session: {
      id: "ses_lance",
      targets: ["http://example.test"],
      rootPath: root,
      config: {},
      findingsPath: join(root, "findings"),
      scratchpadPath: join(root, "scratchpad"),
      pocsPath: join(root, "pocs"),
    } as SessionInfo,
    sandbox: {
      type: "linux" as const,
      execute: vi.fn(async () => {
        throw new Error("Unexpected runtime probe");
      }),
    },
  };
}
afterEach(() => {
  for (const root of roots.splice(0))
    rmSync(root, { recursive: true, force: true });
  observed.streams.length = 0;
});

describe("Lance shared harness integration", () => {
  it.each([
    "unsolved",
    "deadline_exhausted",
    "cancelled",
  ])("allows a user-requested interactive turn after %s, including legacy results", async (outcome) => {
    const args = input();
    writeFileSync(
      join(args.session.rootPath, "lance-result.json"),
      JSON.stringify({ outcome, reason: "Previous turn ended" }),
    );
    const agent = new OffensiveSecurityAgent({
      ...args,
      lance: { interactive: true },
    });
    await agent.consume();
    expect(agent.lanceRuntime?.metrics("fixture").outcome).toBe(
      "awaiting_input",
    );
  });

  it("honors the judge toggle and gives a supplied harness verifier precedence", () => {
    const enabled = new OffensiveSecurityAgent({
      ...input(),
      findingPolicy: "native",
    });
    expect(enabled.lanceRuntime?.options.verificationSource).toBe("apex_judge");
    expect(enabled.lanceRuntime?.options.verifyObjective).toBeTypeOf(
      "function",
    );
    const disabled = new OffensiveSecurityAgent({
      ...input(),
      findingPolicy: "external",
    });
    expect(disabled.lanceRuntime?.options.verifyObjective).toBeUndefined();
    const verify = vi.fn();
    const harness = new OffensiveSecurityAgent({
      ...input(),
      findingPolicy: "native",
      lance: { verifyObjective: verify },
    });
    expect(harness.lanceRuntime?.options.verifyObjective).toBe(verify);
    expect(harness.lanceRuntime?.options.verificationSource).not.toBe(
      "apex_judge",
    );
  });

  it("constructs only direct tools and suppresses production prompts and auxiliary calls", async () => {
    const args = input();
    const agent = new OffensiveSecurityAgent(args);
    await agent.consume();
    const stream = observed.streams[0];
    expect(Object.keys(stream.tools ?? {}).sort()).toEqual(
      [
        ...LANCE_CONFIG.tools,
        "submit_objective",
        "finish_task",
        "finish_unsolved",
      ].sort(),
    );
    expect(stream.primaryModelOnly).toBe(true);
    expect(stream.runContextCompaction).toBe(
      agent.lanceRuntime!.runContextCompaction,
    );
    expect(stream.system).toContain(LANCE_SYSTEM_PROMPT);
    expect(stream.system).not.toContain("Session Workspace");
    expect(args.sandbox.execute).not.toHaveBeenCalled();
    expect(() => new OffensiveSecurityAgent(args)).toThrow("terminal");
    expect(
      () => new OffensiveSecurityAgent({ ...args, mode: "default" }),
    ).not.toThrow();
    stream.onInvalidToolCall?.("spawn_pentest_agent");
    expect(
      agent.lanceRuntime!.metrics("fixture").policyViolations,
    ).toMatchObject([{ kind: "forbidden_tool", name: "spawn_pentest_agent" }]);
  });

  it.each([
    "extraTools",
    "system",
    "subagentSpawner",
    "responseSchema",
    "resolveResult",
    "subagentId",
  ])("rejects a %s override", (key) => {
    expect(
      () => new OffensiveSecurityAgent({ ...input(), [key]: {} } as never),
    ).toThrow("does not permit");
  });

  it("retains command scope and destructive-action guards", async () => {
    const args = input();
    args.session.config = {
      scopeConstraints: { allowedHosts: ["example.test"], strictScope: true },
    } as never;
    const agent = new OffensiveSecurityAgent(args);
    await agent.streamReady();
    const tools = observed.streams[0].tools!;
    const result = await tools.execute_command.execute!(
      { command: "curl https://outside.test", toolCallDescription: "probe" },
      { toolCallId: "test", messages: [] },
    );
    expect(JSON.stringify(result)).toMatch(/scope/i);
    const destructive = await tools.execute_command.execute!(
      {
        command: "curl -X DELETE https://example.test/resource",
        toolCallDescription: "destructive guard fixture",
      },
      { toolCallId: "destructive", messages: [] },
    );
    expect(JSON.stringify(destructive)).toMatch(/Destructive action blocked/);
    expect(args.sandbox.execute).not.toHaveBeenCalled();
    agent.lanceRuntime!.finish();
  });

  it("keeps compaction out of the agent step limit while retaining usage callbacks", async () => {
    const onStepFinish = vi.fn();
    const agent = new OffensiveSecurityAgent({ ...input(), onStepFinish });
    await agent.streamReady();
    const onStep = observed.streams[0].onStepFinish!;
    const event = (id: string) =>
      ({
        response: { id, messages: [] },
        usage: { inputTokens: 2, outputTokens: 1 },
      }) as unknown as Parameters<typeof onStep>[0];
    for (let index = 0; index < LANCE_CONFIG.maxSteps - 1; index++) {
      await onStep(event(`agent-${index}`));
    }
    await onStep(event("summarization"));
    await onStep(event("tool-repair"));
    expect(agent.lanceRuntime!.terminal).toBe(false);
    expect(onStepFinish).toHaveBeenCalledTimes(LANCE_CONFIG.maxSteps + 1);
    await onStep(event("agent-final"));
    expect(agent.lanceRuntime!.metrics("fixture").outcome).toBe("step_limit");
    await agent.consume();
  });
});
