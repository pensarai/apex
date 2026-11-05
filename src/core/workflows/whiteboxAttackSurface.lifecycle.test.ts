import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { simulateReadableStream, streamText } from "ai";
import { MockLanguageModelV3 } from "ai/test";
import { afterEach, describe, expect, it, vi } from "vitest";
import { inProcessSubagentSpawner } from "../agents/offSecAgent/subagentSpawner";
import { CodeAgent } from "../agents/specialized/codeAgent/agent";
import type { streamResponse } from "../ai";
import { AgentEventBus, type AgentEventMap } from "../eventBus";
import type { SessionInfo } from "../session";
import { LocalBackends } from "../tools/backends/local";
import { inProcessSeams } from "./seams";
import { runWhiteboxAttackSurfaceWorkflow } from "./whiteboxAttackSurface";

const observed = vi.hoisted(() => ({
  model: undefined as MockLanguageModelV3 | undefined,
}));
vi.mock("../ai", async (importOriginal) => ({
  ...(await importOriginal<typeof import("../ai")>()),
  streamResponse: (request: Parameters<typeof streamResponse>[0]) => {
    if (!observed.model) throw new Error("Missing fixture model");
    return streamText({
      model: observed.model,
      tools: request.tools,
      activeTools: request.activeTools,
      stopWhen: request.stopWhen,
      maxRetries: 0,
      prompt: "Discover fixture applications",
    });
  },
}));

const roots: string[] = [];
afterEach(() => {
  vi.restoreAllMocks();
  observed.model = undefined;
  for (const root of roots.splice(0))
    rmSync(root, { recursive: true, force: true });
});

function fixture(result?: unknown) {
  let calls = 0;
  observed.model = new MockLanguageModelV3({
    doStream: async () => {
      calls++;
      return {
        stream: simulateReadableStream({
          chunks: [
            { type: "stream-start", warnings: [] },
            ...(result === undefined
              ? []
              : [
                  {
                    type: "tool-call" as const,
                    toolCallId: "response-apps",
                    toolName: "response",
                    input: JSON.stringify({ result }),
                  },
                ]),
            {
              type: "finish",
              finishReason: {
                unified: result === undefined ? "stop" : "tool-calls",
                raw: result === undefined ? "stop" : "tool_calls",
              },
              usage: {
                inputTokens: {
                  total: 1,
                  noCache: 1,
                  cacheRead: 0,
                  cacheWrite: 0,
                },
                outputTokens: { total: 1, text: 1, reasoning: 0 },
              },
            },
          ],
        }),
      };
    },
  });
  const root = mkdtempSync(join(tmpdir(), "whitebox-phase1-lifecycle-"));
  roots.push(root);
  const session = {
    id: "ses_phase1_lifecycle",
    version: "1.0.0",
    rootPath: root,
    targets: [],
    time: { created: 1, updated: 1 },
    logsPath: join(root, "logs"),
    findingsPath: join(root, "findings"),
    scratchpadPath: join(root, "scratchpad"),
    pocsPath: join(root, "pocs"),
  } satisfies SessionInfo;
  const backends = LocalBackends({
    session,
    agentCwd: root,
    subagentSpawner: inProcessSubagentSpawner,
  });
  const eventBus = new AgentEventBus();
  const spawns: AgentEventMap["subagent-spawn"][] = [];
  const completions: AgentEventMap["subagent-complete"][] = [];
  eventBus.on("subagent-spawn", (event) => spawns.push(event));
  eventBus.on("subagent-complete", (event) => completions.push(event));
  const spawnMany = vi.fn(async () => []);
  const input = {
    codebasePath: root,
    model: "fixture-model",
    session,
    eventBus,
    hooks: { backends, toolProtocol: "direct" as const },
    seams: inProcessSeams({
      ids: { newSessionId: () => "ses_apps_umbrella" },
      fanOut: { spawnMany },
    }),
  };
  return { input, spawns, completions, spawnMany, calls: () => calls };
}

describe("whitebox Phase 1 umbrella lifecycle with a real CodeAgent", () => {
  it.each([
    false,
    true,
  ])("fails the announced umbrella when the model finishes without a validated response (incremental=%s)", async (incremental) => {
    const f = fixture();
    const failure = await runWhiteboxAttackSurfaceWorkflow({
      ...f.input,
      ...(incremental
        ? {
            incremental: {
              diffPath: join(f.input.session.rootPath, "diff"),
              assetsPath: join(f.input.session.rootPath, "assets"),
              existingResult: {
                repoType: "single-app",
                packageManager: "bun",
                apps: [],
                summary: {
                  totalApps: 0,
                  totalPages: 0,
                  totalApiEndpoints: 0,
                  totalPentestObjectives: 0,
                },
              },
            },
          }
        : {}),
    }).catch((error: unknown) => error);

    expect(failure).toBeInstanceOf(Error);
    expect(failure).toMatchObject({
      message:
        "Structured agent ses_apps_umbrella ended without a validated response",
    });
    expect(f.calls()).toBe(1);
    expect(f.spawns.map((event) => event.subagentId)).toEqual([
      "ses_apps_umbrella",
    ]);
    expect(f.completions).toEqual([
      { subagentId: "ses_apps_umbrella", status: "failed" },
    ]);
    expect(f.spawnMany).not.toHaveBeenCalled();
  });

  it.each([
    new Error("Phase 1 provider failed", { cause: new Error("fixture cause") }),
    new DOMException("Phase 1 cancelled", "AbortError"),
  ])("preserves the exact Phase 1 rejection: %s", async (failure) => {
    const f = fixture();
    vi.spyOn(CodeAgent.prototype, "consume").mockRejectedValueOnce(failure);

    await expect(runWhiteboxAttackSurfaceWorkflow(f.input)).rejects.toBe(
      failure,
    );

    expect(f.completions).toEqual([
      { subagentId: "ses_apps_umbrella", status: "failed" },
    ]);
    expect(f.spawns.map((event) => event.subagentId)).toEqual([
      "ses_apps_umbrella",
    ]);
    expect(f.spawnMany).not.toHaveBeenCalled();
    expect(f.calls()).toBe(0);
  });

  it("keeps one successful completion for a validated empty discovery", async () => {
    const f = fixture({
      repoType: "single-app",
      packageManager: "bun",
      apps: [],
    });

    await expect(
      runWhiteboxAttackSurfaceWorkflow(f.input),
    ).resolves.toMatchObject({
      apps: [],
      summary: { totalApps: 0 },
    });

    expect(f.completions).toEqual([
      { subagentId: "ses_apps_umbrella", status: "completed" },
    ]);
    expect(f.calls()).toBe(1);
    expect(f.spawnMany).not.toHaveBeenCalled();
  });
});
