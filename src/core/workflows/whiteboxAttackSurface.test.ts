import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { AgentHooks } from "../agents/offSecAgent";
import type { AppInfo } from "../agents/specialized/whiteboxAttackSurface";
import type { AIModel } from "../ai";
import * as idModule from "../id/id";
import type { SessionInfo } from "../session";
import * as concurrencyModule from "../utils/concurrency";
import {
  type ConcurrencyRunner,
  inProcessSeams,
  type SessionIdFactory,
  WorkflowLimitExceededError,
} from "./seams";

const mocks = vi.hoisted(() => ({
  codeAgentInputs: [] as Array<Record<string, unknown>>,
  consumeImpl: null as
    | ((input: Record<string, unknown>) => Promise<unknown>)
    | null,
}));

vi.mock("../agents/specialized/codeAgent/agent", () => ({
  CodeAgent: class {
    private readonly input: Record<string, unknown>;
    constructor(input: Record<string, unknown>) {
      this.input = input;
      mocks.codeAgentInputs.push(input);
    }
    async consume() {
      if (mocks.consumeImpl) return mocks.consumeImpl(this.input);
      const objective = String(this.input.objective ?? "");
      if (objective.startsWith("# Identify All Applications")) {
        return {
          repoType: "single-app",
          packageManager: "bun",
          apps: [
            {
              name: "web",
              type: "web_application",
              framework: "next",
              description: "test app",
              location: ".",
            },
          ],
        };
      }
      return { summary: "ok" };
    }
  },
}));

import {
  runWhiteboxAttackSurfaceApp,
  runWhiteboxAttackSurfaceWorkflow,
} from "./whiteboxAttackSurface";

let rootPath: string;
let session: SessionInfo;

beforeEach(() => {
  rootPath = mkdtempSync(join(tmpdir(), "whitebox-seams-"));
  session = {
    id: "ses_whitebox_seams",
    version: "test",
    targets: [],
    time: { created: 0, updated: 0 },
    rootPath,
    logsPath: join(rootPath, "logs"),
    findingsPath: join(rootPath, "findings"),
    scratchpadPath: join(rootPath, "scratchpad"),
    pocsPath: join(rootPath, "pocs"),
  } as SessionInfo;
});

afterEach(() => {
  mocks.codeAgentInputs.length = 0;
  mocks.consumeImpl = null;
  vi.restoreAllMocks();
  rmSync(rootPath, { recursive: true, force: true });
});

describe("runWhiteboxAttackSurfaceWorkflow — default seams are byte-identical", () => {
  it("fans out per-app work through the same runWithBoundedConcurrency pool, once", async () => {
    const spy = vi.spyOn(concurrencyModule, "runWithBoundedConcurrency");

    await runWhiteboxAttackSurfaceWorkflow({
      codebasePath: "/repo",
      model: {} as AIModel,
      session,
      surfaceIntegrationEnabled: false,
    });

    expect(spy).toHaveBeenCalledTimes(1);
    const [items, concurrency] = spy.mock.calls[0];
    expect(items).toHaveLength(1);
    expect(concurrency).toBe(5);
  });

  it("mints one newSessionId() per child: umbrella + pages + apiEndpoints for one app", async () => {
    const spy = vi.spyOn(idModule, "newSessionId");

    await runWhiteboxAttackSurfaceWorkflow({
      codebasePath: "/repo",
      model: {} as AIModel,
      session,
      surfaceIntegrationEnabled: false,
    });

    expect(spy).toHaveBeenCalledTimes(3);
  });
});

describe("runWhiteboxAttackSurfaceWorkflow — custom seams", () => {
  it("mints every child id through the injected SessionIdFactory, umbrella first, then per-app tasks in dispatch order", async () => {
    const calls: Array<{ name: string; ordinal: number }> = [];
    const ids: SessionIdFactory = {
      newSessionId: (name, ordinal) => {
        calls.push({ name, ordinal });
        return `wb-${ordinal}`;
      },
    };

    await runWhiteboxAttackSurfaceWorkflow({
      codebasePath: "/repo",
      model: {} as AIModel,
      session,
      surfaceIntegrationEnabled: false,
      seams: inProcessSeams({ ids }),
    });

    expect(calls[0]).toEqual({ name: "whitebox-apps-discovery", ordinal: 0 });
    expect(calls.slice(1)).toEqual([
      { name: "Pages", ordinal: 1 },
      { name: "API Endpoints", ordinal: 2 },
    ]);
  });

  it("routes the per-app fan-out through a custom ConcurrencyRunner", async () => {
    const spawnMany = vi.fn(
      async (
        items: readonly unknown[],
        worker: (item: unknown, index: number) => Promise<unknown>,
      ) => Promise.all(items.map((item, index) => worker(item, index))),
    ) as unknown as ConcurrencyRunner["spawnMany"];

    await runWhiteboxAttackSurfaceWorkflow({
      codebasePath: "/repo",
      model: {} as AIModel,
      session,
      surfaceIntegrationEnabled: false,
      seams: inProcessSeams({ fanOut: { spawnMany } }),
    });

    expect(spawnMany).toHaveBeenCalledTimes(1);
  });

  it("rejects when the per-app fan-out would exceed maxDepth", async () => {
    await expect(
      runWhiteboxAttackSurfaceWorkflow({
        codebasePath: "/repo",
        model: {} as AIModel,
        session,
        surfaceIntegrationEnabled: false,
        seams: inProcessSeams({ limits: { maxDepth: 0 } as never }),
      }),
    ).rejects.toThrow(WorkflowLimitExceededError);
  });
});

describe("runWhiteboxAttackSurfaceWorkflow — AgentHooks", () => {
  it("reaches the Phase 1 apps-discovery agent with the caller's own AgentHooks object", async () => {
    const backends = {
      __sentinel: "backends",
    } as unknown as AgentHooks["backends"];

    await runWhiteboxAttackSurfaceWorkflow({
      codebasePath: "/repo",
      model: {} as AIModel,
      session,
      surfaceIntegrationEnabled: false,
      hooks: { backends },
    });

    expect(mocks.codeAgentInputs[0]?.backends).toBe(backends);
  });

  it("reaches Phase 2 agents, with a per-app hooksForItem override applied by index", async () => {
    const sharedBackends = {
      __sentinel: "shared",
    } as unknown as AgentHooks["backends"];
    const overrideBackends = {
      __sentinel: "override-for-app-0",
    } as unknown as AgentHooks["backends"];

    await runWhiteboxAttackSurfaceWorkflow({
      codebasePath: "/repo",
      model: {} as AIModel,
      session,
      surfaceIntegrationEnabled: false,
      hooks: { backends: sharedBackends },
      seams: inProcessSeams({
        hooksForItem: (_item, index) =>
          index === 0 ? { backends: overrideBackends } : {},
      }),
    });

    // [0] = Phase 1 apps-discovery agent — not part of the per-app fan-out,
    // so it keeps the shared hooks rather than the per-app override.
    expect(mocks.codeAgentInputs[0]?.backends).toBe(sharedBackends);
    // [1] = Pages, [2] = API Endpoints — both spawned for app index 0.
    expect(mocks.codeAgentInputs[1]?.backends).toBe(overrideBackends);
    expect(mocks.codeAgentInputs[2]?.backends).toBe(overrideBackends);
  });
});

describe("runWhiteboxAttackSurfaceApp — standalone, no runWhiteboxAttackSurfaceWorkflow involved", () => {
  const app: AppInfo = {
    name: "web",
    type: "web_application",
    framework: "next",
    description: "test app",
    location: ".",
  };

  it("constructs its discovery agents through the caller's own AgentHooks and reports success", async () => {
    const backends = {
      __sentinel: "standalone-backends",
    } as unknown as AgentHooks["backends"];
    const mintCalls: string[] = [];

    const failed = await runWhiteboxAttackSurfaceApp(app, 0, {
      codebasePath: "/repo",
      model: {} as AIModel,
      session,
      surfaceIntegrationEnabled: false,
      isSingleAppRepo: true,
      umbrellaId: "umbrella",
      mintChildId: (name) => {
        mintCalls.push(name);
        return `wb-${mintCalls.length}`;
      },
      agentLimiter: (fn) => fn(),
      hooks: { backends },
      seams: inProcessSeams(),
    });

    expect(failed).toBe(false);
    expect(mintCalls).toEqual(["Pages", "API Endpoints"]);
    expect(mocks.codeAgentInputs).toHaveLength(2);
    expect(mocks.codeAgentInputs[0]?.backends).toBe(backends);
    expect(mocks.codeAgentInputs[1]?.backends).toBe(backends);
  });

  it("reports failure when a discovery agent throws, without throwing itself", async () => {
    mocks.consumeImpl = async (input) => {
      if (input.subagentName === "API Endpoints") {
        throw new Error("boom");
      }
      return { summary: "ok" };
    };

    const failed = await runWhiteboxAttackSurfaceApp(app, 0, {
      codebasePath: "/repo",
      model: {} as AIModel,
      session,
      surfaceIntegrationEnabled: false,
      isSingleAppRepo: true,
      umbrellaId: "umbrella",
      mintChildId: (name) => name,
      agentLimiter: (fn) => fn(),
      hooks: {},
      seams: inProcessSeams(),
    });

    expect(failed).toBe(true);
  });
});
