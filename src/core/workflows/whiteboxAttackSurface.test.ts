import { createHash } from "node:crypto";
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

import type { SubagentSpawner } from "../agents/offSecAgent/subagentSpawner";
import { CodeAgent } from "../agents/specialized/codeAgent/agent";

// Routes spawned "code" children through the mocked CodeAgent so tests can
// observe the inputs the spawner seam hands a child.
const codeSpawner: SubagentSpawner = {
  async spawn(opts) {
    const { spec, runtime } = opts;
    if (spec.type !== "code") throw new Error("unexpected spawn type");
    const agent = new CodeAgent({
      ...spec,
      backends: runtime.backends,
      subagentName: opts.subagentName,
    } as never);
    return (await agent.consume()) as never;
  },
  spawnMany: (items, worker) =>
    Promise.all(items.map((item, i) => worker(item, i))),
} as SubagentSpawner;

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
      subagentSpawner: codeSpawner,
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
      subagentSpawner: codeSpawner,
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
      subagentSpawner: codeSpawner,
      seams: inProcessSeams(),
    });

    expect(failed).toBe(true);
  });
});

describe("opt-in incremental recon on the existing root", () => {
  it("roundtrips unchanged, modified, deleted and new assets through real backend tools without app fanout", async () => {
    const { LocalBackends } = await import("../tools/backends/local");
    const { documentEndpoint } = await import(
      "../agents/offSecAgent/tools/documentEndpoint"
    );
    const { documentApp } = await import(
      "../agents/offSecAgent/tools/documentApp"
    );
    const { readFileSync, existsSync } = await import("node:fs");
    const ownedRoot = join(rootPath, "owned-sandbox");
    const assetsPath = join(ownedRoot, "assets");
    const backends = LocalBackends({
      session,
      subagentSpawner: codeSpawner,
      agentCwd: ownedRoot,
      fileWorkspaceRoot: ownedRoot,
    });
    const riskScore = {
      score: 4,
      explanation: "retained",
      breakdown: {
        exposure: 1,
        dataSensitivity: 1,
        functionCriticality: 1,
        securityIndicators: 1,
      },
    };
    const endpoints = ["unchanged", "modified", "deleted"].map((name) => ({
      method: "GET",
      path: `/${name}`,
      file: `${name}.ts`,
      description: name,
      authRequired: true,
      pentestObjectives: ["preserve objective"],
      threatModel: "retained threat model",
      riskScore,
    }));
    const metadata = {
      name: "API",
      type: "api" as const,
      framework: "Express",
      description: "original app",
      location: "api",
    };
    const existing = {
      repoType: "monorepo",
      packageManager: "bun",
      apps: [{ ...metadata, pages: [], apiEndpoints: endpoints }],
      summary: {
        totalApps: 1,
        totalPages: 0,
        totalApiEndpoints: 3,
        totalPentestObjectives: 3,
      },
    };
    for (const [name, record] of [
      ["app", metadata],
      ...endpoints.map((ep) => [
        ep.path.slice(1),
        { ...ep, routePath: ep.path, appName: "API" },
      ]),
    ] as Array<[string, unknown]>) {
      const result = await backends.fs.write(
        join(assetsPath, "api", `${name}.json`),
        JSON.stringify(record),
        { mode: "overwrite" },
      );
      expect(result.success).toBe(true);
    }
    const unchanged = readFileSync(
      join(assetsPath, "api", "unchanged.json"),
      "utf8",
    );
    const ctx = {
      session,
      subagentSpawner: codeSpawner,
      agentCwd: ownedRoot,
      fileWorkspaceRoot: ownedRoot,
      backends,
      attackSurfaceArtifactsPath: assetsPath,
    };
    const fanOut = { spawnMany: vi.fn() };
    const ids = {
      newSessionId: vi.fn(
        (name: string, ordinal: number) => `${name}:${ordinal}`,
      ),
    };
    mocks.consumeImpl = async (input) => {
      expect(input.subagentId).toBe("whitebox-apps-discovery:0");
      expect(input.excludeTools).toEqual([]);
      expect(input.attackSurfaceArtifactsPath).toBe(assetsPath);
      expect(input.objective).toContain("shared libraries");
      expect(input.objective).not.toContain(
        "(e.g. utility functions, configs, tests) → skip",
      );
      expect(input.objective).toContain("deleted");
      const path = join(assetsPath, "api", "modified.json");
      const original = JSON.parse((await backends.fs.readRaw(path)).content);
      await backends.fs.write(
        path,
        JSON.stringify({
          ...original,
          description: "changed by shared auth dependency",
          riskScore: undefined,
        }),
        { mode: "overwrite" },
      );
      await backends.fs.delete(join(assetsPath, "api", "deleted.json"));
      const app = documentApp(ctx);
      if (!app.execute) throw new Error("Missing document_app executor");
      await app.execute(
        {
          appName: "New app",
          appType: "api",
          framework: "Express",
          description: "new app",
          location: "new-app",
          toolCallDescription: "new app",
        } as never,
        {} as never,
      );
      const endpoint = documentEndpoint(ctx);
      if (!endpoint.execute)
        throw new Error("Missing document_endpoint executor");
      const output = await endpoint.execute(
        {
          appName: "New app",
          routePath: "/new",
          method: "GET",
          file: "new-app/route.ts",
          description: "new endpoint",
          riskLevel: "LOW",
          toolCallDescription: "new endpoint",
        } as never,
        {} as never,
      );
      expect(output).toMatchObject({ success: true });
      return {
        repoType: "monorepo",
        packageManager: "bun",
        changedApps: ["API", "New app"],
        addedEndpoints: 1,
        modifiedEndpoints: 1,
        removedEndpoints: 1,
        summary: "incremental",
      };
    };
    const result = await runWhiteboxAttackSurfaceWorkflow({
      codebasePath: ownedRoot,
      model: {} as AIModel,
      session,
      hooks: { backends },
      seams: inProcessSeams({ fanOut, ids }),
      incremental: {
        assetsPath,
        diffPath: join(ownedRoot, "diff.txt"),
        existingResult: existing,
      },
    });
    expect(fanOut.spawnMany).not.toHaveBeenCalled();
    expect(ids.newSessionId.mock.calls).toEqual([
      ["whitebox-apps-discovery", 0],
    ]);
    expect(mocks.codeAgentInputs).toHaveLength(1);
    const api = result.apps.find((app) => app.name === "API");
    if (!api) throw new Error("Missing retained API");
    expect(api.apiEndpoints.find((ep) => ep.path === "/unchanged")).toEqual(
      endpoints[0],
    );
    expect(
      readFileSync(join(assetsPath, "api", "unchanged.json"), "utf8"),
    ).toBe(unchanged);
    expect(api.apiEndpoints.find((ep) => ep.path === "/modified")).toEqual({
      ...endpoints[1],
      description: "changed by shared auth dependency",
    });
    expect(api.apiEndpoints.some((ep) => ep.path === "/deleted")).toBe(false);
    expect(
      result.apps.find((app) => app.name === "New app")?.apiEndpoints[0],
    ).toMatchObject({ path: "/new", file: "new-app/route.ts" });
    expect(existsSync(join(session.rootPath, "assets"))).toBe(false);
    expect(existsSync(join(session.rootPath, "apps"))).toBe(false);
  });

  it("leaves the unmarked schema, objective, tools and identity unchanged", async () => {
    const { AppsDiscoveryResultSchema, WHITEBOX_APPS_DISCOVERY_SYSTEM_PROMPT } =
      await import("../agents/specialized/whiteboxAttackSurface");
    const ids = {
      newSessionId: vi.fn(
        (name: string, ordinal: number) => `${name}:${ordinal}`,
      ),
    };
    mocks.consumeImpl = async () => ({
      repoType: "single-app",
      packageManager: "bun",
      apps: [],
    });
    await runWhiteboxAttackSurfaceWorkflow({
      codebasePath: "/repo",
      model: {} as AIModel,
      session,
      seams: inProcessSeams({ ids }),
    });
    const input = mocks.codeAgentInputs[0];
    expect(input.responseSchema).toBe(AppsDiscoveryResultSchema);
    expect(input.system).toBe(WHITEBOX_APPS_DISCOVERY_SYSTEM_PROMPT);
    expect(
      createHash("sha256").update(String(input.objective)).digest("hex"),
    ).toBe("3c3e60247a41caec90ecf55afb4a0c2b619175e2831d655d0e8a6929635fbc2e");
    expect(input.objective).toMatch(
      /^# Identify All Applications in the Repository/,
    );
    expect(input.objective).not.toContain("Incremental Attack Surface");
    expect(input.excludeTools).toEqual(["document_endpoint"]);
    expect(input).not.toHaveProperty("attackSurfaceArtifactsPath");
    expect(ids.newSessionId.mock.calls).toEqual([
      ["whitebox-apps-discovery", 0],
    ]);
  });
});

it("reads more than 500 endpoint artifacts through bounded owned-backend pages", async () => {
  const { LocalBackends } = await import("../tools/backends/local");
  const { mkdirSync, writeFileSync } = await import("node:fs");
  const ownedRoot = join(rootPath, "sandbox");
  const assetsPath = join(ownedRoot, "assets");
  mkdirSync(join(assetsPath, "api"), { recursive: true });
  writeFileSync(
    join(assetsPath, "api", "app.json"),
    JSON.stringify({
      name: "API",
      type: "api",
      framework: "Express",
      description: "large app",
      location: "api",
    }),
  );
  for (let index = 0; index < 513; index++)
    writeFileSync(
      join(assetsPath, "api", `asset_${index}.json`),
      JSON.stringify({
        method: "GET",
        routePath: `/route-${index}`,
        file: `route-${index}.ts`,
        pentestObjectives: [],
      }),
    );
  const backends = LocalBackends({
    session,
    agentCwd: ownedRoot,
    fileWorkspaceRoot: ownedRoot,
    subagentSpawner: codeSpawner,
  });
  const run = vi.spyOn(backends.command, "run");
  mocks.consumeImpl = async () => ({ changedApps: [] });
  const result = await runWhiteboxAttackSurfaceWorkflow({
    codebasePath: ownedRoot,
    model: {} as AIModel,
    session,
    hooks: { backends },
    incremental: {
      assetsPath,
      diffPath: join(ownedRoot, "diff"),
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
  });
  expect(result.apps[0].apiEndpoints).toHaveLength(513);
  expect(
    new Set(result.apps[0].apiEndpoints.map((endpoint) => endpoint.path)).size,
  ).toBe(513);
  expect(run).toHaveBeenCalledTimes(9);
});

it.each([
  "command-failure",
  "non-advancing",
  "short-final-page",
])("rejects incomplete artifact pagination: %s", async (failure) => {
  const { LocalBackends } = await import("../tools/backends/local");
  const backends = LocalBackends({
    session,
    agentCwd: rootPath,
    subagentSpawner: codeSpawner,
  });
  vi.spyOn(backends.fs, "list").mockResolvedValue({
    success: true,
    error: "",
    files: [],
    truncated: true,
    directory: rootPath,
    count: 500,
  });
  vi.spyOn(backends.command, "run").mockImplementation(async function* () {
    yield {
      type: "stdout",
      seq: 0,
      bytes: JSON.stringify({
        files: [],
        total: 501,
        next: failure === "short-final-page" ? null : 64,
      }),
    };
    yield {
      type: "end",
      exitCode: failure === "command-failure" ? 1 : 0,
      timedOut: false,
    };
  });
  mocks.consumeImpl = async () => ({ changedApps: [] });
  await expect(
    runWhiteboxAttackSurfaceWorkflow({
      codebasePath: rootPath,
      model: {} as AIModel,
      session,
      hooks: { backends },
      incremental: {
        assetsPath: rootPath,
        diffPath: join(rootPath, "diff"),
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
    }),
  ).rejects.toThrow(/enumeration|pagination/);
});
