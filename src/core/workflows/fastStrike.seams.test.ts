import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { SessionInfo } from "../session";
import {
  type EndpointScope,
  inProcessSeams,
  type OrchestrationHooks,
} from "./seams";

const mocks = vi.hoisted(() => ({
  fastStrikeInputs: [] as Array<Record<string, unknown>>,
  registry: {
    groupByRootCause: vi.fn(async () => []),
    getFindings: vi.fn(() => []),
    register: vi.fn(async (finding: unknown) => ({
      duplicate: false,
      finding,
    })),
    isDuplicate: vi.fn(() => ({ duplicate: false })),
    unregister: vi.fn(async () => {}),
    size: 0,
  },
  registryOptions: [] as Array<Record<string, unknown>>,
  consumeImpl: null as
    | ((input: Record<string, unknown>) => Promise<unknown>)
    | null,
}));

vi.mock("../agents/offSecAgent", () => ({
  PLAN_MODE_TOOL_NAMES: [],
  defineAgent: (def: unknown) => def,
  AgentRuntime: class {},
  OffensiveSecurityAgent: class {
    private readonly input: Record<string, unknown>;
    constructor(input: Record<string, unknown>) {
      this.input = input;
      mocks.fastStrikeInputs.push(input);
    }
    async consume() {
      if (mocks.consumeImpl) return mocks.consumeImpl(this.input);
      return { solved: false, summary: "no result" };
    }
  },
}));

vi.mock("../findings/registry", () => ({
  FindingsRegistry: {
    fromDirectory: (_path: string, options: Record<string, unknown>) => {
      mocks.registryOptions.push(options);
      return mocks.registry;
    },
  },
}));

import { runFastStrike } from "./fastStrike";
import type { PentestWorkflowInput } from "./pentest";

let rootPath: string;
let session: SessionInfo;

beforeEach(() => {
  rootPath = mkdtempSync(join(tmpdir(), "faststrike-seams-"));
  session = {
    id: "ses_faststrike_seams",
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
  mocks.fastStrikeInputs.length = 0;
  mocks.registryOptions.length = 0;
  mocks.consumeImpl = null;
  vi.restoreAllMocks();
  rmSync(rootPath, { recursive: true, force: true });
});

describe("runFastStrike — default seams are byte-identical", () => {
  it("builds the findings registry through FindingsRegistry.fromDirectory, same as before", async () => {
    await runFastStrike({
      target: "https://example.com",
      model: {} as PentestWorkflowInput["model"],
      session,
    });

    expect(mocks.registryOptions).toContainEqual(
      expect.objectContaining({ sessionId: session.id }),
    );
  });
});

describe("runFastStrike — custom seams", () => {
  it("uses a caller-supplied registries provider instead of the default fromDirectory closure", async () => {
    const findings = vi.fn(() => mocks.registry);

    await runFastStrike({
      target: "https://example.com",
      model: {} as PentestWorkflowInput["model"],
      session,
      seams: inProcessSeams({
        registries: { findings, attackSurface: () => ({}) as never },
      }),
    });

    expect(findings).toHaveBeenCalledTimes(1);
    expect(mocks.registryOptions).toHaveLength(0);
  });

  it("fires onEndpointStart/onEndpointDone and onFindingPersisted on a non-duplicate register", async () => {
    mocks.consumeImpl = async (input) => {
      const registry = input.findingsRegistry as {
        register: (f: unknown) => Promise<unknown>;
      };
      await registry.register({ title: "RCE", endpoint: "/x" });
      return { solved: true, summary: "got it" };
    };

    const events: string[] = [];
    const findingsSeen: unknown[] = [];
    const hooks: OrchestrationHooks = {
      onEndpointStart: (scope: EndpointScope) => {
        events.push(`start:${scope.target}`);
      },
      onEndpointDone: (scope: EndpointScope) => {
        events.push(`done:${scope.target}`);
      },
      onEndpointFailed: (scope: EndpointScope) => {
        events.push(`failed:${scope.target}`);
      },
      onFindingPersisted: (finding) => {
        findingsSeen.push(finding);
      },
    };

    await runFastStrike({
      target: "https://example.com",
      model: {} as PentestWorkflowInput["model"],
      session,
      seams: inProcessSeams({
        hooks,
        registries: {
          findings: () => mocks.registry,
          attackSurface: () => ({}) as never,
        },
      }),
    });

    expect(events).toEqual([
      "start:https://example.com",
      "done:https://example.com",
    ]);
    expect(findingsSeen).toEqual([{ title: "RCE", endpoint: "/x" }]);
  });

  it("fires onEndpointFailed and rethrows when the operator agent throws", async () => {
    mocks.consumeImpl = async () => {
      throw new Error("blocked");
    };

    const events: string[] = [];
    const hooks: OrchestrationHooks = {
      onEndpointStart: (scope: EndpointScope) => {
        events.push(`start:${scope.target}`);
      },
      onEndpointFailed: (scope: EndpointScope, error: unknown) => {
        events.push(`failed:${scope.target}:${(error as Error).message}`);
      },
    };

    await expect(
      runFastStrike({
        target: "https://example.com",
        model: {} as PentestWorkflowInput["model"],
        session,
        seams: inProcessSeams({
          hooks,
          registries: {
            findings: () => mocks.registry,
            attackSurface: () => ({}) as never,
          },
        }),
      }),
    ).rejects.toThrow("blocked");

    expect(events).toEqual([
      "start:https://example.com",
      "failed:https://example.com:blocked",
    ]);
  });
});
