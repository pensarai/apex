import pLimit from "p-limit";
import { beforeEach, describe, expect, it, vi } from "vitest";
import type { ConsolidatedEndpoint } from "../../../integrations/surface/types";
import type { SessionInfo } from "../../../session";
import { runWithBoundedConcurrency } from "../../../utils/concurrency";
import type { AppInfo } from "./types";

// Tracks how many mocked CodeAgent runs are executing at once so we can assert
// the workflow's shared limiter actually bounds total concurrency.
const tracker = vi.hoisted(() => {
  let live = 0;
  let peak = 0;
  let total = 0;
  return {
    reset() {
      live = 0;
      peak = 0;
      total = 0;
    },
    get peak() {
      return peak;
    },
    get total() {
      return total;
    },
    async run() {
      live++;
      total++;
      if (live > peak) peak = live;
      // Hold the "slot" across a macrotask so concurrent runs actually overlap.
      await new Promise((r) => setTimeout(r, 1));
      live--;
    },
  };
});

vi.mock("../codeAgent/agent", () => ({
  CodeAgent: class {
    async consume() {
      await tracker.run();
      return { summary: "ok", endpointsDocumented: 1 };
    }
  },
}));

import { runAppEndpointDocumentation } from "./endpointDocumentationAgent";

const NUM_APPS = 50;
const ENDPOINTS_PER_APP = 100;
const CAP = 12;
// Mirror the workflow's Phase 2 app-level fan-out (DEFAULT_CONCURRENCY) and the
// per-app endpoint fan-out (ENDPOINT_DOCUMENTATION_CONCURRENCY) so the control
// reproduces the real pre-fix peak (APP_CONCURRENCY * ENDPOINT_CONCURRENCY).
const APP_CONCURRENCY = 5;

function makeApp(name: string): AppInfo {
  return {
    name,
    framework: "express",
    description: "synthetic",
    location: `apps/${name}`,
    type: "api",
  };
}

function makeEndpoints(n: number, appName: string): ConsolidatedEndpoint[] {
  return Array.from({ length: n }, (_, i) => ({
    method: ["GET"],
    kind: "api",
    path: `/api/${appName}/r${i}`,
    handler: "handler",
    file: `apps/${appName}/r${i}.ts`,
    line: i + 1,
    framework: "express",
    auth: [],
    internal: false,
  }));
}

async function runAllApps(
  agentLimiter?: <T>(fn: () => Promise<T>) => Promise<T>,
): Promise<void> {
  const apps = Array.from({ length: NUM_APPS }, (_, a) => `app${a}`);
  // Same two-level nesting the workflow uses: up to APP_CONCURRENCY apps run at
  // once, each documenting its endpoints. The shared `agentLimiter` (when given)
  // is the only thing bounding the *total* across apps.
  await runWithBoundedConcurrency(apps, APP_CONCURRENCY, (name) =>
    runAppEndpointDocumentation({
      codebasePath: "/repo",
      app: makeApp(name),
      endpoints: makeEndpoints(ENDPOINTS_PER_APP, name),
      frameworks: ["express"],
      model: "test-model",
      session: {} as unknown as SessionInfo,
      agentLimiter,
    }),
  );
}

describe("endpoint documentation concurrency (50 apps x 100 endpoints)", () => {
  beforeEach(() => tracker.reset());

  it("bounds total concurrent agents to the shared limiter across all apps", async () => {
    const slots = pLimit(CAP);
    const agentLimiter = <T>(fn: () => Promise<T>): Promise<T> => slots(fn);

    await runAllApps(agentLimiter);

    // All 5000 endpoints were processed...
    expect(tracker.total).toBe(NUM_APPS * ENDPOINTS_PER_APP);
    // ...but never more than CAP ran at once, regardless of app count.
    expect(tracker.peak).toBeLessThanOrEqual(CAP);
  });

  it("control: without the shared limiter concurrency multiplies past the cap", async () => {
    await runAllApps(undefined);

    expect(tracker.total).toBe(NUM_APPS * ENDPOINTS_PER_APP);
    // Pre-fix peak = APP_CONCURRENCY (5) * ENDPOINT_DOCUMENTATION_CONCURRENCY
    // (10) = ~50, independent of how many endpoints — and it grows with more
    // apps allowed in flight. Well above the bounded cap.
    expect(tracker.peak).toBeGreaterThanOrEqual(APP_CONCURRENCY * 8);
  });
});
