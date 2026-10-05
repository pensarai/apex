import { describe, expect, it, vi } from "vitest";
import { AttackSurfaceRegistry } from "../findings/attackSurfaceRegistry";
import { FindingsRegistry } from "../findings/registry";
import * as concurrency from "../utils/concurrency";
import {
  assertDepth,
  type ConcurrencyRunner,
  DEFAULT_MAX_CONCURRENT_CHILDREN,
  DEFAULT_MAX_DEPTH,
  inProcessConcurrencyRunner,
  inProcessSeams,
  noopOrchestrationHooks,
  sharedBrowserSessionProvider,
  WorkflowLimitExceededError,
  withFindingPersistedHook,
} from "./seams";

describe("inProcessSeams", () => {
  it("defaults registries to fresh in-memory FindingsRegistry / AttackSurfaceRegistry instances", () => {
    const seams = inProcessSeams();

    const findings = seams.registries.findings();
    const attackSurface = seams.registries.attackSurface();

    expect(findings).toBeInstanceOf(FindingsRegistry);
    expect(attackSurface).toBeInstanceOf(AttackSurfaceRegistry);
    // Each call returns a fresh registry, not a shared singleton.
    expect(seams.registries.findings()).not.toBe(findings);
  });

  it("defaults ids to a fresh random session id, ignoring name/ordinal", () => {
    const seams = inProcessSeams();

    const first = seams.ids.newSessionId("worker", 0);
    const second = seams.ids.newSessionId("worker", 1);

    expect(first).not.toBe(second);
    expect(first.startsWith("ses_")).toBe(true);
  });

  it("defaults browser to no session for any scope", () => {
    const seams = inProcessSeams();
    expect(seams.browser.forChild({ subagentId: "child" })).toBeUndefined();
  });

  it("defaults hooks to no-ops", () => {
    expect(noopOrchestrationHooks.onEndpointStart).toBeUndefined();
    expect(noopOrchestrationHooks.onEndpointDone).toBeUndefined();
    expect(noopOrchestrationHooks.onEndpointFailed).toBeUndefined();
    expect(noopOrchestrationHooks.onFindingPersisted).toBeUndefined();
    expect(inProcessSeams().hooks).toBe(noopOrchestrationHooks);
  });

  it("defaults limits to depth 3 / the current bounded-pool width", () => {
    expect(inProcessSeams().limits).toEqual({
      maxDepth: DEFAULT_MAX_DEPTH,
      maxConcurrentChildren: DEFAULT_MAX_CONCURRENT_CHILDREN,
    });
    expect(DEFAULT_MAX_DEPTH).toBe(3);
    expect(DEFAULT_MAX_CONCURRENT_CHILDREN).toBe(10);
  });

  it("merges a partial limits override onto the defaults", () => {
    const seams = inProcessSeams({ limits: { maxDepth: 5 } as never });
    expect(seams.limits).toEqual({
      maxDepth: 5,
      maxConcurrentChildren: DEFAULT_MAX_CONCURRENT_CHILDREN,
    });
  });

  it("default fanOut delegates to the existing runWithBoundedConcurrency pool", async () => {
    const spy = vi.spyOn(concurrency, "runWithBoundedConcurrency");
    const seams = inProcessSeams();

    const results = await seams.fanOut.spawnMany(
      [1, 2, 3],
      async (n) => n * 2,
      { concurrency: 2 },
    );

    expect(results).toEqual([2, 4, 6]);
    expect(spy).toHaveBeenCalledTimes(1);
    expect(spy).toHaveBeenCalledWith(
      [1, 2, 3],
      2,
      expect.any(Function),
      undefined,
    );
    spy.mockRestore();
  });

  it("returns a custom registry provider unchanged", () => {
    const customFindings = new FindingsRegistry();
    const customAttackSurface = new AttackSurfaceRegistry();
    const registries = {
      findings: () => customFindings,
      attackSurface: () => customAttackSurface,
    };

    const seams = inProcessSeams({ registries });

    expect(seams.registries).toBe(registries);
    expect(seams.registries.findings()).toBe(customFindings);
    expect(seams.registries.attackSurface()).toBe(customAttackSurface);
  });

  it("routes spawnMany through a custom fanOut", async () => {
    const spawnMany = vi.fn(async (items: readonly unknown[]) =>
      items.map(() => "custom-result"),
    ) as unknown as ConcurrencyRunner["spawnMany"];
    const seams = inProcessSeams({ fanOut: { spawnMany } });

    const result = await seams.fanOut.spawnMany([1], async (n) => n, {
      concurrency: 1,
    });

    expect(spawnMany).toHaveBeenCalledTimes(1);
    expect(result).toEqual(["custom-result"]);
  });

  it("rejects a concurrency above maxConcurrentChildren, even for a custom fanOut", async () => {
    const spawnMany = vi.fn(async () => []);
    const seams = inProcessSeams({
      fanOut: { spawnMany },
      limits: { maxConcurrentChildren: 2 } as never,
    });

    await expect(
      seams.fanOut.spawnMany([1, 2, 3], async (n) => n, { concurrency: 3 }),
    ).rejects.toThrow(WorkflowLimitExceededError);
    expect(spawnMany).not.toHaveBeenCalled();
  });
});

describe("inProcessConcurrencyRunner", () => {
  it("honours the concurrency bound instead of running every item at once", async () => {
    let active = 0;
    let maxActive = 0;
    const items = [1, 2, 3, 4, 5];

    await inProcessConcurrencyRunner.spawnMany(
      items,
      async (n) => {
        active++;
        maxActive = Math.max(maxActive, active);
        await new Promise((resolve) => setTimeout(resolve, 5));
        active--;
        return n;
      },
      { concurrency: 2 },
    );

    expect(maxActive).toBeLessThanOrEqual(2);
  });
});

describe("assertDepth", () => {
  const limits = {
    maxDepth: DEFAULT_MAX_DEPTH,
    maxConcurrentChildren: DEFAULT_MAX_CONCURRENT_CHILDREN,
  };

  it("does not throw at or below maxDepth", () => {
    expect(() => assertDepth(0, limits)).not.toThrow();
    expect(() => assertDepth(3, limits)).not.toThrow();
  });

  it("throws WorkflowLimitExceededError past maxDepth", () => {
    expect(() => assertDepth(4, limits)).toThrow(WorkflowLimitExceededError);
  });
});

describe("sharedBrowserSessionProvider", () => {
  it("returns the same by-reference session for any child scope", () => {
    const session = { id: "shared" } as never;
    const provider = sharedBrowserSessionProvider(session);

    expect(provider.forChild({ subagentId: "a" })).toBe(session);
    expect(provider.forChild({ subagentId: "b", subagentName: "b-name" })).toBe(
      session,
    );
  });

  it("returns undefined when constructed without a session", () => {
    const provider = sharedBrowserSessionProvider();
    expect(provider.forChild({ subagentId: "a" })).toBeUndefined();
  });
});

describe("withFindingPersistedHook", () => {
  const finding = { title: "SQLi", endpoint: "/x" } as never;

  it("returns the registry unchanged when no hook is set", () => {
    const registry = new FindingsRegistry();
    expect(withFindingPersistedHook(registry, undefined)).toBe(registry);
  });

  it("invokes the hook after a non-duplicate register, and returns the same result", async () => {
    const seen: unknown[] = [];
    const registry = {
      size: 0,
      getFindings: () => [],
      isDuplicate: () => ({ duplicate: false }),
      register: async () => ({ duplicate: false, finding }),
      unregister: async () => {},
      groupByRootCause: async () => [],
    };

    const wrapped = withFindingPersistedHook(registry, async (f) => {
      seen.push(f);
    });
    const result = await wrapped.register(finding);

    expect(seen).toEqual([finding]);
    expect(result).toEqual({ duplicate: false, finding });
  });

  it("does not invoke the hook when register reports a duplicate", async () => {
    const seen: unknown[] = [];
    const registry = {
      size: 0,
      getFindings: () => [],
      isDuplicate: () => ({ duplicate: true }),
      register: async () => ({ duplicate: true }),
      unregister: async () => {},
      groupByRootCause: async () => [],
    };

    const wrapped = withFindingPersistedHook(registry, async (f) => {
      seen.push(f);
    });
    await wrapped.register(finding);

    expect(seen).toEqual([]);
  });

  it("delegates size/getFindings/isDuplicate/unregister/groupByRootCause unchanged", async () => {
    const registry = {
      size: 3,
      getFindings: vi.fn(() => [finding]),
      isDuplicate: vi.fn(() => ({ duplicate: false })),
      register: vi.fn(async () => ({ duplicate: false, finding })),
      unregister: vi.fn(async () => {}),
      groupByRootCause: vi.fn(async () => []),
    };

    const wrapped = withFindingPersistedHook(registry, async () => {});

    expect(wrapped.size).toBe(3);
    expect(wrapped.getFindings()).toEqual([finding]);
    expect(wrapped.isDuplicate(finding)).toEqual({ duplicate: false });
    await wrapped.unregister(finding);
    await wrapped.groupByRootCause();

    expect(registry.getFindings).toHaveBeenCalledTimes(1);
    expect(registry.isDuplicate).toHaveBeenCalledWith(finding);
    expect(registry.unregister).toHaveBeenCalledWith(finding);
    expect(registry.groupByRootCause).toHaveBeenCalledTimes(1);
  });
});
