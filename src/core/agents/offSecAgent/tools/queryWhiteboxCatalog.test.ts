import { afterEach, describe, expect, it, vi } from "vitest";
import type { RepoProfile } from "../../../whitebox";

const state = vi.hoisted(() => ({
  profileCalls: 0,
  fail: false,
  gate: null as Promise<void> | null,
  releases: [] as Array<() => void>,
}));

vi.mock("../../../whitebox", async () => {
  const actual =
    await vi.importActual<typeof import("../../../whitebox")>(
      "../../../whitebox",
    );
  return {
    ...actual,
    profileCodebase: async (rootPath: string) => {
      state.profileCalls++;
      if (state.gate) await state.gate;
      if (state.fail) throw new Error("fixture unavailable");
      return { rootPath, languages: ["typescript"] } as RepoProfile;
    },
  };
});

import { queryWhiteboxCatalog } from "./queryWhiteboxCatalog";
import type { ToolContext } from "./types";

interface ToolResult {
  success: boolean;
  summary: string;
  data: { records: unknown[] };
}

function makeCtx(sessionId: string, rootPath: string): ToolContext {
  return {
    session: { id: sessionId, config: {} },
    agentCwd: rootPath,
  } as unknown as ToolContext;
}

function invoke(
  sessionId: string,
  rootPath = "/fixture-root",
): Promise<unknown> {
  return queryWhiteboxCatalog(makeCtx(sessionId, rootPath)).execute?.(
    { query: "auth", limit: 3, toolCallDescription: "fixture" },
    { toolCallId: "tc_test", messages: [] },
  ) as Promise<unknown>;
}

function releaseGatedAttempts(): void {
  for (const release of state.releases.splice(0)) release();
}

afterEach(() => {
  releaseGatedAttempts();
  state.gate = null;
  state.fail = false;
  vi.restoreAllMocks();
});

describe("queryWhiteboxCatalog profile coalescing", () => {
  it("coalesces sixteen concurrent misses into one shared profile attempt", async () => {
    state.profileCalls = 0;
    state.gate = new Promise<void>((resolve) => state.releases.push(resolve));

    const wave = Array.from({ length: 16 }, () => invoke("stampede"));
    expect(state.profileCalls).toBe(1);
    releaseGatedAttempts();
    const outputs = (await Promise.all(wave)) as ToolResult[];

    expect(state.profileCalls).toBe(1);
    expect(outputs).toHaveLength(16);
    for (const output of outputs) {
      expect(output.success).toBe(true);
      expect(output).toEqual(outputs[0]);
    }

    // Warm hit: no further profiling after the wave completes.
    const warm = (await invoke("stampede")) as ToolResult;
    expect(state.profileCalls).toBe(1);
    expect(warm).toEqual(outputs[0]);
  });

  it("shares one failed attempt as the fallback and retries the next wave", async () => {
    state.profileCalls = 0;
    state.fail = true;
    state.gate = new Promise<void>((resolve) => state.releases.push(resolve));

    const wave = Array.from({ length: 16 }, () => invoke("failure-wave"));
    expect(state.profileCalls).toBe(1);
    releaseGatedAttempts();
    const outputs = (await Promise.all(wave)) as ToolResult[];

    // Every waiter gets the same undefined-profile fallback: the tool still
    // succeeds with catalog records, no observable error is introduced, and
    // nothing failed is retained in the completed cache.
    expect(state.profileCalls).toBe(1);
    for (const output of outputs) {
      expect(output.success).toBe(true);
      expect(output.data.records.length).toBeGreaterThan(0);
      expect(output).toEqual(outputs[0]);
    }

    state.fail = false;
    const retry = (await invoke("failure-wave")) as ToolResult;
    expect(state.profileCalls).toBe(2);
    expect(retry).toEqual(outputs[0]);

    const warm = (await invoke("failure-wave")) as ToolResult;
    expect(state.profileCalls).toBe(2);
    expect(warm).toEqual(outputs[0]);
  });

  it("preserves warm hits, TTL expiry, and session/root isolation", async () => {
    let fakeNow = 1_000_000;
    const dateSpy = vi.spyOn(Date, "now").mockImplementation(() => fakeNow);
    state.profileCalls = 0;

    try {
      await invoke("ttl-owner", "/root-a");
      await invoke("ttl-owner", "/root-a");
      expect(state.profileCalls).toBe(1);

      await invoke("another-owner", "/root-a");
      expect(state.profileCalls).toBe(2);
      await invoke("ttl-owner", "/root-b");
      expect(state.profileCalls).toBe(3);

      fakeNow += 45_001;
      await invoke("ttl-owner", "/root-a");
      expect(state.profileCalls).toBe(4);
    } finally {
      dateSpy.mockRestore();
    }
  });

  it("still evicts the oldest completed entry at the 16-entry cap", async () => {
    const fakeNow = 1_000_000;
    const dateSpy = vi.spyOn(Date, "now").mockImplementation(() => fakeNow);
    state.profileCalls = 0;

    try {
      for (let i = 0; i < 17; i++) {
        await invoke(`cap-owner-${i}`);
      }
      expect(state.profileCalls).toBe(17);

      // The oldest insertion (cap-owner-0) was evicted by the 17th; the 17th
      // itself stays warm.
      await invoke("cap-owner-0");
      expect(state.profileCalls).toBe(18);
      await invoke("cap-owner-16");
      expect(state.profileCalls).toBe(18);
    } finally {
      dateSpy.mockRestore();
    }
  });

  it("an abandoned waiter does not disturb the others' shared result", async () => {
    state.profileCalls = 0;
    state.gate = new Promise<void>((resolve) => state.releases.push(resolve));

    const wave = Array.from({ length: 4 }, () => invoke("abandoned"));
    // One caller drops its result entirely; the shared attempt must still
    // serve the remaining waiters and complete into the cache.
    void wave[0];
    releaseGatedAttempts();
    const outputs = (await Promise.all(wave.slice(1))) as ToolResult[];

    expect(state.profileCalls).toBe(1);
    for (const output of outputs) {
      expect(output.success).toBe(true);
      expect(output).toEqual(outputs[0]);
    }

    const warm = (await invoke("abandoned")) as ToolResult;
    expect(state.profileCalls).toBe(1);
    expect(warm).toEqual(outputs[0]);
  });
});
