/**
 * Work-count regression for the whitebox profile cache stampede: sixteen
 * concurrent same-session lookups must run one real profileCodebase walk
 * (and therefore one directory-read pass), not sixteen.
 */

import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";

const state = vi.hoisted(() => ({ profileCalls: 0, commandCalls: 0 }));

vi.mock("../../../whitebox", async () => {
  const actual =
    await vi.importActual<typeof import("../../../whitebox")>(
      "../../../whitebox",
    );
  return {
    ...actual,
    profileCodebase: async (
      rootPath: string,
      command?: Parameters<typeof actual.profileCodebase>[1],
    ) => {
      state.profileCalls++;
      return actual.profileCodebase(rootPath, command);
    },
  };
});

// profileCodebase walks the tree by shelling out through runCommandBounded
// (so it works against a sandbox command backend), not node:fs — count those
// executions to prove the wave coalesces into a single walk.
vi.mock("../../../whitebox/boundedProcess", async () => {
  const actual = await vi.importActual<
    typeof import("../../../whitebox/boundedProcess")
  >("../../../whitebox/boundedProcess");
  return {
    ...actual,
    runCommandBounded: async (
      ...args: Parameters<typeof actual.runCommandBounded>
    ) => {
      state.commandCalls++;
      return actual.runCommandBounded(...args);
    },
  };
});

import { queryWhiteboxCatalog } from "./queryWhiteboxCatalog";
import type { ToolContext } from "./types";

const fixtureRoot = mkdtempSync(join(tmpdir(), "whitebox-coalescing-"));

beforeAll(() => {
  for (let dir = 0; dir < 40; dir++) {
    const packageDir = join(fixtureRoot, `package-${dir}`);
    mkdirSync(packageDir);
    for (let file = 0; file < 8; file++) {
      writeFileSync(
        join(packageDir, `module-${file}.ts`),
        `export const value = ${file};\n`,
      );
    }
  }
  writeFileSync(
    join(fixtureRoot, "package.json"),
    JSON.stringify({ name: "fixture", scripts: { build: "fixture build" } }),
  );
});

afterAll(() => {
  rmSync(fixtureRoot, { recursive: true, force: true });
});

function invoke(sessionId: string): Promise<unknown> {
  const ctx = {
    session: { id: sessionId },
    agentCwd: fixtureRoot,
  } as unknown as ToolContext;
  return queryWhiteboxCatalog(ctx).execute?.(
    { query: "auth", limit: 3, toolCallDescription: "fixture" },
    { toolCallId: "tc_test", messages: [] },
  ) as Promise<unknown>;
}

describe("queryWhiteboxCatalog profile coalescing cost", () => {
  it("profiles a real fixture once for sixteen concurrent requests", async () => {
    state.profileCalls = 0;
    state.commandCalls = 0;
    const single = (await invoke("cost-calibration")) as {
      success: boolean;
      data: { records: unknown[] };
    };

    expect(single.success).toBe(true);
    expect(state.profileCalls).toBe(1);
    const singleCommandCalls = state.commandCalls;
    expect(singleCommandCalls).toBeGreaterThan(0);

    state.profileCalls = 0;
    state.commandCalls = 0;
    const wave = await Promise.all(
      Array.from({ length: 16 }, () => invoke("cost-wave")),
    );

    // One profile attempt and one filesystem-walk pass for the whole wave.
    expect(state.profileCalls).toBe(1);
    expect(state.commandCalls).toBe(singleCommandCalls);
    for (const output of wave) {
      expect(output).toEqual(single);
    }
  });
});
