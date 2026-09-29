import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, describe, expect, it, vi } from "vitest";
import type { ToolContext } from "./types";

/**
 * Public-path work instrumentation for list_files. The passthrough spy wraps
 * node:fs/promises.readdir so every directory the production tool actually
 * reads is measured: how many readdirs ran, how many entries the runtime
 * materialized (the width-dependent native cost readdir always pays), and
 * how many entries the tool's JS loop actually consumed. Only the public
 * execute path is invoked — no result-API metrics, no helper calls.
 */
const counters = vi.hoisted(() => ({
  readdirCalls: 0,
  nativeEnumerated: 0,
  consumed: 0,
}));

vi.mock("node:fs/promises", async (importOriginal) => {
  const actual = await importOriginal<typeof import("node:fs/promises")>();
  return {
    ...actual,
    readdir: (async (...args: Parameters<typeof actual.readdir>) => {
      const result = await actual.readdir(...args);
      if (!Array.isArray(result)) return result;
      counters.readdirCalls++;
      counters.nativeEnumerated += result.length;
      // Count only what the caller iterates; slice/map on the non-recursive
      // path still reads the underlying array directly.
      return new Proxy(result, {
        get(target, prop, receiver) {
          if (prop === Symbol.iterator) {
            return function* counted() {
              for (const entry of target) {
                counters.consumed++;
                yield entry;
              }
            };
          }
          const value = Reflect.get(target, prop, receiver);
          return typeof value === "function" ? value.bind(target) : value;
        },
      }) as typeof result;
    }) as typeof actual.readdir,
  };
});

import { type ListFilesResult, listFiles } from "./listFiles";

const MAX_RECURSIVE = 200;

const fixtureRoots: string[] = [];

async function tempRoot(prefix: string): Promise<string> {
  const root = await mkdtemp(join(tmpdir(), prefix));
  fixtureRoots.push(root);
  return root;
}

afterAll(async () => {
  await Promise.all(
    fixtureRoots.map((root) => rm(root, { recursive: true, force: true })),
  );
});

function mockCtx(root: string): ToolContext {
  return { agentCwd: root } as unknown as ToolContext;
}

async function callListFiles(
  root: string,
  input: Record<string, unknown>,
): Promise<ListFilesResult> {
  const execute = listFiles(mockCtx(root)).execute;
  if (!execute) throw new Error("list_files tool has no execute");
  return (await execute(
    { toolCallDescription: "test", ...input } as never,
    { toolCallId: "test" } as never,
  )) as ListFilesResult;
}

function resetCounters(): void {
  counters.readdirCalls = 0;
  counters.nativeEnumerated = 0;
  counters.consumed = 0;
}

describe("list_files public-path readdir work", () => {
  it("stops the JS loop at the witness while enumerating only visited directories", async () => {
    const root = await tempRoot("apex-list-count-witness-");
    for (let d = 0; d < 10; d++) {
      const dir = join(root, `d${String(d).padStart(2, "0")}`);
      await mkdir(dir, { recursive: true });
      for (let i = 0; i < 25; i++) {
        await writeFile(join(dir, `f-${String(i).padStart(4, "0")}.txt`), "");
      }
    }

    resetCounters();
    const result = await callListFiles(root, {
      directory: root,
      recursive: true,
    });

    // The walk examined exactly maxEntries + 1 entries, then stopped. The
    // passthrough counter sees iterator pulls, which include the one boundary
    // pull each active for-of loop performs before its return check — the
    // witness landed inside dir8, so dir8's loop and the root loop each pull
    // once more while unwinding: 201 examined + 2 pulls.
    expect(counters.consumed).toBe(MAX_RECURSIVE + 3);
    expect(counters.readdirCalls).toBe(9);
    expect(counters.nativeEnumerated).toBe(210);
    expect(result.truncated).toBe(true);
    expect(result.count).toBe(MAX_RECURSIVE);
  });

  it("measures the retained width cost of a hostile huge flat directory", async () => {
    const root = await tempRoot("apex-list-count-hugeflat-");
    await mkdir(root, { recursive: true });
    for (let i = 0; i < 2_000; i++) {
      await writeFile(join(root, `f-${String(i).padStart(6, "0")}.txt`), "");
    }

    resetCounters();
    const result = await callListFiles(root, {
      directory: root,
      recursive: true,
    });

    // One readdir materializes the whole directory (2,000 entries — the
    // runtime's eager enumeration, retained cost by design); the JS loop
    // examines the witness (201) plus one boundary pull before returning.
    expect(counters.readdirCalls).toBe(1);
    expect(counters.nativeEnumerated).toBe(2_000);
    expect(counters.consumed).toBe(MAX_RECURSIVE + 2);
    expect(result.truncated).toBe(true);
  });

  it("enumerates exactly its own directories for an untruncated walk", async () => {
    const root = await tempRoot("apex-list-count-exact200-");
    let deep = root;
    for (let i = 0; i < 200; i++) {
      deep = join(deep, "d");
      await mkdir(deep, { recursive: true });
    }

    resetCounters();
    const result = await callListFiles(root, {
      directory: root,
      recursive: true,
    });

    expect(counters.consumed).toBe(MAX_RECURSIVE);
    // 201 readdirs: root plus 200 accepted directories, including the final
    // (empty) one — at most maxEntries + 1 attempts.
    expect(counters.readdirCalls).toBe(MAX_RECURSIVE + 1);
    expect(counters.nativeEnumerated).toBe(MAX_RECURSIVE);
    expect(result.truncated).toBeUndefined();
    expect(result.count).toBe(MAX_RECURSIVE);
  });
});
