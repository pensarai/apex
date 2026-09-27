import {
  chmod,
  mkdir,
  mkdtemp,
  readdir,
  rm,
  symlink,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, relative } from "node:path";
import { afterAll, describe, expect, it } from "vitest";
import { type ListFilesResult, listFiles, listRecursive } from "./listFiles";
import type { ToolContext } from "./types";

type ListFilesExecute = NonNullable<ReturnType<typeof listFiles>["execute"]>;
type ExecuteOutput = Awaited<ReturnType<ListFilesExecute>>;

/** The tool never streams; collapse the SDK's result union for assertions. */
async function callListFiles(
  ctx: ToolContext,
  input: Record<string, unknown>,
): Promise<ListFilesResult> {
  const execute = listFiles(ctx).execute;
  if (!execute) throw new Error("list_files tool has no execute");
  const output: ExecuteOutput = await execute(
    { toolCallDescription: "test", ...input } as never,
    { toolCallId: "test" } as never,
  );
  return output as ListFilesResult;
}

const MAX_RECURSIVE = 200;
const MAX_NON_RECURSIVE = 500;

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

/**
 * Abort deterministically at the Nth cancellation checkpoint: the wrapped
 * signal schedules the abort in a microtask fired while the checkpoint's
 * next awaited filesystem call is still in flight. Checkpoint numbers count
 * checks that ran, including the one that threw.
 */
function signalAbortingAtCheckpoint(checkpoint: number): {
  signal: AbortSignal;
  checkpoints: () => number;
} {
  const controller = new AbortController();
  const original = controller.signal.throwIfAborted.bind(controller.signal);
  let seen = 0;
  controller.signal.throwIfAborted = () => {
    if (++seen === checkpoint) {
      queueMicrotask(() => controller.abort(new Error("test cancellation")));
    }
    original();
  };
  return { signal: controller.signal, checkpoints: () => seen };
}

function mockCtx(root: string, signal?: AbortSignal): ToolContext {
  return {
    agentCwd: root,
    abortSignal: signal,
    session: {
      id: "ses_test",
      version: "1.0.0",
      targets: [],
      time: { created: Date.now(), updated: Date.now() },
      rootPath: root,
      logsPath: join(root, "logs"),
      findingsPath: join(root, "findings"),
      scratchpadPath: join(root, "scratchpad"),
      pocsPath: join(root, "pocs"),
      config: {},
    },
  } as unknown as ToolContext;
}

/**
 * The unbounded baseline walk: full-tree readdir DFS, exact total, first-N
 * cap applied after the fact. The bounded implementation must reproduce this
 * walk's first-N paths on the same runtime, where readdir order is shared.
 */
async function referenceListing(
  dir: string,
  maxEntries: number,
): Promise<{ paths: string[]; total: number }> {
  const results: string[] = [];
  let total = 0;

  async function walk(current: string) {
    let entries: import("fs").Dirent[];
    try {
      entries = await readdir(current, { withFileTypes: true });
    } catch {
      return;
    }
    for (const entry of entries) {
      total++;
      const fullPath = join(current, entry.name);
      if (entry.isDirectory()) {
        if (results.length < maxEntries) results.push(`${fullPath}/`);
        await walk(fullPath);
      } else if (results.length < maxEntries) {
        results.push(fullPath);
      }
    }
  }

  await walk(dir);
  return { paths: results, total };
}

function toRelative(base: string, paths: string[]): string[] {
  return paths.map((p) => {
    const isDir = p.endsWith("/");
    const rel = relative(base, isDir ? p.slice(0, -1) : p);
    return isDir ? `${rel}/` : rel;
  });
}

async function makeFlat(
  dir: string,
  count: number,
  prefix = "f",
): Promise<void> {
  for (let i = 0; i < count; i++) {
    await writeFile(
      join(dir, `${prefix}-${String(i).padStart(5, "0")}.txt`),
      "",
    );
  }
}

describe("listFiles recursive listing", () => {
  it("returns the same full listing as the unbounded walk for small trees", async () => {
    const root = await tempRoot("apex-list-small-");
    await mkdir(join(root, "a", "b"), { recursive: true });
    await writeFile(join(root, "a", "b", "leaf.txt"), "");
    await writeFile(join(root, "a", "mid.txt"), "");
    await writeFile(join(root, ".hidden"), "");
    await writeFile(join(root, "top.txt"), "");

    const result = await callListFiles(mockCtx(root), {
      directory: root,
      recursive: true,
    });

    const reference = await referenceListing(root, MAX_RECURSIVE);
    expect(result.success).toBe(true);
    expect(result.files).toEqual(toRelative(root, reference.paths));
    expect(result.truncated).toBeUndefined();
    expect(result.totalFound).toBeUndefined();
    expect(result.totalFoundLowerBound).toBeUndefined();
    expect(result.count).toBe(reference.total);
  });

  it("stops at the 201st path witness and reports an explicit lower bound", async () => {
    const root = await tempRoot("apex-list-witness-");
    for (let d = 0; d < 10; d++) {
      const dir = join(root, `d${String(d).padStart(2, "0")}`);
      await mkdir(dir, { recursive: true });
      await makeFlat(dir, 25);
    }

    const result = await callListFiles(mockCtx(root), {
      directory: root,
      recursive: true,
    });

    const reference = await referenceListing(root, MAX_RECURSIVE);
    expect(reference.total).toBeGreaterThan(MAX_RECURSIVE);
    expect(result.success).toBe(true);
    expect(result.files).toEqual(
      toRelative(root, reference.paths.slice(0, MAX_RECURSIVE)),
    );
    expect(result.count).toBe(MAX_RECURSIVE);
    expect(result.truncated).toBe(true);
    // The walk never learns the real total; 201 is the honest lower bound.
    expect(result.totalFound).toBe(MAX_RECURSIVE + 1);
    expect(result.totalFoundLowerBound).toBe(true);
    expect(result.error).toBe(
      "Listing truncated at 200 entries — narrow the directory or use grep",
    );
  });

  it("lists exactly 200 entries without truncating, ending on a directory", async () => {
    // A chain of 200 single-child directories: the 200th accepted path is a
    // directory whose own (empty) readdir is the final enumeration, and no
    // overflow witness is ever collected.
    const root = await tempRoot("apex-list-exact200-");
    let deep = root;
    for (let i = 0; i < 200; i++) {
      deep = join(deep, "d");
      await mkdir(deep, { recursive: true });
    }

    const result = await callListFiles(mockCtx(root), {
      directory: root,
      recursive: true,
    });
    const reference = await referenceListing(root, MAX_RECURSIVE);
    expect(reference.total).toBe(MAX_RECURSIVE);
    expect(result.success).toBe(true);
    expect(result.files).toEqual(toRelative(root, reference.paths));
    expect(result.count).toBe(MAX_RECURSIVE);
    expect(result.truncated).toBeUndefined();
    expect(result.totalFound).toBeUndefined();
    expect(result.error).toBe("");
    expect(result.files.at(-1)?.endsWith("d/")).toBe(true);
  });

  it("rejects when cancellation lands during an empty final readdir", async () => {
    const root = await tempRoot("apex-list-abort-empty-");
    const { signal, checkpoints } = signalAbortingAtCheckpoint(1);
    // Checkpoint 1 is the walk-entry check; the abort fires while the root's
    // (empty) readdir is in flight, so only a post-enumeration check can
    // observe it.
    await expect(listRecursive(root, MAX_RECURSIVE, signal)).rejects.toThrow(
      /test cancellation/,
    );
    expect(checkpoints()).toBe(2);
  });

  it("rejects when cancellation lands during a rejected readdir", async () => {
    const root = await tempRoot("apex-list-abort-reject-");
    const { signal, checkpoints } = signalAbortingAtCheckpoint(1);
    // The missing directory makes readdir reject; the catch must not swallow
    // the cancellation that landed alongside the error.
    await expect(
      listRecursive(join(root, "missing"), MAX_RECURSIVE, signal),
    ).rejects.toThrow(/test cancellation/);
    expect(checkpoints()).toBe(2);
  });

  it("fails the public listing when cancellation lands during its readdir", async () => {
    const root = await tempRoot("apex-list-abort-public-");
    // Checkpoints: 1 = execute entry, 2 = recursive-branch entry, 3 = the
    // walk entry; the abort fires while the root's readdir is in flight and
    // the post-enumeration check must turn it into a failed listing.
    const { signal } = signalAbortingAtCheckpoint(3);
    const result = await callListFiles(mockCtx(root, signal), {
      directory: root,
      recursive: true,
    });
    expect(result.success).toBe(false);
    expect(result.files).toEqual([]);
    expect(result.error).toMatch(/test cancellation/);
  });

  it("preserves first-200 parity for trees mixing deep chains, wide dirs, and hidden files", async () => {
    const root = await tempRoot("apex-list-mixed-");
    let deep = root;
    for (let i = 0; i < 40; i++) {
      deep = join(deep, `lvl${String(i).padStart(2, "0")}`);
      await mkdir(deep, { recursive: true });
      await writeFile(
        join(deep, `chain-${String(i).padStart(2, "0")}.txt`),
        "",
      );
    }
    for (let d = 0; d < 3; d++) {
      const dir = join(root, `wide-${String(d).padStart(2, "0")}`);
      await mkdir(dir, { recursive: true });
      await makeFlat(dir, 60, `w${d}`);
    }
    await writeFile(join(root, ".dotfile"), "");

    const result = await callListFiles(mockCtx(root), {
      directory: root,
      recursive: true,
    });
    const reference = await referenceListing(root, MAX_RECURSIVE);
    expect(result.truncated).toBe(true);
    expect(result.files).toEqual(
      toRelative(root, reference.paths.slice(0, MAX_RECURSIVE)),
    );
  });

  it("walks deep chains without a depth cap and truncates at the witness", async () => {
    const root = await tempRoot("apex-list-deep-");
    let deep = root;
    for (let i = 0; i < 150; i++) {
      deep = join(deep, `d${String(i).padStart(3, "0")}`);
      await mkdir(deep, { recursive: true });
      await writeFile(join(deep, `f${String(i).padStart(3, "0")}.txt`), "");
    }

    const result = await callListFiles(mockCtx(root), {
      directory: root,
      recursive: true,
    });
    const reference = await referenceListing(root, MAX_RECURSIVE);
    expect(reference.total).toBe(2 * 150);
    expect(result.truncated).toBe(true);
    expect(result.files).toEqual(
      toRelative(root, reference.paths.slice(0, MAX_RECURSIVE)),
    );
  });

  it.skipIf(process.platform === "win32")(
    "lists symlinks as files without descending them",
    async () => {
      const root = await tempRoot("apex-list-symlink-");
      const target = await tempRoot("apex-list-symlink-target-");
      await makeFlat(target, 10);
      await writeFile(join(root, "real.txt"), "");
      await symlink(target, join(root, "link-to-dir"));
      await symlink(join(target, "f-00000.txt"), join(root, "link-to-file"));

      const result = await callListFiles(mockCtx(root), {
        directory: root,
        recursive: true,
      });
      const reference = await referenceListing(root, MAX_RECURSIVE);
      expect(result.files).toEqual(toRelative(root, reference.paths));
      expect(result.files.some((f) => f === "link-to-dir/")).toBe(false);
      expect(result.files).toContain("link-to-dir");
      expect(result.files).toContain("link-to-file");
    },
  );

  it.skipIf(process.platform === "win32" || (process.getuid?.() ?? 1) === 0)(
    "skips unreadable directories and keeps walking",
    async () => {
      const root = await tempRoot("apex-list-eacces-");
      const locked = join(root, "locked");
      await mkdir(locked, { recursive: true });
      await makeFlat(locked, 5);
      await writeFile(join(root, "open.txt"), "");
      await chmod(locked, 0o000);
      try {
        const result = await callListFiles(mockCtx(root), {
          directory: root,
          recursive: true,
        });
        const reference = await referenceListing(root, MAX_RECURSIVE);
        expect(result.files).toEqual(toRelative(root, reference.paths));
        expect(result.files).toContain("open.txt");
        // The directory entry itself is reachable; only its contents are not.
        expect(result.files).toContain("locked/");
        expect(result.files.some((f) => f.startsWith("locked/f-"))).toBe(false);
      } finally {
        await chmod(locked, 0o755);
      }
    },
  );

  it("returns an empty listing for an empty directory", async () => {
    const root = await tempRoot("apex-list-empty-");
    const result = await callListFiles(mockCtx(root), {
      directory: root,
      recursive: true,
    });
    expect(result.success).toBe(true);
    expect(result.files).toEqual([]);
    expect(result.count).toBe(0);
    expect(result.truncated).toBeUndefined();
    expect(result.error).toBe("");
  });

  it("rejects before any work when the signal is already aborted", async () => {
    const root = await tempRoot("apex-list-abort-pre-");
    const controller = new AbortController();
    controller.abort();
    await expect(
      callListFiles(mockCtx(root, controller.signal), {
        directory: root,
        recursive: true,
      }),
    ).rejects.toThrow(/abort/i);
  });

  it("stops between work units when aborted mid-walk", async () => {
    const root = await tempRoot("apex-list-abort-mid-");
    for (let d = 0; d < 10; d++) {
      const dir = join(root, `d${String(d).padStart(2, "0")}`);
      await mkdir(dir, { recursive: true });
      await makeFlat(dir, 5);
    }
    const controller = new AbortController();

    // Abort lands synchronously after the walk starts but before any awaited
    // readdir or stat resolves, so the next checkpoint must cancel it.
    const pending = callListFiles(mockCtx(root, controller.signal), {
      directory: root,
      recursive: true,
    });
    controller.abort();
    const result = await pending;
    expect(result.success).toBe(false);
    expect(result.files).toEqual([]);
    expect(result.error).toMatch(/abort/i);

    const pendingWalk = listRecursive(root, MAX_RECURSIVE, controller.signal);
    await expect(pendingWalk).rejects.toThrow(/abort/i);
  });

  it("ignores hostile limit parameters", async () => {
    const root = await tempRoot("apex-list-hostile-");
    for (let d = 0; d < 5; d++) {
      const dir = join(root, `d${String(d).padStart(2, "0")}`);
      await mkdir(dir, { recursive: true });
      await makeFlat(dir, 50);
    }
    const result = await callListFiles(mockCtx(root), {
      directory: root,
      recursive: true,
      maxEntries: 10_000_000,
      limit: 10_000_000,
      maxRecursiveEntries: 10_000_000,
    });
    expect(result.success).toBe(true);
    expect(result.count).toBe(MAX_RECURSIVE);
    expect(result.truncated).toBe(true);
    expect(result.totalFound).toBe(MAX_RECURSIVE + 1);
  });

  it("fails with the baseline error for a non-directory path", async () => {
    const root = await tempRoot("apex-list-notdir-");
    await writeFile(join(root, "plain.txt"), "x");
    const result = await callListFiles(mockCtx(root), {
      directory: join(root, "plain.txt"),
      recursive: true,
    });
    expect(result.success).toBe(false);
    expect(result.error).toContain("is not a directory");
  });
});

describe("listFiles flat listing", () => {
  it("lists a small directory exactly like before", async () => {
    const root = await tempRoot("apex-list-flat-small-");
    await mkdir(join(root, "sub"), { recursive: true });
    await makeFlat(root, 5);
    const result = await callListFiles(mockCtx(root), {
      directory: root,
      recursive: false,
    });
    const entries = await readdir(root, { withFileTypes: true });
    const expected = entries.map((e) => {
      const name = e.isDirectory() ? `${e.name}/` : e.name;
      return name;
    });
    expect(result.success).toBe(true);
    expect(result.files).toEqual(expected);
    expect(result.truncated).toBeUndefined();
    expect(result.totalFound).toBeUndefined();
    expect(result.error).toBe("");
  });

  it("truncates at 500 with the exact total it already paid for", async () => {
    const root = await tempRoot("apex-list-flat-600-");
    await makeFlat(root, 600);
    const result = await callListFiles(mockCtx(root), {
      directory: root,
      recursive: false,
    });
    const entries = await readdir(root, { withFileTypes: true });
    const expected = entries.slice(0, MAX_NON_RECURSIVE).map((e) => e.name);
    expect(result.success).toBe(true);
    expect(result.files).toEqual(expected);
    expect(result.count).toBe(MAX_NON_RECURSIVE);
    expect(result.truncated).toBe(true);
    expect(result.totalFound).toBe(600);
    expect(result.totalFoundLowerBound).toBeUndefined();
    expect(result.error).toBe("Showing 500 of 600 entries");
  });

  it("lists exactly 500 entries without truncating", async () => {
    const root = await tempRoot("apex-list-flat-exact500-");
    await makeFlat(root, MAX_NON_RECURSIVE);
    const result = await callListFiles(mockCtx(root), {
      directory: root,
      recursive: false,
    });
    const entries = await readdir(root, { withFileTypes: true });
    expect(result.success).toBe(true);
    expect(result.files).toEqual(entries.map((e) => e.name));
    expect(result.count).toBe(MAX_NON_RECURSIVE);
    expect(result.truncated).toBeUndefined();
    expect(result.totalFound).toBeUndefined();
    expect(result.error).toBe("");
  });

  it("keeps huge flat directories' output identical to the uncap-then-slice baseline", async () => {
    const root = await tempRoot("apex-list-flat-5000-");
    await makeFlat(root, 5_000);
    const result = await callListFiles(mockCtx(root), {
      directory: root,
      recursive: false,
    });
    const entries = await readdir(root, { withFileTypes: true });
    expect(result.files).toEqual(
      entries.slice(0, MAX_NON_RECURSIVE).map((e) => e.name),
    );
    expect(result.truncated).toBe(true);
    expect(result.totalFound).toBe(5_000);
    expect(result.count).toBe(MAX_NON_RECURSIVE);
  });
});
