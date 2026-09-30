/**
 * PR08 benchmark: stop recursive listing after its result limit.
 *
 * Runs the production list_files tool over two fixtures:
 *   - deep: a 400-level chain (800 entries) — the old walk visited every
 *     level to produce an exact total; the bounded walk stops at the witness.
 *   - hugeFlat: a directory with 20,000 files — readdir enumerates the whole
 *     directory on this runtime, so the O(width) allocation remains; this
 *     fixture measures that retained cost honestly on both implementations.
 *
 * Each record carries the exact head commit and a SHA-256 over the ordered
 * JSON path array, so parity between implementations is content-exact.
 *
 * Usage: bun run scripts/performance/list-files-bench.ts --label candidate
 * Emits one JSON line per run. The coordinating harness alternates this
 * against the same script on the baseline commit in fresh processes.
 */

import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { listFiles } from "../../src/core/agents/offSecAgent/tools/listFiles";
import type { ToolContext } from "../../src/core/agents/offSecAgent/tools/types";

const ITERATIONS = 5;

function gc(): void {
  if (typeof Bun !== "undefined") Bun.gc(true);
  else globalThis.gc?.();
}

function mockCtx(root: string): ToolContext {
  return {
    agentCwd: root,
    session: {
      id: "ses_bench",
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

async function buildDeepChain(root: string, levels: number): Promise<void> {
  let dir = root;
  for (let i = 0; i < levels; i++) {
    dir = join(dir, "d");
    await mkdir(dir, { recursive: true });
    await writeFile(join(dir, "f.txt"), "");
  }
}

async function buildHugeFlat(root: string, count: number): Promise<void> {
  for (let i = 0; i < count; i++) {
    await writeFile(join(root, `f-${String(i).padStart(6, "0")}.txt`), "");
  }
}

async function measureFixture(
  name: string,
  root: string,
  recursive: boolean,
): Promise<{
  fixture: string;
  iterations: Array<{ ms: number; rssBefore: number; rssAfter: number }>;
  medianMs: number;
  filesCount: number;
  totalFound: number | null;
  truncated: boolean | null;
  filesSha256: string;
}> {
  // The tool never streams, so the SDK's result union always resolves to one
  // result object.
  type ListingResult = {
    success: boolean;
    error: string;
    files: string[];
    totalFound?: number;
    truncated?: boolean;
  };
  const iterations: Array<{ ms: number; rssBefore: number; rssAfter: number }> =
    [];
  let last: ListingResult | null = null;
  for (let i = 0; i < ITERATIONS; i++) {
    gc();
    const rssBefore = process.memoryUsage.rss();
    const t0 = performance.now();
    const execute = listFiles(mockCtx(root)).execute;
    if (!execute) throw new Error("list_files tool has no execute");
    last = (await execute(
      { directory: root, recursive, toolCallDescription: "bench" } as never,
      { toolCallId: "bench" } as never,
    )) as ListingResult;
    const ms = performance.now() - t0;
    const rssAfter = process.memoryUsage.rss();
    iterations.push({ ms, rssBefore, rssAfter });
  }
  if (!last || last.success !== true) {
    throw new Error(`listing failed: ${name}: ${last?.error ?? "no result"}`);
  }
  const filesSha256 = createHash("sha256")
    .update(JSON.stringify(last.files))
    .digest("hex");
  return {
    fixture: name,
    iterations,
    medianMs: iterations.map((i) => i.ms).sort((a, b) => a - b)[
      Math.floor(ITERATIONS / 2)
    ],
    filesCount: last.files.length,
    totalFound: last.totalFound ?? null,
    truncated: last.truncated ?? null,
    filesSha256,
  };
}

function argLabel(): string {
  const idx = process.argv.indexOf("--label");
  return idx > 0 ? (process.argv[idx + 1] ?? "unlabeled") : "unlabeled";
}

const DEEP_LEVELS = 400;
const FLAT_FILES = 20_000;
const deepRoot = await mkdtemp(join(tmpdir(), "apex-pr08-deep-"));
const flatRoot = await mkdtemp(join(tmpdir(), "apex-pr08-flat-"));
try {
  await buildDeepChain(deepRoot, DEEP_LEVELS);
  await buildHugeFlat(flatRoot, FLAT_FILES);

  const deepRecursive = await measureFixture(
    "deep-400-recursive",
    deepRoot,
    true,
  );
  const flatRecursive = await measureFixture(
    "hugeFlat-20000-recursive",
    flatRoot,
    true,
  );
  const flatListing = await measureFixture(
    "hugeFlat-20000-flat",
    flatRoot,
    false,
  );

  const runtime =
    typeof Bun !== "undefined"
      ? `bun ${Bun.version}`
      : `node ${process.version}`;
  console.log(
    JSON.stringify({
      label: argLabel(),
      runtime,
      commit: spawnSync("git", ["rev-parse", "HEAD"], {
        encoding: "utf8",
      }).stdout.trim(),
      fixtures: { deepLevels: DEEP_LEVELS, flatFiles: FLAT_FILES },
      deepRecursive,
      flatRecursive,
      flatListing,
    }),
  );
} finally {
  await rm(deepRoot, { recursive: true, force: true });
  await rm(flatRoot, { recursive: true, force: true });
}
