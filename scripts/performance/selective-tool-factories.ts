#!/usr/bin/env bun

/**
 * Selective tool-factory construction benchmark (PR03). See
 * docs/performance/selective-tool-factories.md for scope and limits.
 *
 * Usage: bun run scripts/performance/selective-tool-factories.ts [all|selected] [sets] [ROOT]
 * ROOT defaults to this repo; pass the PR02 parent worktree to run its
 * unmodified source through the same runner.
 */

import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";

const mode = process.argv[2] ?? "selected";
const sets = Number(process.argv[3] ?? 32);
const rootArg = process.argv[4] ?? process.env.SELECTIVE_FACTORIES_ROOT ?? "";
if (
  !["all", "selected"].includes(mode) ||
  !Number.isInteger(sets) ||
  sets < 1
) {
  throw new Error(
    "Usage: bun run scripts/performance/selective-tool-factories.ts [all|selected] [sets] [ROOT]",
  );
}
const root = rootArg ? resolve(rootArg) : resolve(import.meta.dir, "../..");

const MANIFEST_KEYS = [
  "src/core/agents/offSecAgent/tools/index.ts",
  "src/core/agents/offSecAgent/tools/browserTools.ts",
  "src/core/agents/offSecAgent/tools/email/index.ts",
  "src/core/agents/offSecAgent/tools/playwrightMcp.ts",
  "src/core/agents/offSecAgent/tools/sandboxPlaywright.ts",
  "src/core/agents/offSecAgent/offensiveSecurityAgent.ts",
  "src/core/agents/offSecAgent/index.ts",
];

function gitText(root: string, args: string[]): string | null {
  try {
    return execFileSync("git", args, { cwd: root, encoding: "utf8" }).trim();
  } catch {
    return null;
  }
}

function provenance(root: string) {
  const sourceHashes: Record<string, string> = {};
  for (const key of MANIFEST_KEYS) {
    try {
      sourceHashes[key] = createHash("sha256")
        .update(readFileSync(join(root, key)))
        .digest("hex");
    } catch {
      sourceHashes[key] = "absent";
    }
  }
  // Porcelain status entries (tracked modifications AND untracked files).
  const statusEntries =
    gitText(root, ["status", "--short"])?.split("\n").filter(Boolean) ?? [];
  return {
    root,
    revision: gitText(root, ["rev-parse", "HEAD"]),
    statusEntries,
    sourceHashes,
  };
}

function makeCtx(root: string) {
  // No sandbox, no credentialManager, no injection library: construction
  // routing is pinned; deterministic counts live in the vitest gate.
  return {
    session: {
      id: "fixture",
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
    agentCwd: root,
    subagentSpawner: {} as never,
  } as never;
}

const JUDGE_TOOLS = [
  "execute_command",
  "http_request",
  "read_file",
  "list_files",
  "grep",
  "web_search",
  "get_page",
];

const fixtureRoot = mkdtempSync(join(tmpdir(), "apex-selective-bench-"));
try {
  const ctx = makeCtx(fixtureRoot);
  const mod = (await import(
    join(root, "src/core/agents/offSecAgent/tools/index.ts")
  )) as {
    createAllTools: (
      ctx: never,
    ) => Record<string, { description?: unknown; inputSchema?: unknown }>;
    createToolsForNames?: (
      ctx: never,
      names: readonly string[],
    ) => Record<string, { description?: unknown; inputSchema?: unknown }>;
  };

  let construct: () => Record<
    string,
    { description?: unknown; inputSchema?: unknown }
  >;
  if (mode === "all") {
    construct = () => mod.createAllTools(ctx);
  } else {
    const createSelected = mod.createToolsForNames;
    if (!createSelected) {
      // Thrown, not process.exit — the finally block must still clean up.
      throw new Error(
        `createToolsForNames is absent at ${root} (revision ${provenance(root).revision}); the parent only supports all-mode`,
      );
    }
    construct = () => createSelected(ctx, JUDGE_TOOLS);
  }

  for (let i = 0; i < 3; i++) construct();

  const { asSchema } = await import("ai");

  // Schema parity digest over the REAL canonical JSON schemas produced by
  // the production SDK converter. Conversion failures throw — a converter
  // failure invalidates parity and must be loud, never coerced to a
  // placeholder string.
  const schemaDigest = (
    tools: Record<string, { description?: unknown; inputSchema?: unknown }>,
    names: string[],
  ): string => {
    const payload = names.map((name) => {
      const tool = tools[name];
      if (!tool) throw new Error(`tool absent from toolset: ${name}`);
      return [
        name,
        tool.description ?? null,
        tool.inputSchema
          ? (asSchema(tool.inputSchema as never).jsonSchema ?? null)
          : null,
      ];
    });
    return createHash("sha256").update(JSON.stringify(payload)).digest("hex");
  };

  Bun.gc(true);
  const memoryStart = process.memoryUsage();
  const cpuStart = process.cpuUsage();
  const t = performance.now();
  const retained = Array.from({ length: sets }, construct);
  const wallMs = performance.now() - t;
  const cpuDelta = process.cpuUsage(cpuStart);
  Bun.gc(true);
  // Memory snapshot immediately after GC, before any post-processing —
  // temporary Object.keys arrays must stay outside the heap/RSS delta.
  const memoryEnd = process.memoryUsage();
  // Then touch every retained set so live-through-GC remains proven by
  // future use; the key total is retained KEYS, not constructions.
  const retainedToolKeysTotal = retained.reduce(
    (acc, set) => acc + Object.keys(set).length,
    0,
  );

  const toolset = retained[0];
  if (!toolset) throw new Error("no retained toolsets constructed");
  const names = Object.keys(toolset);
  const wanted = new Set(JUDGE_TOOLS);

  let fullMapSchemaSha256: string | null;
  let selectedProjectionSchemaSha256: string | null;
  if (mode === "all") {
    fullMapSchemaSha256 = schemaDigest(toolset, names);
    // Projection over the actual registry-relative order of the selected
    // names — not the hardcoded fixture order.
    selectedProjectionSchemaSha256 = schemaDigest(
      toolset,
      names.filter((n) => wanted.has(n)),
    );
  } else {
    selectedProjectionSchemaSha256 = schemaDigest(toolset, names);
    for (const name of JUDGE_TOOLS) {
      if (!Object.hasOwn(toolset, name)) {
        throw new Error(`selected toolset is missing fixture tool: ${name}`);
      }
    }
    if (names.length !== JUDGE_TOOLS.length) {
      throw new Error(
        `selected toolset has ${names.length} tools, expected ${JUDGE_TOOLS.length}`,
      );
    }
    // The full-map digest comes from the separate matched all-mode control
    // run; a second construction here would pollute the memory window.
    fullMapSchemaSha256 = null;
  }

  console.log(
    "SELECTIVE_FACTORIES_BENCH",
    JSON.stringify({
      ...provenance(root),
      runtime: `bun ${Bun.version}`,
      mode,
      sets,
      toolsPerSet: names.length,
      retainedToolKeysTotal,
      constructWallMs: wallMs,
      constructCpuMs: (cpuDelta.user + cpuDelta.system) / 1000,
      // Observed post-GC differences; background/GC noise means these can
      // drift in either direction — they are not bounds on allocation.
      heapDeltaObservedBytes: memoryEnd.heapUsed - memoryStart.heapUsed,
      rssDeltaObservedBytes: memoryEnd.rss - memoryStart.rss,
      fullMapSchemaSha256,
      selectedProjectionSchemaSha256,
    }),
  );
} finally {
  rmSync(fixtureRoot, { recursive: true, force: true });
}
