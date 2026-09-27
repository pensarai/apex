#!/usr/bin/env bun

/**
 * Whitebox profile-coalescing benchmark.
 *
 * Fires N concurrent query_whitebox_catalog lookups for the same
 * session/root key at a real filesystem fixture, through the production
 * tool. The tree under test decides the behavior: the baseline runs one
 * profileCodebase walk per request; the coalescing tree shares one attempt.
 *
 * Two separately-scoped CPU numbers are reported; they are never subtracted.
 * `lookupParentCpuMs` is measured in-process around the lookup wave and
 * excludes the profile's `git`/`which` subprocesses. `wholeProcessCpuMs` is
 * captured by wrapping each fresh child in /usr/bin/time and covers the whole
 * child process lifetime — module imports, fixture build, lookups, and
 * cleanup, plus the waited-for subprocesses rolled up by wait4 rusage.
 *
 * Usage (single measurement, current tree):
 *   bun run scripts/performance/whitebox-profile-coalescing.ts \
 *     --requests 16 [--fixture /path]
 *
 * Usage (comparison — alternating fresh baseline/candidate processes per
 * trial, output-hash equality asserted across trees):
 *   bun run scripts/performance/whitebox-profile-coalescing.ts \
 *     --compare true --baseline-root /path/to/baseline \
 *     --baseline-revision be2e4b81...
 *
 * The baseline root must contain this script (copy it in untracked). The
 * default fixture is a generated non-git tree, so profiles contain no
 * currentCommit and outputs stay comparable across trees.
 */

import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import {
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const SCRIPT = "scripts/performance/whitebox-profile-coalescing.ts";
const TOOL_SOURCE = "src/core/agents/offSecAgent/tools/queryWhiteboxCatalog.ts";
const FIXTURE_DIRS = 120;
const FIXTURE_FILES = 10;
const TRIALS_DEFAULT = 5;
const REQUESTS_DEFAULT = 16;

interface Measurement {
  kind: "measurement";
  label: string;
  revision: string;
  root: string;
  requests: number;
  trial: number;
  wallMs: number;
  lookupParentCpuMs: number;
  // Null in the single-measurement path: whole-process CPU comes from the
  // /usr/bin/time wrapper, which only the comparator path runs under.
  wholeProcessCpuMs: number | null;
  hash: string;
  recordsCount: number;
  sourceHash: string;
  bunVersion: string;
}

// A comparator measurement: the child ran under /usr/bin/time, so
// wholeProcessCpuMs is present.
interface TimedMeasurement extends Measurement {
  wholeProcessCpuMs: number;
}

function parseArgs(argv: string[]): Map<string, string> {
  const flags = new Map<string, string>();
  for (let i = 0; i < argv.length; i += 2) {
    if (!argv[i]?.startsWith("--")) {
      throw new Error(`expected --flag value pairs, got: ${argv[i]}`);
    }
    flags.set(argv[i].slice(2), argv[i + 1] ?? "");
  }
  return flags;
}

function buildFixture(root: string): void {
  for (let dir = 0; dir < FIXTURE_DIRS; dir++) {
    const packageDir = join(root, `pkg-${dir}`);
    mkdirSync(packageDir);
    for (let file = 0; file < FIXTURE_FILES; file++) {
      writeFileSync(
        join(packageDir, `mod-${file}.ts`),
        `export const v = ${file};\n`,
      );
    }
  }
  writeFileSync(
    join(root, "package.json"),
    JSON.stringify({ name: "whitebox-bench-fixture", scripts: { build: "x" } }),
  );
}

function sourceHash(root: string): string {
  return createHash("sha256")
    .update(readFileSync(`${root}/${TOOL_SOURCE}`, "utf8"))
    .digest("hex");
}

function gitRevision(root: string): string {
  const rev = spawnSync("git", ["-C", root, "rev-parse", "HEAD"], {
    encoding: "utf8",
  });
  return rev.status === 0 ? rev.stdout.trim() : "unknown";
}

interface ToolResult {
  success: boolean;
  data: { records: unknown[] };
}

async function measure(
  label: string,
  revision: string,
  requests: number,
  trial: number,
  fixtureArg?: string,
): Promise<Measurement> {
  const ownedFixture = !fixtureArg;
  const fixture = fixtureArg ?? mkdtempSync(join(tmpdir(), "wb-bench-"));
  if (ownedFixture) buildFixture(fixture);
  const base = {
    kind: "measurement",
    label,
    revision,
    root: process.cwd(),
    requests,
    trial,
    sourceHash: sourceHash(process.cwd()),
    bunVersion: Bun.version,
  } as Measurement;

  try {
    const { queryWhiteboxCatalog } = await import(
      "../../src/core/agents/offSecAgent/tools/queryWhiteboxCatalog"
    );
    const ctx = {
      session: { id: "coalescing-bench" },
      agentCwd: fixture,
    } as never;
    const tool = queryWhiteboxCatalog(ctx);

    const start = performance.now();
    const cpuStart = process.cpuUsage();
    const outputs = (await Promise.all(
      Array.from({ length: requests }, () =>
        tool.execute?.(
          { query: "auth", limit: 3, toolCallDescription: "bench" },
          { toolCallId: "tc_bench", messages: [] },
        ),
      ),
    )) as ToolResult[];

    const cpu = process.cpuUsage(cpuStart);
    const wallMs = performance.now() - start;
    if (outputs.some((o) => !o.success)) {
      throw new Error("tool lookup failed during measurement");
    }
    return {
      ...base,
      wallMs,
      lookupParentCpuMs: (cpu.user + cpu.system) / 1000,
      wholeProcessCpuMs: null,
      hash: createHash("sha256").update(JSON.stringify(outputs)).digest("hex"),
      recordsCount: outputs[0]?.data.records.length ?? 0,
    };
  } finally {
    if (ownedFixture) rmSync(fixture, { recursive: true, force: true });
  }
}

function measureInChild(
  root: string,
  label: string,
  revision: string,
  requests: number,
  trial: number,
): TimedMeasurement {
  const child = spawnSync(
    "/usr/bin/time",
    [
      process.execPath,
      "run",
      `${root}/${SCRIPT}`,
      "--requests",
      String(requests),
      "--trial",
      String(trial),
      "--label",
      label,
      "--revision",
      revision,
    ],
    { cwd: root, encoding: "utf8", timeout: 600_000 },
  );
  if (child.status !== 0) {
    throw new Error(
      `child measurement failed (status ${child.status}): ${child.stderr?.slice(0, 800)}`,
    );
  }
  const line = child.stdout
    .trim()
    .split("\n")
    .find((l) => l.startsWith("{"));
  if (!line) throw new Error("no measurement JSON in child output");
  const measurement = JSON.parse(line) as Measurement;
  const time = child.stderr.match(
    /([\d.]+)\s+real\s+([\d.]+)\s+user\s+([\d.]+)\s+sys/,
  );
  if (!time) throw new Error("could not parse /usr/bin/time output");
  const timed: TimedMeasurement = {
    ...measurement,
    wholeProcessCpuMs: (Number(time[2]) + Number(time[3])) * 1000,
  };
  return timed;
}

function median(values: number[]): number {
  const sorted = [...values].sort((a, b) => a - b);
  const mid = Math.floor(sorted.length / 2);
  return sorted.length % 2 === 1
    ? sorted[mid]
    : (sorted[mid - 1] + sorted[mid]) / 2;
}

async function main(): Promise<void> {
  const flags = parseArgs(process.argv.slice(2));

  if (flags.get("compare") !== "true") {
    const measurement = await measure(
      flags.get("label") ?? "candidate",
      flags.get("revision") ?? gitRevision(process.cwd()),
      Number(flags.get("requests") ?? REQUESTS_DEFAULT),
      Number(flags.get("trial") ?? 1),
      flags.get("fixture"),
    );
    console.log(JSON.stringify(measurement));
    return;
  }

  const baselineRoot = flags.get("baseline-root");
  if (!baselineRoot) throw new Error("--compare requires --baseline-root");
  const baselineRevision =
    flags.get("baseline-revision") ?? gitRevision(baselineRoot);
  if (baselineRevision === "unknown") {
    throw new Error(
      "baseline revision unresolved: pass --baseline-revision for a snapshot",
    );
  }
  const candidateRoot = process.cwd();
  const candidateRevision = gitRevision(candidateRoot);
  const requests = Number(flags.get("requests") ?? REQUESTS_DEFAULT);
  const trials = Number(flags.get("trials") ?? TRIALS_DEFAULT);

  const measurements: TimedMeasurement[] = [];
  for (let trial = 1; trial <= trials; trial++) {
    const order: Array<{ root: string; label: string; revision: string }> =
      trial % 2 === 1
        ? [
            {
              root: baselineRoot,
              label: "baseline",
              revision: baselineRevision,
            },
            {
              root: candidateRoot,
              label: "candidate",
              revision: candidateRevision,
            },
          ]
        : [
            {
              root: candidateRoot,
              label: "candidate",
              revision: candidateRevision,
            },
            {
              root: baselineRoot,
              label: "baseline",
              revision: baselineRevision,
            },
          ];
    for (const tree of order) {
      measurements.push(
        measureInChild(tree.root, tree.label, tree.revision, requests, trial),
      );
    }
  }

  let parityFailed = false;
  for (const trial of Array.from(
    new Set(measurements.map((m) => m.trial)),
  ).sort((a, b) => a - b)) {
    const forTrial = measurements.filter((m) => m.trial === trial);
    const baseline = forTrial.find((m) => m.label === "baseline");
    const candidate = forTrial.find((m) => m.label === "candidate");
    const hashesEqual = new Set(forTrial.map((m) => m.hash)).size === 1;
    console.log(
      `trial=${trial} requests=${requests} ` +
        `baseline[rev=${baseline?.revision.slice(0, 8)} ` +
        `wallMs=${baseline?.wallMs.toFixed(1)} ` +
        `lookupParentCpuMs=${baseline?.lookupParentCpuMs.toFixed(1)} ` +
        `wholeProcessCpuMs=${baseline?.wholeProcessCpuMs.toFixed(1)}] ` +
        `candidate[rev=${candidate?.revision.slice(0, 8)} ` +
        `wallMs=${candidate?.wallMs.toFixed(1)} ` +
        `lookupParentCpuMs=${candidate?.lookupParentCpuMs.toFixed(1)} ` +
        `wholeProcessCpuMs=${candidate?.wholeProcessCpuMs.toFixed(1)}] ` +
        `hashesEqual=${hashesEqual} records=${candidate?.recordsCount}`,
    );
    if (!hashesEqual) parityFailed = true;
  }

  const byLabel = (label: string, field: keyof Measurement) =>
    median(
      measurements
        .filter((m) => m.label === label)
        .map((m) => m[field] as number),
    );
  console.log(
    `medians baseline[wallMs=${byLabel("baseline", "wallMs").toFixed(1)} ` +
      `lookupParentCpuMs=${byLabel("baseline", "lookupParentCpuMs").toFixed(1)} ` +
      `wholeProcessCpuMs=${byLabel("baseline", "wholeProcessCpuMs").toFixed(1)}] ` +
      `candidate[wallMs=${byLabel("candidate", "wallMs").toFixed(1)} ` +
      `lookupParentCpuMs=${byLabel("candidate", "lookupParentCpuMs").toFixed(1)} ` +
      `wholeProcessCpuMs=${byLabel("candidate", "wholeProcessCpuMs").toFixed(1)}]`,
  );

  console.log(
    JSON.stringify({
      kind: "comparison",
      bunVersion: Bun.version,
      requests,
      fixture: { dirs: FIXTURE_DIRS, filesPerDir: FIXTURE_FILES },
      measurements,
    }),
  );
  if (parityFailed) {
    console.error("output hash mismatch between trees");
    process.exit(1);
  }
}

await main();
