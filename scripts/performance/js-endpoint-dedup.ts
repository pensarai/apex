#!/usr/bin/env bun

/**
 * JS endpoint deduplication benchmark.
 *
 * Measures the production fetching helper (`extractJavascriptEndpoints` —
 * same parser on both sides of the change) on fixture pages where every
 * endpoint appears twice, so the only behavioral difference between trees
 * is the deduplication algorithm. `--mode pure` measures the extracted pure
 * parser directly. Every record carries the tree label, git revision,
 * source hash, and runtime so results are attributable.
 *
 * Usage (single measurement, current tree):
 *   bun run scripts/performance/js-endpoint-dedup.ts --mode fetched --size 20000
 *
 * Usage (comparison — alternating fresh before/after processes per trial,
 * output-hash equality asserted across trees):
 *   bun run scripts/performance/js-endpoint-dedup.ts --compare \
 *     --baseline-root /path/to/baseline --baseline-revision be2e4b81...
 *
 * The baseline root must contain this script (copy it in untracked). For a
 * plain `git archive` snapshot pass --baseline-revision because it has no
 * .git directory.
 */

import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";

const SCRIPT = "scripts/performance/js-endpoint-dedup.ts";
const EXTRACTION_SOURCE =
  "src/core/agents/specialized/attackSurface/jsExtraction.ts";
const SIZES_DEFAULT = [5000, 10000, 20000, 40000];
const TRIALS_DEFAULT = 5;

interface Measurement {
  kind: "measurement";
  label: string;
  revision: string;
  root: string;
  mode: string;
  size: number;
  trial: number;
  wallMs: number;
  cpuMs: number;
  hash: string;
  uniqueEndpoints: number;
  totalAjaxCalls: number;
  sourceHash: string;
  bunVersion: string;
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

function buildFixtureHtml(size: number): string {
  const calls: string[] = [];
  for (let i = 0; i < size; i++) {
    const endpoint = `/api/item/${i}`;
    calls.push(`fetch('${endpoint}'); fetch('${endpoint}');`);
  }
  return `<script>\n${calls.join("\n")}\n</script>`;
}

function sourceHash(root: string): string {
  return createHash("sha256")
    .update(readFileSync(`${root}/${EXTRACTION_SOURCE}`, "utf8"))
    .digest("hex");
}

function gitRevision(root: string): string {
  const rev = spawnSync("git", ["-C", root, "rev-parse", "HEAD"], {
    encoding: "utf8",
  });
  return rev.status === 0 ? rev.stdout.trim() : "unknown";
}

async function measure(
  label: string,
  revision: string,
  mode: string,
  size: number,
  trial: number,
): Promise<Measurement> {
  const html = buildFixtureHtml(size);
  const url = "https://fixture.invalid/app";
  const extraction = await import(
    "../../src/core/agents/specialized/attackSurface/jsExtraction"
  );

  let run: () => Promise<unknown>;
  if (mode === "fetched") {
    const helper = extraction.extractJavascriptEndpoints;
    // The page fetch routes through the tool http backend (design §3.2), so
    // the benchmark injects a backend that returns the fixture body.
    const ctx = {
      backends: {
        http: { request: async () => ({ success: true, body: html }) },
      },
    } as unknown as Parameters<typeof helper>[0]["ctx"];
    run = () => helper({ url, ctx });
  } else if (mode === "pure") {
    const pure = extraction.extractJavascriptEndpointsFromHtml;
    run = () => Promise.resolve(pure(html, url));
  } else {
    throw new Error(`unknown mode: ${mode}`);
  }

  const start = performance.now();
  const cpuStart = process.cpuUsage();
  const result = (await run()) as Awaited<
    ReturnType<typeof extraction.extractJavascriptEndpoints>
  >;
  const cpu = process.cpuUsage(cpuStart);

  return {
    kind: "measurement",
    label,
    revision,
    root: process.cwd(),
    mode,
    size,
    trial,
    wallMs: performance.now() - start,
    cpuMs: (cpu.user + cpu.system) / 1000,
    hash: createHash("sha256").update(JSON.stringify(result)).digest("hex"),
    uniqueEndpoints: result.endpoints?.length ?? 0,
    totalAjaxCalls: result.totalAjaxCalls ?? 0,
    sourceHash: sourceHash(process.cwd()),
    bunVersion: Bun.version,
  };
}

function measureInChild(
  root: string,
  label: string,
  revision: string,
  size: number,
  trial: number,
): Measurement {
  const child = spawnSync(
    process.execPath,
    [
      "run",
      `${root}/${SCRIPT}`,
      "--mode",
      "fetched",
      "--size",
      String(size),
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
      `child measurement failed (status ${child.status}): ${child.stderr}`,
    );
  }
  const line = child.stdout
    .trim()
    .split("\n")
    .find((l) => l.startsWith("{"));
  if (!line) throw new Error("no measurement JSON in child output");
  return JSON.parse(line) as Measurement;
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
      flags.get("mode") ?? "fetched",
      Number(flags.get("size") ?? 20000),
      Number(flags.get("trial") ?? 1),
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
  const sizes = (flags.get("sizes") ?? SIZES_DEFAULT.join(","))
    .split(",")
    .map(Number)
    .filter(Number.isFinite);
  const trials = Number(flags.get("trials") ?? TRIALS_DEFAULT);

  const measurements: Measurement[] = [];
  for (const size of sizes) {
    for (let trial = 1; trial <= trials; trial++) {
      const order: Array<{
        root: string;
        label: string;
        revision: string;
      }> =
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
          measureInChild(tree.root, tree.label, tree.revision, size, trial),
        );
      }
    }
  }

  let parityFailed = false;
  for (const size of sizes) {
    const forSize = measurements.filter((m) => m.size === size);
    const byLabel = (label: string) => forSize.filter((m) => m.label === label);
    const baseline = byLabel("baseline");
    const candidate = byLabel("candidate");
    const hashes = new Set(forSize.map((m) => m.hash));
    console.log(
      `size=${size} trials=${trials} ` +
        `baseline[label=baseline rev=${baseline[0]?.revision.slice(0, 8)} ` +
        `source=${baseline[0]?.sourceHash.slice(0, 8)} ` +
        `medianWallMs=${median(baseline.map((m) => m.wallMs)).toFixed(1)}] ` +
        `candidate[label=candidate rev=${candidate[0]?.revision.slice(0, 8)} ` +
        `source=${candidate[0]?.sourceHash.slice(0, 8)} ` +
        `medianWallMs=${median(candidate.map((m) => m.wallMs)).toFixed(1)}] ` +
        `hashesEqual=${hashes.size === 1} ` +
        `uniqueEndpoints=${forSize[0]?.uniqueEndpoints} ` +
        `totalAjaxCalls=${forSize[0]?.totalAjaxCalls}`,
    );
    if (hashes.size !== 1) parityFailed = true;
  }

  console.log(
    JSON.stringify({
      kind: "comparison",
      bunVersion: Bun.version,
      mode: "fetched",
      measurements,
    }),
  );
  if (parityFailed) {
    console.error("output hash mismatch between trees");
    process.exit(1);
  }
}

await main();
