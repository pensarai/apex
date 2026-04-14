/**
 * Threat Model Benchmark — Configuration & CLI Parsing
 */

import { existsSync, readdirSync } from "fs";
import path from "path";
import type { AIModel } from "../../../src/core/ai/ai";
import type { BenchmarkConfig } from "./types";

// ---------------------------------------------------------------------------
// Defaults
// ---------------------------------------------------------------------------

const DEFAULT_MODEL: AIModel = "claude-sonnet-4-5";
const DEFAULT_TIMEOUT = 600_000; // 10 minutes
const DEFAULT_CONCURRENCY = 1;

function defaultAppsDir(): string {
  // Sibling repo relative to the Apex project root
  return path.resolve(
    __dirname,
    "../../../../argus-validation-benchmarks/benchmarks/threat-model/apps",
  );
}

function defaultResultsDir(): string {
  return path.resolve(__dirname, "../results");
}

// ---------------------------------------------------------------------------
// CLI Parsing
// ---------------------------------------------------------------------------

function printUsage(): void {
  console.log(`
Threat Model Benchmark Runner
==============================

Evaluates Apex's threat modelling quality against known test applications.

Usage:
  bun run benchmarks/threat-model/harness/runner.ts [options]

Options:
  --apps <ids>           Comma-separated app IDs (default: all TM-APP-*)
  --model <model>        AI model for threat model generation (default: claude-sonnet-4-5)
  --judge-model <model>  AI model for LLM judges (default: claude-sonnet-4-5)
  --apps-dir <path>      Path to test apps directory
  --results-dir <path>   Path to results output directory
  --fast                 Skip LLM judges (structural + grounding only)
  --repeats <n>          Repeat each app N times for determinism (default: 1)
  --compare-with <id>    Previous run ID for regression comparison
  --timeout <ms>         Per-app timeout in milliseconds (default: 600000)
  --concurrency <n>      Max parallel apps (default: 1)
  --help, -h             Show this help message

Examples:
  # Run all apps (fast mode)
  bun run benchmarks/threat-model/harness/runner.ts --fast

  # Run specific app
  bun run benchmarks/threat-model/harness/runner.ts --apps TM-APP-001

  # Full suite with LLM judges
  bun run benchmarks/threat-model/harness/runner.ts --model claude-sonnet-4-5

  # Compare with previous run
  bun run benchmarks/threat-model/harness/runner.ts --compare-with tm-bench-2026-04-14T10-30-00
`);
}

function getArg(argv: string[], flag: string): string | undefined {
  const idx = argv.indexOf(flag);
  if (idx === -1) return undefined;
  return argv[idx + 1];
}

function hasFlag(argv: string[], flag: string): boolean {
  return argv.includes(flag);
}

export function discoverApps(appsDir: string): string[] {
  if (!existsSync(appsDir)) return [];
  return readdirSync(appsDir)
    .filter((d) => d.startsWith("TM-APP-"))
    .sort();
}

export function parseConfig(argv: string[]): BenchmarkConfig {
  if (hasFlag(argv, "--help") || hasFlag(argv, "-h")) {
    printUsage();
    process.exit(0);
  }

  const appsDir = path.resolve(getArg(argv, "--apps-dir") ?? defaultAppsDir());
  const resultsDir = path.resolve(getArg(argv, "--results-dir") ?? defaultResultsDir());

  let apps: string[];
  const appsArg = getArg(argv, "--apps");
  if (appsArg) {
    apps = appsArg.split(",").map((s) => s.trim());
    // Validate
    for (const app of apps) {
      if (!existsSync(path.join(appsDir, app))) {
        console.error(`App directory not found: ${path.join(appsDir, app)}`);
        process.exit(1);
      }
    }
  } else {
    apps = discoverApps(appsDir);
    if (apps.length === 0) {
      console.error(`No TM-APP-* directories found in: ${appsDir}`);
      console.error("Use --apps-dir to specify the test apps location.");
      process.exit(1);
    }
  }

  const model = (getArg(argv, "--model") ?? DEFAULT_MODEL) as AIModel;
  const judgeModel = (getArg(argv, "--judge-model") ?? DEFAULT_MODEL) as AIModel;
  const repeats = parseInt(getArg(argv, "--repeats") ?? "1", 10);
  const timeout = parseInt(getArg(argv, "--timeout") ?? String(DEFAULT_TIMEOUT), 10);
  const concurrency = parseInt(
    getArg(argv, "--concurrency") ?? String(DEFAULT_CONCURRENCY),
    10,
  );

  return {
    apps,
    model,
    judgeModel,
    repeats,
    compareWith: getArg(argv, "--compare-with"),
    fast: hasFlag(argv, "--fast"),
    appsDir,
    resultsDir,
    concurrency,
    timeout,
  };
}
