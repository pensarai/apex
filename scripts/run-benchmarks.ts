#!/usr/bin/env bun

/**
 * Argus Benchmark Runner CLI
 *
 * Runs Apex against the Argus validation benchmark suite (60 benchmarks).
 * Supports both local sequential execution and Daytona remote parallel execution.
 *
 * Usage:
 *   bun run scripts/run-benchmarks.ts [options]
 *
 * Examples:
 *   bun run scripts/run-benchmarks.ts --branches APEX-001-25 --model claude-haiku-4-5
 *   bun run scripts/run-benchmarks.ts --branches APEX-001-25,APEX-002-25 --model claude-sonnet-4-5
 *   bun run scripts/run-benchmarks.ts --all --mode daytona --model claude-sonnet-4-5
 */

import { execSync } from "node:child_process";
import { existsSync, mkdirSync, writeFileSync } from "node:fs";
import path from "node:path";
import {
  type CostBenchGateway,
  parseOpenRouterReferenceRates,
} from "../src/core/benchmark/gatewayCost";
import {
  generateJsonReport,
  generateTextReport,
} from "../src/core/benchmark/report";
import { runBenchmarkSuite } from "../src/core/benchmark/runner";
import type { BenchmarkSuiteConfig } from "../src/core/benchmark/types";

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const DEFAULT_REPO_URL =
  "https://github.com/pensarai/argus-validation-benchmarks";
const DEFAULT_MODEL = "claude-sonnet-4-5-20250929";
const DEFAULT_TIMEOUT = 30;
const DEFAULT_BATCH_SIZE = 4;
const ALL_BRANCHES = Array.from({ length: 60 }, (_, i) => {
  const num = String(i + 1).padStart(3, "0");
  return `APEX-${num}-25`;
});

function parseSstSecret(value: string | undefined): string | undefined {
  if (!value) return undefined;
  try {
    const parsed = JSON.parse(value) as { value?: unknown };
    if (typeof parsed.value === "string" && parsed.value.trim()) {
      return parsed.value;
    }
  } catch {
    // SST can also inject the secret as a bare string.
  }
  return value.trim() || undefined;
}

function configureGatewaySecrets(): void {
  process.env.OPENROUTER_API_KEY ??= parseSstSecret(
    process.env.SST_RESOURCE_OpenrouterApiKey,
  );
  process.env.CONCENTRATE_API_KEY ??= parseSstSecret(
    process.env.SST_RESOURCE_ConcentrateApiKey,
  );
}

function costGatewayForModel(model: string): CostBenchGateway {
  if (model === "z-ai/glm-5.3") return "openrouter";
  if (model === "concentrate:glm-5.3") return "concentrate";
  throw new Error(
    `Provider-cost tracking currently supports GLM 5.3 only, received ${model}`,
  );
}

async function loadReferenceRates() {
  const source = "https://openrouter.ai/api/v1/models";
  const capturedAt = new Date().toISOString();
  const response = await fetch(source, {
    signal: AbortSignal.timeout(30_000),
  });
  if (!response.ok) {
    throw new Error(
      `OpenRouter model catalog returned HTTP ${response.status}`,
    );
  }
  return parseOpenRouterReferenceRates(
    (await response.json()) as unknown,
    capturedAt,
    source,
  );
}

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

function printUsage(): void {
  console.log(`
Argus Benchmark Runner
======================

Runs Apex against the Argus validation benchmark suite.

Usage:
  bun run scripts/run-benchmarks.ts [options]

Options:
  --branches <id1,id2,...>    Comma-separated APEX benchmark IDs
  --all                       Run all 60 benchmarks
  --repo-url <url>            Git repo URL (default: pensarai/argus-validation-benchmarks)
  --repo-dir <path>           Path to already-cloned repo (skip git clone)
  --model <model>             AI model (default: claude-sonnet-4-5-20250929)
  --output <dir>              Output directory for suite results
  --mode <local|daytona>      Execution mode (default: local)
  --timeout <minutes>         Per-benchmark timeout (default: 30)
  --skip <n>                  Skip first N benchmarks
  --limit <n>                 Max benchmarks to run
  --daytona-batch-size <n>    Parallel Daytona sandboxes (default: 4)
  --track-provider-cost       Require provider-billed GLM 5.3 cost metadata
  --max-provider-cost <usd>   Abort a run after this billed-cost ceiling (default: 40)
  --no-comparison             Skip the separate LLM comparison scorer
  --no-cleanup                Don't remove temp clone directories
  --help, -h                  Show this help message

Examples:
  # Single benchmark
  bun run scripts/run-benchmarks.ts --branches APEX-001-25 --model claude-haiku-4-5

  # Multiple benchmarks
  bun run scripts/run-benchmarks.ts --branches APEX-001-25,APEX-002-25,APEX-003-25

  # All 60 benchmarks with Daytona
  bun run scripts/run-benchmarks.ts --all --mode daytona --daytona-batch-size 5

  # Using a pre-cloned repo
  bun run scripts/run-benchmarks.ts --repo-dir ~/argus-validation-benchmarks --branches APEX-001-25
`);
}

async function main(): Promise<void> {
  const args = process.argv.slice(2);

  // Defaults
  let branches: string[] = [];
  let all = false;
  let repoUrl = DEFAULT_REPO_URL;
  let repoDir: string | undefined;
  let model = DEFAULT_MODEL;
  let outputDir = path.join(
    process.env.HOME || "~",
    ".pensar",
    "benchmark-reports",
  );
  let mode: "local" | "daytona" = "local";
  let timeoutMinutes = DEFAULT_TIMEOUT;
  let skip = 0;
  let limit = Infinity;
  let daytonaBatchSize = DEFAULT_BATCH_SIZE;
  let cleanupTempDirs = true;
  let runComparison = true;
  let trackProviderCost = false;
  let maxProviderCostUsd = 40;

  // Parse arguments
  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    const value = args[i + 1];

    if (arg === "--help" || arg === "-h") {
      printUsage();
      process.exit(0);
    } else if (arg === "--branches" && value) {
      i++;
      branches = value.split(",").map((b) => b.trim());
    } else if (arg === "--all") {
      all = true;
    } else if (arg === "--repo-url" && value) {
      i++;
      repoUrl = value;
    } else if (arg === "--repo-dir" && value) {
      i++;
      repoDir = path.resolve(value);
    } else if (arg === "--model" && value) {
      i++;
      model = value;
    } else if (arg === "--output" && value) {
      i++;
      outputDir = path.resolve(value);
    } else if (arg === "--mode" && value) {
      i++;
      mode = value as "local" | "daytona";
    } else if (arg === "--timeout" && value) {
      i++;
      timeoutMinutes = parseInt(value, 10);
    } else if (arg === "--skip" && value) {
      i++;
      skip = parseInt(value, 10);
    } else if (arg === "--limit" && value) {
      i++;
      limit = parseInt(value, 10);
    } else if (arg === "--daytona-batch-size" && value) {
      i++;
      daytonaBatchSize = parseInt(value, 10);
    } else if (arg === "--track-provider-cost") {
      trackProviderCost = true;
    } else if (arg === "--max-provider-cost" && value) {
      i++;
      maxProviderCostUsd = Number(value);
      trackProviderCost = true;
    } else if (arg === "--no-comparison") {
      runComparison = false;
    } else if (arg === "--no-cleanup") {
      cleanupTempDirs = false;
    }
  }

  // Resolve branch list
  if (all) {
    branches = ALL_BRANCHES;
  }

  if (branches.length === 0) {
    console.error("Error: No benchmarks specified. Use --branches or --all.");
    printUsage();
    process.exit(1);
  }

  // Apply skip/limit
  if (skip > 0) {
    branches = branches.slice(skip);
  }
  if (limit < branches.length) {
    branches = branches.slice(0, limit);
  }

  // Validate environment
  configureGatewaySecrets();
  if (model.startsWith("concentrate:") && !process.env.CONCENTRATE_API_KEY) {
    console.error("Error: CONCENTRATE_API_KEY environment variable required.");
    process.exit(1);
  }
  if (model.startsWith("z-ai/") && !process.env.OPENROUTER_API_KEY) {
    console.error("Error: OPENROUTER_API_KEY environment variable required.");
    process.exit(1);
  }
  if (
    !model.startsWith("concentrate:") &&
    !model.startsWith("z-ai/") &&
    !process.env.ANTHROPIC_API_KEY &&
    !process.env.OPENROUTER_API_KEY
  ) {
    console.error(
      "Error: ANTHROPIC_API_KEY or OPENROUTER_API_KEY environment variable required.",
    );
    process.exit(1);
  }
  if (
    trackProviderCost &&
    (!Number.isFinite(maxProviderCostUsd) || maxProviderCostUsd <= 0)
  ) {
    console.error("Error: --max-provider-cost must be a positive number.");
    process.exit(1);
  }
  if (trackProviderCost && mode !== "local") {
    console.error(
      "Error: provider-cost tracking requires local mode because Daytona does not return token metrics.",
    );
    process.exit(1);
  }

  if (mode === "local") {
    // Verify docker is available
    try {
      execSync("docker compose version", { stdio: "pipe" });
    } catch {
      console.error(
        "Error: Docker Compose is required for local mode. Install Docker Desktop.",
      );
      process.exit(1);
    }
  }

  if (mode === "daytona" && !process.env.DAYTONA_API_KEY) {
    console.error(
      "Error: DAYTONA_API_KEY environment variable required for daytona mode.",
    );
    process.exit(1);
  }

  if (repoDir && !existsSync(repoDir)) {
    console.error(`Error: --repo-dir path does not exist: ${repoDir}`);
    process.exit(1);
  }

  const costTracking = trackProviderCost
    ? {
        gateway: costGatewayForModel(model),
        referenceRates: await loadReferenceRates(),
        maxProviderCostUsd,
      }
    : undefined;

  // Print run configuration
  console.log("═".repeat(55));
  console.log("        ARGUS BENCHMARK RUNNER");
  console.log("═".repeat(55));
  console.log(`Mode:       ${mode}`);
  console.log(`Model:      ${model}`);
  console.log(`Repo:       ${repoDir || repoUrl}`);
  console.log(`Benchmarks: ${branches.length}`);
  console.log(`Timeout:    ${timeoutMinutes}m per benchmark`);
  console.log(`Comparison: ${runComparison ? "enabled" : "disabled"}`);
  if (costTracking) {
    console.log(
      `Cost guard:  $${costTracking.maxProviderCostUsd.toFixed(2)} provider-billed`,
    );
  }
  if (mode === "daytona") {
    console.log(`Batch Size: ${daytonaBatchSize}`);
  }
  console.log("═".repeat(55));
  console.log("");

  // Build config
  const config: BenchmarkSuiteConfig = {
    repoUrl,
    repoDir,
    branches,
    model,
    outputDir,
    mode,
    timeoutMinutes,
    daytonaBatchSize,
    cleanupTempDirs,
    runComparison,
    costTracking,
  };

  // Run suite
  const suiteResult = await runBenchmarkSuite(config);

  // Print text report
  const textReport = generateTextReport(suiteResult);
  console.log(`\n${textReport}`);

  // Write JSON results
  mkdirSync(outputDir, { recursive: true });
  const timestamp = new Date().toISOString().replace(/[:.]/g, "-");
  const jsonPath = path.join(outputDir, `benchmark-results-${timestamp}.json`);
  writeFileSync(jsonPath, generateJsonReport(suiteResult));
  console.log(`\nJSON results written to: ${jsonPath}`);

  // Exit with appropriate code
  const { summary } = suiteResult;
  if (summary.failed > 0 || summary.timedOut > 0) {
    process.exit(1);
  }
}

main().catch((error) => {
  console.error("Fatal error:", error);
  process.exit(1);
});
