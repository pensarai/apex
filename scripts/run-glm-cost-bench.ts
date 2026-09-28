#!/usr/bin/env bun

import { mkdirSync, writeFileSync } from "node:fs";
import path from "node:path";
import {
  type CostBenchCaseId,
  generateCostBenchJson,
  generateCostBenchMarkdown,
  parseOpenRouterReferenceRates,
  runCostBench,
  summarizeCostBench,
} from "../src/core/benchmark";

const DEFAULT_OUTPUT_DIR = path.join(
  process.env.HOME ?? ".",
  ".pensar",
  "benchmark-reports",
  "glm-5.3-gateways",
);

type CliOptions = {
  repetitions: number;
  budgetUsd: number;
  reservePerCallUsd: number;
  cases?: CostBenchCaseId[];
  outputDir: string;
};

const VALID_CASES = new Set<CostBenchCaseId>([
  "exact-reasoning",
  "structured-extraction",
  "tool-call",
  "security-analysis",
  "long-context-cache",
]);

function usage(): string {
  return `
GLM 5.3 Gateway Cost Benchmark
==============================

Usage:
  bun run scripts/run-glm-cost-bench.ts [options]

Options:
  --repetitions <n>       Repetitions per case and gateway (default: 3)
  --budget <usd>          Provider-reported spend ceiling (default: 10)
  --reserve-per-call <n>  Required remaining budget before a call (default: 0.25)
  --cases <ids>           Comma-separated case IDs
  --smoke                 One exact-reasoning call per gateway
  --output <dir>          Result directory
  --help, -h              Show this help

Cases:
  exact-reasoning, structured-extraction, tool-call,
  security-analysis, long-context-cache
`;
}

function positiveNumber(value: string | undefined, flag: string): number {
  const parsed = Number(value);
  if (!Number.isFinite(parsed) || parsed <= 0) {
    throw new Error(`${flag} requires a finite positive number`);
  }
  return parsed;
}

function parseOptions(args: string[]): CliOptions {
  const options: CliOptions = {
    repetitions: 3,
    budgetUsd: 10,
    reservePerCallUsd: 0.25,
    outputDir: DEFAULT_OUTPUT_DIR,
  };

  for (let index = 0; index < args.length; index++) {
    const arg = args[index];
    const value = args[index + 1];
    if (arg === "--help" || arg === "-h") {
      process.stdout.write(usage());
      process.exit(0);
    }
    if (arg === "--repetitions") {
      options.repetitions = positiveNumber(value, arg);
      index++;
    } else if (arg === "--budget") {
      options.budgetUsd = positiveNumber(value, arg);
      index++;
    } else if (arg === "--reserve-per-call") {
      options.reservePerCallUsd = positiveNumber(value, arg);
      index++;
    } else if (arg === "--output") {
      if (!value) throw new Error("--output requires a directory");
      options.outputDir = path.resolve(value);
      index++;
    } else if (arg === "--cases") {
      if (!value) throw new Error("--cases requires at least one case ID");
      const cases = value.split(",").map((item) => item.trim());
      for (const caseId of cases) {
        if (!VALID_CASES.has(caseId as CostBenchCaseId)) {
          throw new Error(`Unknown benchmark case: ${caseId}`);
        }
      }
      options.cases = cases as CostBenchCaseId[];
      index++;
    } else if (arg === "--smoke") {
      options.repetitions = 1;
      options.budgetUsd = Math.min(options.budgetUsd, 1);
      options.cases = ["exact-reasoning"];
    } else {
      throw new Error(`Unknown option: ${arg}`);
    }
  }

  if (!Number.isSafeInteger(options.repetitions)) {
    throw new Error("--repetitions must be a positive integer");
  }
  return options;
}

function parseSstSecret(value: string | undefined): string | undefined {
  if (!value) return undefined;
  try {
    const parsed = JSON.parse(value) as { value?: unknown };
    if (typeof parsed.value === "string") {
      return parsed.value.trim() || undefined;
    }
  } catch {
    // SST can also inject the secret as a bare string.
    return value.trim() || undefined;
  }
  return undefined;
}

function requiredKeys(): {
  openRouterApiKey: string;
  concentrateApiKey: string;
} {
  const openRouterApiKey =
    process.env.OPENROUTER_API_KEY ??
    parseSstSecret(process.env.SST_RESOURCE_OpenrouterApiKey);
  const concentrateApiKey =
    process.env.CONCENTRATE_API_KEY ??
    parseSstSecret(process.env.SST_RESOURCE_ConcentrateApiKey);
  if (!openRouterApiKey || !concentrateApiKey) {
    throw new Error(
      "OPENROUTER_API_KEY and CONCENTRATE_API_KEY are required (directly or through SST secret resources)",
    );
  }
  return { openRouterApiKey, concentrateApiKey };
}

async function referenceRates() {
  const capturedAt = new Date().toISOString();
  const source = "https://openrouter.ai/api/v1/models";
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

async function main(): Promise<void> {
  const options = parseOptions(process.argv.slice(2));
  const keys = requiredKeys();
  const rates = await referenceRates();
  const result = await runCostBench({
    ...keys,
    referenceRates: rates,
    repetitions: options.repetitions,
    budgetUsd: options.budgetUsd,
    reservePerCallUsd: options.reservePerCallUsd,
    cases: options.cases,
  });
  const timestamp = result.startedAt.replace(/[:.]/g, "-");
  const outputDir = path.join(options.outputDir, timestamp);
  mkdirSync(outputDir, { recursive: true });
  const jsonPath = path.join(outputDir, "comparison.json");
  const markdownPath = path.join(outputDir, "comparison.md");
  writeFileSync(jsonPath, `${generateCostBenchJson(result)}\n`);
  writeFileSync(markdownPath, generateCostBenchMarkdown(result));

  const summary = summarizeCostBench(result);
  process.stdout.write(
    [
      `Results: ${outputDir}`,
      `OpenRouter: ${summary.gateways.openrouter.passed}/${summary.gateways.openrouter.samples} passed, $${summary.gateways.openrouter.providerCostUsd.toFixed(6)}`,
      `Concentrate: ${summary.gateways.concentrate.passed}/${summary.gateways.concentrate.samples} passed, $${summary.gateways.concentrate.providerCostUsd.toFixed(6)}`,
      `Total provider spend: $${result.spentUsd.toFixed(6)} / $${result.budgetUsd.toFixed(2)}`,
      "",
    ].join("\n"),
  );

  if (
    result.stoppedReason ||
    result.samples.some((sample) => sample.status === "error")
  ) {
    process.exitCode = 1;
  }
}

main().catch((error) => {
  process.stderr.write(
    `GLM cost benchmark failed: ${error instanceof Error ? error.message : String(error)}\n`,
  );
  process.exitCode = 1;
});
