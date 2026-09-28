#!/usr/bin/env bun

import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import path from "node:path";
import {
  type ArgusProviderComparison,
  type BenchmarkSuiteResult,
  generateArgusProviderComparisonJson,
  generateArgusProviderComparisonMarkdown,
} from "../src/core/benchmark";

type Options = {
  openrouter?: string;
  concentrate?: string;
  output?: string;
  perRunBudgetUsd: number;
};

function usage(): string {
  return `
Compare Argus GLM 5.3 Provider Results
=======================================

Usage:
  bun run scripts/compare-argus-provider-results.ts \\
    --openrouter <benchmark-results.json> \\
    --concentrate <benchmark-results.json> \\
    --output <dir> \\
    [--per-run-budget 25]
`;
}

function parseOptions(args: string[]): Required<Options> {
  const options: Options = { perRunBudgetUsd: 25 };
  for (let index = 0; index < args.length; index++) {
    const arg = args[index];
    const value = args[index + 1];
    if (arg === "--help" || arg === "-h") {
      process.stdout.write(usage());
      process.exit(0);
    }
    if (!value) throw new Error(`${arg} requires a value`);
    if (arg === "--openrouter") options.openrouter = path.resolve(value);
    else if (arg === "--concentrate") options.concentrate = path.resolve(value);
    else if (arg === "--output") options.output = path.resolve(value);
    else if (arg === "--per-run-budget")
      options.perRunBudgetUsd = Number(value);
    else throw new Error(`Unknown option: ${arg}`);
    index++;
  }
  if (!options.openrouter || !options.concentrate || !options.output) {
    throw new Error("--openrouter, --concentrate, and --output are required");
  }
  if (
    !Number.isFinite(options.perRunBudgetUsd) ||
    options.perRunBudgetUsd <= 0
  ) {
    throw new Error("--per-run-budget must be a finite positive number");
  }
  return options as Required<Options>;
}

function objectOf(value: unknown): Record<string, unknown> | undefined {
  return value !== null && typeof value === "object" && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : undefined;
}

function readResult(file: string, expectedModel: string): BenchmarkSuiteResult {
  const parsed = JSON.parse(readFileSync(file, "utf8")) as unknown;
  const result = objectOf(parsed);
  if (
    result?.model !== expectedModel ||
    !Array.isArray(result.results) ||
    !objectOf(result.summary)
  ) {
    throw new Error(`${file} is not an Argus result for ${expectedModel}`);
  }
  return result as unknown as BenchmarkSuiteResult;
}

async function main(): Promise<void> {
  const options = parseOptions(process.argv.slice(2));
  const comparison: ArgusProviderComparison = {
    openrouter: readResult(options.openrouter, "z-ai/glm-5.3"),
    concentrate: readResult(options.concentrate, "concentrate:glm-5.3"),
    perRunBudgetUsd: options.perRunBudgetUsd,
  };
  mkdirSync(options.output, { recursive: true });
  writeFileSync(
    path.join(options.output, "argus-glm-5.3-provider-comparison.json"),
    `${generateArgusProviderComparisonJson(comparison)}\n`,
  );
  writeFileSync(
    path.join(options.output, "argus-glm-5.3-provider-comparison.md"),
    generateArgusProviderComparisonMarkdown(comparison),
  );
  process.stdout.write(`Argus comparison written to ${options.output}\n`);
}

main().catch((error) => {
  process.stderr.write(
    `Comparison failed: ${error instanceof Error ? error.message : String(error)}\n`,
  );
  process.exitCode = 1;
});
