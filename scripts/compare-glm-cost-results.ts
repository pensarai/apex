#!/usr/bin/env bun

import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import path from "node:path";
import {
  type BenchmarkSuiteResult,
  type CostBenchResult,
  type GlmGatewayCostComparison,
  generateGlmGatewayComparisonJson,
  generateGlmGatewayComparisonMarkdown,
} from "../src/core/benchmark";

type Options = {
  micro?: string;
  openrouterArgus?: string;
  concentrateArgus?: string;
  output?: string;
  budgetUsd: number;
};

function usage(): string {
  return `
Combine GLM 5.3 Cost Benchmark Results
=======================================

Usage:
  bun run scripts/compare-glm-cost-results.ts \\
    --micro <comparison.json> \\
    --openrouter-argus <benchmark-results.json> \\
    --concentrate-argus <benchmark-results.json> \\
    --output <dir> [--budget 100]
`;
}

function parseOptions(args: string[]): Required<Options> {
  const options: Options = { budgetUsd: 100 };
  for (let index = 0; index < args.length; index++) {
    const arg = args[index];
    const value = args[index + 1];
    if (arg === "--help" || arg === "-h") {
      process.stdout.write(usage());
      process.exit(0);
    }
    if (!value) throw new Error(`${arg} requires a value`);
    if (arg === "--micro") options.micro = path.resolve(value);
    else if (arg === "--openrouter-argus")
      options.openrouterArgus = path.resolve(value);
    else if (arg === "--concentrate-argus")
      options.concentrateArgus = path.resolve(value);
    else if (arg === "--output") options.output = path.resolve(value);
    else if (arg === "--budget") options.budgetUsd = Number(value);
    else throw new Error(`Unknown option: ${arg}`);
    index++;
  }
  if (
    !options.micro ||
    !options.openrouterArgus ||
    !options.concentrateArgus ||
    !options.output
  ) {
    throw new Error(
      "--micro, --openrouter-argus, --concentrate-argus, and --output are required",
    );
  }
  if (!Number.isFinite(options.budgetUsd) || options.budgetUsd <= 0) {
    throw new Error("--budget must be a finite positive number");
  }
  return options as Required<Options>;
}

function readJson(file: string): unknown {
  return JSON.parse(readFileSync(file, "utf8")) as unknown;
}

function objectOf(value: unknown): Record<string, unknown> | undefined {
  return value !== null && typeof value === "object" && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : undefined;
}

function microResult(file: string): CostBenchResult {
  const document = objectOf(readJson(file));
  const result = objectOf(document?.result);
  if (result?.benchmark !== "glm-5.3-gateway-cost") {
    throw new Error(`${file} is not a GLM 5.3 microbenchmark result`);
  }
  return result as unknown as CostBenchResult;
}

function argusResult(
  file: string,
  expectedModel: string,
): BenchmarkSuiteResult {
  const result = objectOf(readJson(file));
  if (
    result?.model !== expectedModel ||
    !Array.isArray(result.results) ||
    !objectOf(result.summary)
  ) {
    throw new Error(
      `${file} is not an Argus result for model ${expectedModel}`,
    );
  }
  return result as unknown as BenchmarkSuiteResult;
}

async function main(): Promise<void> {
  const options = parseOptions(process.argv.slice(2));
  const comparison: GlmGatewayCostComparison = {
    micro: microResult(options.micro),
    argus: {
      branch: "APEX-005-25",
      openrouter: argusResult(options.openrouterArgus, "z-ai/glm-5.3"),
      concentrate: argusResult(options.concentrateArgus, "concentrate:glm-5.3"),
    },
    budgetUsd: options.budgetUsd,
  };

  mkdirSync(options.output, { recursive: true });
  writeFileSync(
    path.join(options.output, "glm-5.3-gateway-comparison.json"),
    `${generateGlmGatewayComparisonJson(comparison)}\n`,
  );
  writeFileSync(
    path.join(options.output, "glm-5.3-gateway-comparison.md"),
    generateGlmGatewayComparisonMarkdown(comparison),
  );
  process.stdout.write(`Combined comparison written to ${options.output}\n`);
}

main().catch((error) => {
  process.stderr.write(
    `Comparison failed: ${error instanceof Error ? error.message : String(error)}\n`,
  );
  process.exitCode = 1;
});
