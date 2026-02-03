#!/usr/bin/env bun
/**
 * APEX Benchmark Runner
 *
 * Runs the APEX validation benchmarks from argus-validation-benchmarks repository
 * using Daytona sandboxes in parallel.
 *
 * Usage:
 *   bun run scripts/run-apex-benchmarks.ts --repo <url> --all --parallel 3
 *   bun run scripts/run-apex-benchmarks.ts --repo <url> --branches APEX-001-25,APEX-002-25
 */

import { existsSync, mkdirSync, writeFileSync, readFileSync, readdirSync } from "fs";
import path from "path";
import { execSync, spawn } from "child_process";
import pLimit from "p-limit";
import type { AIModel } from "../src/core/ai";
import { runBenchmarkWithDaytona } from "../src/core/agent/benchmark/remote/daytona-benchmark";
import type { APEXBenchmarkResults, APEXBenchmarkSummary, APEXBenchmarkEntry, ComparisonResult } from "../src/core/agent/benchmark/types";
import type { BenchmarkResults } from "../src/core/agent/benchmark/types";

// APEX benchmark branch names (APEX-001-25 through APEX-019-25)
const APEX_BRANCHES = [
  "APEX-001-25", // SSRF in URL Preview
  "APEX-002-25", // Cross-Site Scripting (XSS)
  "APEX-003-25", // Authentication/Session Issue
  "APEX-004-25", // NoSQL Operator Injection
  "APEX-005-25", // Blind SQL Injection (Time-Based)
  "APEX-006-25", // Race Condition (TOCTOU)
  "APEX-007-25", // Prototype Pollution to RCE
  "APEX-008-25", // OAuth 2.0 Redirect URI Bypass
  "APEX-009-25", // WebSocket Command Injection
  "APEX-010-25", // Multi-Step Chain (SSRF to Cloud Secrets)
  "APEX-011-25", // Second-Order SQL Injection
  "APEX-012-25", // Python Pickle Deserialization RCE
  "APEX-013-25", // GraphQL Batching Attack
  "APEX-014-25", // CORS Misconfiguration
  "APEX-015-25", // Path Traversal with Encoding Bypass
  "APEX-016-25", // HTTP Request Smuggling (CL.TE)
  "APEX-017-25", // Session Fixation to Account Takeover
  "APEX-018-25", // LDAP Injection Authentication Bypass
  "APEX-019-25", // Mass Assignment Privilege Escalation
];

// Vulnerability type mapping for each benchmark
const VULN_TYPE_MAP: Record<string, string> = {
  "APEX-001-25": "SSRF",
  "APEX-002-25": "XSS",
  "APEX-003-25": "Auth/Session",
  "APEX-004-25": "NoSQL Injection",
  "APEX-005-25": "Blind SQLi",
  "APEX-006-25": "Race Condition",
  "APEX-007-25": "Prototype Pollution",
  "APEX-008-25": "OAuth Bypass",
  "APEX-009-25": "WebSocket Injection",
  "APEX-010-25": "SSRF Chain",
  "APEX-011-25": "Second-Order SQLi",
  "APEX-012-25": "Deserialization RCE",
  "APEX-013-25": "GraphQL Attack",
  "APEX-014-25": "CORS Misconfig",
  "APEX-015-25": "Path Traversal",
  "APEX-016-25": "HTTP Smuggling",
  "APEX-017-25": "Session Fixation",
  "APEX-018-25": "LDAP Injection",
  "APEX-019-25": "Mass Assignment",
};

interface APEXBenchmarkConfig {
  repoUrl: string;
  branches: string[];
  maxParallel: number;
  batchSize: number;
  outputDir: string;
  model: AIModel;
  localRepoPath?: string; // Optional: use existing local clone
}

interface BatchResult {
  batchNumber: number;
  benchmarks: APEXBenchmarkEntry[];
  completed: number;
  failed: number;
  startTime: string;
  endTime: string;
  durationMinutes: number;
}

/**
 * Clone or update the benchmark repository
 */
async function setupRepository(repoUrl: string, localPath: string): Promise<void> {
  if (existsSync(localPath)) {
    console.log(`📁 Repository exists at ${localPath}, fetching updates...`);
    try {
      execSync("git fetch --all", { cwd: localPath, stdio: "pipe" });
      console.log("✅ Repository updated");
    } catch (error: any) {
      console.log(`⚠️  Failed to fetch updates: ${error.message}`);
    }
  } else {
    console.log(`📥 Cloning repository from ${repoUrl}...`);
    execSync(`git clone ${repoUrl} ${localPath}`, { stdio: "inherit" });
    console.log("✅ Repository cloned");
  }
}

/**
 * Checkout a specific branch
 */
async function checkoutBranch(repoPath: string, branch: string): Promise<boolean> {
  try {
    // Try direct checkout first (for existing local branches)
    // If that fails, create a local tracking branch from origin
    execSync(
      `git checkout ${branch} 2>/dev/null || git checkout -b ${branch} origin/${branch}`,
      { cwd: repoPath, stdio: "pipe" }
    );
    return true;
  } catch (error: any) {
    console.error(`❌ Failed to checkout ${branch}: ${error.message}`);
    return false;
  }
}

/**
 * Get list of available branches from the repository
 */
function getAvailableBranches(repoPath: string): string[] {
  try {
    const output = execSync("git branch -r", { cwd: repoPath, encoding: "utf-8" });
    return output
      .split("\n")
      .map(b => b.trim().replace("origin/", ""))
      .filter(b => b.startsWith("APEX-"));
  } catch (error) {
    return [];
  }
}

/**
 * Run a single APEX benchmark
 */
async function runSingleAPEXBenchmark(
  repoPath: string,
  benchmarkName: string,
  model: AIModel,
  outputDir: string
): Promise<APEXBenchmarkEntry> {
  const benchmarkOutputDir = path.join(outputDir, "benchmarks", benchmarkName);
  mkdirSync(benchmarkOutputDir, { recursive: true });

  console.log(`\n${"=".repeat(80)}`);
  console.log(`🚀 Starting ${benchmarkName} (${VULN_TYPE_MAP[benchmarkName] || "Unknown"})`);
  console.log(`${"=".repeat(80)}\n`);

  try {
    // Checkout the branch
    console.log(`📁 Checking out branch ${benchmarkName}...`);
    const checkoutSuccess = await checkoutBranch(repoPath, benchmarkName);
    if (!checkoutSuccess) {
      throw new Error(`Failed to checkout branch ${benchmarkName}`);
    }

    // Run the benchmark with Daytona
    // For APEX, benchmarkPath is the src/ directory within the checked out branch
    const benchmarkPath = path.join(repoPath, "src");

    const result = await runBenchmarkWithDaytona({
      benchmarkPath,
      benchmarkName,
      model,
      benchmarkType: "apex",
      vulnsMode: true,
      prefix: `apex-${benchmarkName.toLowerCase()}`,
    });

    // Copy results to output directory
    if (result.sessionPath && existsSync(result.sessionPath)) {
      const resultsFile = path.join(result.sessionPath, "benchmark_results.json");
      const comparisonFile = path.join(result.sessionPath, "comparison-results.json");

      if (existsSync(resultsFile)) {
        const resultsContent = readFileSync(resultsFile, "utf-8");
        writeFileSync(path.join(benchmarkOutputDir, "benchmark_results.json"), resultsContent);
      }

      if (existsSync(comparisonFile)) {
        const comparisonContent = readFileSync(comparisonFile, "utf-8");
        writeFileSync(path.join(benchmarkOutputDir, "comparison-results.json"), comparisonContent);
      }
    }

    // Extract comparison metrics
    const apexResult = result as APEXBenchmarkResults;
    const comparison = apexResult.comparison;

    return {
      name: benchmarkName,
      status: "success",
      vulnType: VULN_TYPE_MAP[benchmarkName],
      accuracy: comparison ? Math.round(comparison.accuracy * 100) : undefined,
      precision: comparison ? Math.round(comparison.precision * 100) : undefined,
      recall: comparison ? Math.round(comparison.recall * 100) : undefined,
      expectedVulns: comparison?.totalExpected,
      detectedVulns: comparison?.matched.length,
      sessionPath: result.sessionPath,
    };
  } catch (error: any) {
    console.error(`\n❌ ${benchmarkName} FAILED: ${error.message}`);

    // Determine error category
    const message = (error?.message || "").toLowerCase();
    let errorCategory = "unknown";
    if (message.includes("rate") || message.includes("429") || message.includes("overloaded")) {
      errorCategory = "rate_limit";
    } else if (message.includes("timeout") || message.includes("network") || message.includes("econnreset")) {
      errorCategory = "transient";
    } else if (message.includes("not found") || message.includes("invalid")) {
      errorCategory = "permanent";
    }

    return {
      name: benchmarkName,
      status: "failed",
      vulnType: VULN_TYPE_MAP[benchmarkName],
      error: error.message,
      errorCategory,
    };
  }
}

/**
 * Run benchmarks in batches
 */
async function runBenchmarksInBatches(
  config: APEXBenchmarkConfig
): Promise<APEXBenchmarkSummary> {
  const { branches, maxParallel, batchSize, outputDir, model, repoUrl } = config;
  const repoPath = config.localRepoPath || path.join(process.cwd(), ".pensar", "benchmarks", "apex-repo");

  // Setup repository
  await setupRepository(repoUrl, repoPath);

  // Verify branches exist
  const availableBranches = getAvailableBranches(repoPath);
  const validBranches = branches.filter(b => availableBranches.includes(b));
  const invalidBranches = branches.filter(b => !availableBranches.includes(b));

  if (invalidBranches.length > 0) {
    console.log(`⚠️  Branches not found: ${invalidBranches.join(", ")}`);
  }

  if (validBranches.length === 0) {
    throw new Error("No valid branches to run");
  }

  console.log(`\n📊 Running ${validBranches.length} benchmarks in batches of ${batchSize}`);
  console.log(`   Max parallel: ${maxParallel}`);
  console.log(`   Model: ${model}`);
  console.log(`   Output: ${outputDir}\n`);

  // Create output directory structure
  mkdirSync(path.join(outputDir, "benchmarks"), { recursive: true });
  mkdirSync(path.join(outputDir, "batches"), { recursive: true });

  const allResults: APEXBenchmarkEntry[] = [];
  const batchResults: BatchResult[] = [];
  const limit = pLimit(maxParallel);

  // Split into batches
  const batches: string[][] = [];
  for (let i = 0; i < validBranches.length; i += batchSize) {
    batches.push(validBranches.slice(i, i + batchSize));
  }

  // Process each batch
  for (let batchNum = 0; batchNum < batches.length; batchNum++) {
    const batch = batches[batchNum]!;
    const batchStartTime = new Date();

    console.log(`\n${"=".repeat(80)}`);
    console.log(`📦 BATCH ${batchNum + 1}/${batches.length}: ${batch.join(", ")}`);
    console.log(`${"=".repeat(80)}\n`);

    // Run batch in parallel with limit
    const batchPromises = batch.map(benchmarkName =>
      limit(async () => {
        // Each benchmark needs its own checkout, so we clone to a separate directory
        const benchmarkRepoPath = path.join(
          process.cwd(),
          ".pensar",
          "benchmarks",
          "apex-workspaces",
          benchmarkName
        );

        // Clone from the original remote URL (not local repo) so remote branches are available
        if (!existsSync(benchmarkRepoPath)) {
          mkdirSync(path.dirname(benchmarkRepoPath), { recursive: true });
          execSync(`git clone ${repoUrl} ${benchmarkRepoPath}`, { stdio: "pipe" });
        }

        return runSingleAPEXBenchmark(benchmarkRepoPath, benchmarkName, model, outputDir);
      })
    );

    const batchResultsSettled = await Promise.allSettled(batchPromises);
    const batchBenchmarkResults: APEXBenchmarkEntry[] = batchResultsSettled.map((settled, index) => {
      if (settled.status === "fulfilled") {
        return settled.value;
      } else {
        return {
          name: batch[index]!,
          status: "failed" as const,
          vulnType: VULN_TYPE_MAP[batch[index]!],
          error: settled.reason?.message || String(settled.reason),
          errorCategory: "unknown",
        };
      }
    });

    allResults.push(...batchBenchmarkResults);

    const batchEndTime = new Date();
    const batchDuration = (batchEndTime.getTime() - batchStartTime.getTime()) / 1000 / 60;

    const batchResult: BatchResult = {
      batchNumber: batchNum + 1,
      benchmarks: batchBenchmarkResults,
      completed: batchBenchmarkResults.filter(r => r.status === "success").length,
      failed: batchBenchmarkResults.filter(r => r.status === "failed").length,
      startTime: batchStartTime.toISOString(),
      endTime: batchEndTime.toISOString(),
      durationMinutes: Math.round(batchDuration * 10) / 10,
    };

    batchResults.push(batchResult);

    // Save batch summary
    const batchSummaryPath = path.join(outputDir, "batches", `batch-${batchNum + 1}-summary.json`);
    writeFileSync(batchSummaryPath, JSON.stringify(batchResult, null, 2));

    console.log(`\n📊 Batch ${batchNum + 1} complete: ${batchResult.completed}/${batch.length} succeeded in ${batchDuration.toFixed(1)}m`);
  }

  // Calculate aggregate metrics
  const successfulResults = allResults.filter(r => r.status === "success");
  const failedResults = allResults.filter(r => r.status === "failed");

  const avgAccuracy = successfulResults.length > 0
    ? successfulResults.reduce((sum, r) => sum + (r.accuracy || 0), 0) / successfulResults.length
    : 0;
  const avgPrecision = successfulResults.length > 0
    ? successfulResults.reduce((sum, r) => sum + (r.precision || 0), 0) / successfulResults.length
    : 0;
  const avgRecall = successfulResults.length > 0
    ? successfulResults.reduce((sum, r) => sum + (r.recall || 0), 0) / successfulResults.length
    : 0;

  // Generate summary
  const summary: APEXBenchmarkSummary = {
    timestamp: new Date().toISOString(),
    repoUrl,
    model,
    totalBenchmarks: validBranches.length,
    completed: successfulResults.length,
    failed: failedResults.length,
    aggregateMetrics: {
      avgAccuracy: Math.round(avgAccuracy * 10) / 10,
      avgPrecision: Math.round(avgPrecision * 10) / 10,
      avgRecall: Math.round(avgRecall * 10) / 10,
    },
    benchmarks: allResults,
    failedBenchmarks: failedResults.map(r => r.name),
  };

  // Save summary JSON
  const summaryJsonPath = path.join(outputDir, "summary.json");
  writeFileSync(summaryJsonPath, JSON.stringify(summary, null, 2));

  // Generate markdown report
  const markdownReport = generateMarkdownReport(summary, batchResults);
  const summaryMdPath = path.join(outputDir, "summary.md");
  writeFileSync(summaryMdPath, markdownReport);

  console.log(`\n${"=".repeat(80)}`);
  console.log("📊 APEX BENCHMARK SUMMARY");
  console.log(`${"=".repeat(80)}`);
  console.log(`Total: ${validBranches.length}`);
  console.log(`Completed: ${successfulResults.length}`);
  console.log(`Failed: ${failedResults.length}`);
  console.log(`Avg Accuracy: ${summary.aggregateMetrics.avgAccuracy}%`);
  console.log(`Avg Precision: ${summary.aggregateMetrics.avgPrecision}%`);
  console.log(`Avg Recall: ${summary.aggregateMetrics.avgRecall}%`);
  console.log(`${"=".repeat(80)}`);
  console.log(`\n📄 Results saved to: ${outputDir}`);

  if (failedResults.length > 0) {
    console.log(`\n⚠️  Failed benchmarks: ${failedResults.map(r => r.name).join(", ")}`);
    console.log("\nTo retry failed benchmarks:");
    console.log(`  bun run scripts/run-apex-benchmarks.ts --repo ${repoUrl} --branches ${failedResults.map(r => r.name).join(",")}`);
  }

  return summary;
}

/**
 * Generate markdown report
 */
function generateMarkdownReport(summary: APEXBenchmarkSummary, batches: BatchResult[]): string {
  const lines: string[] = [];

  lines.push("# APEX Benchmark Results\n");
  lines.push(`**Timestamp:** ${new Date(summary.timestamp).toLocaleString()}`);
  lines.push(`**Repository:** ${summary.repoUrl}`);
  lines.push(`**Model:** ${summary.model}`);
  lines.push("");

  lines.push("## Summary\n");
  lines.push(`| Metric | Value |`);
  lines.push(`|--------|-------|`);
  lines.push(`| Total Benchmarks | ${summary.totalBenchmarks} |`);
  lines.push(`| Completed | ${summary.completed} |`);
  lines.push(`| Failed | ${summary.failed} |`);
  lines.push(`| Avg Accuracy | ${summary.aggregateMetrics.avgAccuracy}% |`);
  lines.push(`| Avg Precision | ${summary.aggregateMetrics.avgPrecision}% |`);
  lines.push(`| Avg Recall | ${summary.aggregateMetrics.avgRecall}% |`);
  lines.push("");

  lines.push("## Results by Benchmark\n");
  lines.push(`| Benchmark | Vuln Type | Status | Accuracy | Precision | Recall | Matched |`);
  lines.push(`|-----------|-----------|--------|----------|-----------|--------|---------|`);

  for (const benchmark of summary.benchmarks) {
    const statusIcon = benchmark.status === "success" ? "✅" : "❌";
    const matched = benchmark.expectedVulns !== undefined && benchmark.detectedVulns !== undefined
      ? `${benchmark.detectedVulns}/${benchmark.expectedVulns}`
      : "-";

    lines.push(`| ${benchmark.name} | ${benchmark.vulnType || "-"} | ${statusIcon} | ${benchmark.accuracy ?? "-"}% | ${benchmark.precision ?? "-"}% | ${benchmark.recall ?? "-"}% | ${matched} |`);
  }
  lines.push("");

  // Batch results
  if (batches.length > 0) {
    lines.push("## Batch Execution\n");
    for (const batch of batches) {
      lines.push(`### Batch ${batch.batchNumber}`);
      lines.push(`- **Duration:** ${batch.durationMinutes}m`);
      lines.push(`- **Completed:** ${batch.completed}/${batch.benchmarks.length}`);
      lines.push(`- **Benchmarks:** ${batch.benchmarks.map(b => b.name).join(", ")}`);
      lines.push("");
    }
  }

  // Failed benchmarks
  if (summary.failedBenchmarks.length > 0) {
    lines.push("## Failed Benchmarks\n");
    for (const benchmark of summary.benchmarks.filter(b => b.status === "failed")) {
      lines.push(`### ${benchmark.name}`);
      lines.push(`- **Error Category:** ${benchmark.errorCategory || "unknown"}`);
      lines.push(`- **Error:** ${benchmark.error || "Unknown error"}`);
      lines.push("");
    }

    lines.push("### Retry Command\n");
    lines.push("```bash");
    lines.push(`bun run scripts/run-apex-benchmarks.ts \\`);
    lines.push(`  --repo ${summary.repoUrl} \\`);
    lines.push(`  --branches ${summary.failedBenchmarks.join(",")}`);
    lines.push("```");
    lines.push("");
  }

  return lines.join("\n");
}

/**
 * Parse command line arguments
 */
function parseArgs(): APEXBenchmarkConfig {
  const args = process.argv.slice(2);

  let repoUrl = "https://github.com/Yuvanesh-ux/argus-validation-benchmarks";
  let branches: string[] = [];
  let maxParallel = 3;
  let batchSize = 5;
  let model: AIModel = "claude-sonnet-4-20250514";
  let outputDir = "";

  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    const nextArg = args[i + 1];

    switch (arg) {
      case "--repo":
        if (nextArg) repoUrl = nextArg;
        i++;
        break;
      case "--branches":
        if (nextArg) branches = nextArg.split(",").map(b => b.trim());
        i++;
        break;
      case "--all":
        branches = [...APEX_BRANCHES];
        break;
      case "--parallel":
        if (nextArg) maxParallel = parseInt(nextArg, 10);
        i++;
        break;
      case "--batch-size":
        if (nextArg) batchSize = parseInt(nextArg, 10);
        i++;
        break;
      case "--model":
        if (nextArg) model = nextArg as AIModel;
        i++;
        break;
      case "--output":
        if (nextArg) outputDir = nextArg;
        i++;
        break;
      case "--help":
      case "-h":
        printUsage();
        process.exit(0);
    }
  }

  // Default branches if none specified
  if (branches.length === 0) {
    console.log("No branches specified. Use --all or --branches to specify benchmarks.\n");
    printUsage();
    process.exit(1);
  }

  // Default output directory
  if (!outputDir) {
    const timestamp = new Date().toISOString().replace(/[:.]/g, "-");
    outputDir = path.join(process.cwd(), ".pensar", "benchmarks", `apex-run-${timestamp}`);
  }

  return {
    repoUrl,
    branches,
    maxParallel,
    batchSize,
    outputDir,
    model,
  };
}

function printUsage(): void {
  console.log(`
APEX Benchmark Runner

Usage:
  bun run scripts/run-apex-benchmarks.ts [options]

Options:
  --repo <url>         Repository URL (default: argus-validation-benchmarks)
  --branches <list>    Comma-separated list of branch names (e.g., APEX-001-25,APEX-002-25)
  --all                Run all 19 APEX benchmarks
  --parallel <n>       Max parallel Daytona sandboxes (default: 3)
  --batch-size <n>     Benchmarks per batch (default: 5)
  --model <model>      AI model to use (default: claude-sonnet-4-20250514)
  --output <dir>       Output directory for results
  --help, -h           Show this help message

Examples:
  # Run all benchmarks with 3 parallel sandboxes
  bun run scripts/run-apex-benchmarks.ts --all --parallel 3

  # Run specific benchmarks
  bun run scripts/run-apex-benchmarks.ts --branches APEX-001-25,APEX-002-25,APEX-003-25

  # Run first batch only (5 benchmarks)
  bun run scripts/run-apex-benchmarks.ts --branches APEX-001-25,APEX-002-25,APEX-003-25,APEX-004-25,APEX-005-25

Environment Variables:
  DAYTONA_API_KEY      Required for Daytona sandbox creation
  ANTHROPIC_API_KEY    Required for AI model
  DOCKER_USERNAME      Optional, for private image pulls
  DOCKER_PASSWORD      Optional, for private image pulls
`);
}

// Main execution
async function main() {
  const config = parseArgs();

  console.log(`
${"=".repeat(80)}
🎯 APEX BENCHMARK RUNNER
${"=".repeat(80)}
Repository: ${config.repoUrl}
Benchmarks: ${config.branches.length}
Max Parallel: ${config.maxParallel}
Batch Size: ${config.batchSize}
Model: ${config.model}
Output: ${config.outputDir}
${"=".repeat(80)}
`);

  try {
    const summary = await runBenchmarksInBatches(config);

    // Exit with error code if any benchmarks failed
    if (summary.failed > 0) {
      process.exit(1);
    }
  } catch (error: any) {
    console.error(`\n❌ Fatal error: ${error.message}`);
    if (error.stack) {
      console.error(error.stack);
    }
    process.exit(1);
  }
}

main();
