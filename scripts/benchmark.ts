#!/usr/bin/env tsx

import { exec as nodeExec } from "child_process";
import { promisify } from "util";
import { runAgent as runBenchmarkAgent } from "../src/core/agent/benchmark";
import type { AIModel } from "../src/core/ai";

const exec = promisify(nodeExec);

interface BenchmarkOptions {
  repoPath: string;
  branches?: string[];
  model?: AIModel;
}

async function getRepoBranches(repoPath: string): Promise<string[]> {
  const { stdout } = await exec(
    // List local branches without decorations (no leading "*" for current)
    "git for-each-ref --format='%(refname:short)' refs/heads",
    { cwd: repoPath }
  );

  return stdout
    .split("\n")
    .map((branch) => branch.trim().replace(/'/g, ""))
    .filter((branch) => branch.length > 0);
}

async function runBenchmark(options: BenchmarkOptions): Promise<void> {
  const {
    repoPath,
    branches,
    model = "claude-sonnet-4-5" as AIModel,
  } = options;

  console.log("=".repeat(80));
  console.log("PENSAR BENCHMARK RUNNER");
  console.log("=".repeat(80));
  console.log(`Repository: ${repoPath}`);
  console.log(`Model: ${model}`);
  console.log();

  // Get list of branches to test
  let branchesToTest: string[];
  if (branches && branches.length > 0) {
    branchesToTest = branches;
    console.log(`Testing specified branches: ${branchesToTest.join(", ")}`);
  } else {
    branchesToTest = await getRepoBranches(repoPath);
    console.log(`Testing all branches: ${branchesToTest.join(", ")}`);
  }

  console.log(`Total branches to test: ${branchesToTest.length}`);
  console.log();

  const results: Array<{
    branch: string;
    success: boolean;
    sessionId?: string;
    error?: string;
  }> = [];

  // Run benchmark for each branch
  for (let i = 0; i < branchesToTest.length; i++) {
    const branch = branchesToTest[i]!;
    console.log("=".repeat(80));
    console.log(
      `[${i + 1}/${branchesToTest.length}] Testing branch: ${branch}`
    );
    console.log("=".repeat(80));
    console.log();

    try {
      // Run the benchmark agent
      const { streamResult, session } = runBenchmarkAgent({
        repoPath,
        branch,
        model: model as AIModel,
      });

      // Consume the stream and display progress
      for await (const delta of streamResult.fullStream) {
        if (delta.type === "text-delta") {
          process.stdout.write(delta.text);
        } else if (delta.type === "tool-call") {
          console.log(
            `\n[Tool Call] ${delta.toolName}: ${
              delta.input.toolCallDescription || ""
            }`
          );
        } else if (delta.type === "tool-result") {
          console.log(`[Tool Result] Completed\n`);
        }
      }

      console.log();
      console.log(`✓ Benchmark completed successfully for branch: ${branch}`);
      console.log(`  Session ID: ${session.id}`);
      console.log(`  Results: ${session.rootPath}/benchmark_results.json`);
      console.log();

      results.push({
        branch,
        success: true,
        sessionId: session.id,
      });
    } catch (error: any) {
      console.error(`✗ Benchmark failed for branch: ${branch}`);
      console.error(`  Error: ${error.message}`);
      console.error();

      results.push({
        branch,
        success: false,
        error: error.message,
      });
    }
  }

  // Print summary
  console.log("=".repeat(80));
  console.log("BENCHMARK SUMMARY");
  console.log("=".repeat(80));
  console.log(`Total branches tested: ${branchesToTest.length}`);
  console.log(`Successful: ${results.filter((r) => r.success).length}`);
  console.log(`Failed: ${results.filter((r) => !r.success).length}`);
  console.log();

  for (const result of results) {
    const status = result.success ? "✓" : "✗";
    console.log(
      `${status} ${result.branch}${
        result.sessionId ? ` (${result.sessionId})` : ""
      }`
    );
    if (result.error) {
      console.log(`  Error: ${result.error}`);
    }
  }

  console.log();
  console.log("=".repeat(80));
}

// CLI interface
async function main() {
  const args = process.argv.slice(2);

  if (args.length === 0) {
    console.error(
      "Usage: tsx scripts/benchmark.ts <repo-path> [branch1 branch2 ...]"
    );
    console.error();
    console.error("Examples:");
    console.error("  tsx scripts/benchmark.ts /path/to/vulnerable-app");
    console.error("  tsx scripts/benchmark.ts /path/to/app main develop");
    console.error();
    console.error(
      "If no branches are specified, all branches in the repo will be tested."
    );
    process.exit(1);
  }

  const repoPath = args[0]!;
  const branches = args.slice(1);

  try {
    await runBenchmark({
      repoPath,
      branches: branches.length > 0 ? branches : undefined,
    });
  } catch (error: any) {
    console.error("Fatal error:", error.message);
    process.exit(1);
  }
}

// Run if called directly
if (require.main === module) {
  main().catch((error) => {
    console.error("Unhandled error:", error);
    process.exit(1);
  });
}

export { runBenchmark, getRepoBranches };
