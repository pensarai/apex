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
  console.log(`Mode: Sequential (one at a time)`);
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
      "Usage: tsx scripts/benchmark.ts <repo-path> [options] [branch1 branch2 ...]"
    );
    console.error();
    console.error("Options:");
    console.error("  --all-branches       Test all branches in the repository");
    console.error(
      "  --limit <number>     Limit the number of branches to test"
    );
    console.error(
      "  --model <model>      Specify the AI model to use (default: claude-sonnet-4-5)"
    );
    console.error();
    console.error("Examples:");
    console.error("  tsx scripts/benchmark.ts /path/to/vulnerable-app");
    console.error("  tsx scripts/benchmark.ts /path/to/app main develop");
    console.error("  tsx scripts/benchmark.ts /path/to/app --all-branches");
    console.error(
      "  tsx scripts/benchmark.ts /path/to/app --all-branches --limit 3"
    );
    console.error("  tsx scripts/benchmark.ts /path/to/app --limit 5");
    console.error("  tsx scripts/benchmark.ts /path/to/app --model gpt-4o");
    console.error(
      "  tsx scripts/benchmark.ts /path/to/app --model claude-opus-4-1 --limit 3"
    );
    console.error();
    console.error(
      "If no branches are specified and --all-branches is not used,"
    );
    console.error("all branches will be tested by default.");
    process.exit(1);
  }

  const repoPath = args[0]!;

  // Check for --all-branches flag
  const allBranchesIndex = args.indexOf("--all-branches");
  const hasAllBranchesFlag = allBranchesIndex !== -1;

  // Check for --limit flag
  const limitIndex = args.indexOf("--limit");
  let limit: number | undefined;
  if (limitIndex !== -1) {
    const limitArg = args[limitIndex + 1];
    if (!limitArg) {
      console.error("Error: --limit must be followed by a number");
      process.exit(1);
    }
    const limitValue = parseInt(limitArg!, 10);
    if (!isNaN(limitValue) && limitValue > 0) {
      limit = limitValue;
    } else {
      console.error("Error: --limit must be followed by a positive number");
      process.exit(1);
    }
  }

  // Check for --model flag
  const modelIndex = args.indexOf("--model");
  let model: AIModel | undefined;
  if (modelIndex !== -1) {
    const modelArg = args[modelIndex + 1];
    if (!modelArg) {
      console.error("Error: --model must be followed by a model name");
      process.exit(1);
    }
    model = modelArg as AIModel;
  }

  // Get branch arguments (excluding flags)
  let branchArgs = args.slice(1).filter((arg, index, arr) => {
    if (arg === "--all-branches" || arg === "--limit" || arg === "--model") {
      return false;
    }
    // Skip the value after --limit or --model
    if (
      index > 0 &&
      (arr[index - 1] === "--limit" || arr[index - 1] === "--model")
    ) {
      return false;
    }
    return true;
  });

  // Determine which branches to test
  let branches: string[] | undefined;
  if (hasAllBranchesFlag) {
    // Explicitly get all branches from the repo
    console.log("Flag --all-branches detected, fetching all branches...");
    branches = await getRepoBranches(repoPath);
    console.log(`Found ${branches.length} branches`);
  } else if (branchArgs.length > 0) {
    // Use specified branches
    branches = branchArgs;
  } else {
    // Default behavior: test all branches
    branches = undefined;
  }

  // Apply limit if specified
  if (limit && branches) {
    console.log(`Limiting to first ${limit} branches`);
    branches = branches.slice(0, limit);
  } else if (limit && !branches) {
    // Need to fetch branches to apply limit
    console.log(`Fetching branches to apply limit of ${limit}...`);
    const allBranches = await getRepoBranches(repoPath);
    branches = allBranches.slice(0, limit);
  }

  try {
    await runBenchmark({
      repoPath,
      branches,
      ...(model && { model }),
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
