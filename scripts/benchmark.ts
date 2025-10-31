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
      "Usage: pensar benchmark <repo-path> [options] [branch1 branch2 ...]"
    );
    console.error();
    console.error("Options:");
    console.error("  --all-branches       Test all branches in the repository");
    console.error(
      "  --limit <number>     Limit the number of branches to test"
    );
    console.error("  --skip <number>      Skip the first N branches");
    console.error(
      "  --model <model>      Specify the AI model to use (default: claude-sonnet-4-5)"
    );
    console.error(
      "  --execution-mode <mode>  Where to run: local, daytona, runloop (default: local)"
    );
    console.error();
    console.error("Remote execution (daytona/runloop) requires:");
    console.error(
      "  - Repository URL (https://github.com/user/repo) instead of local path"
    );
    console.error("  - DAYTONA_API_KEY/RUNLOOP_API_KEY environment variable");
    console.error();
    console.error("Examples:");
    console.error("");
    console.error("Local execution:");
    console.error("  pensar benchmark /path/to/vulnerable-app");
    console.error("  pensar benchmark /path/to/app main develop");
    console.error("  pensar benchmark /path/to/app --all-branches");
    console.error("  pensar benchmark /path/to/app --model gpt-4o");
    console.error("");
    console.error("Remote execution (Daytona):");
    console.error("  pensar benchmark https://github.com/user/repo --execution-mode daytona");
    console.error("  pensar benchmark https://github.com/user/repo main --execution-mode daytona");
    console.error("  pensar benchmark https://github.com/user/repo main develop staging --execution-mode daytona");
    console.error("  pensar benchmark https://github.com/user/repo XBEN-001-24 --execution-mode daytona --model claude-haiku-4-5");
    console.error();
    console.error("Notes:");
    console.error("  - Local mode: defaults to all branches if none specified");
    console.error("  - Remote mode: defaults to 'main' if no branches specified");
    console.error("  - Remote mode: --all-branches flag not supported (specify branches explicitly)");
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

  // Check for --skip flag
  const skipIndex = args.indexOf("--skip");
  let skip: number | undefined;
  if (skipIndex !== -1) {
    const skipArg = args[skipIndex + 1];
    if (!skipArg) {
      console.error("Error: --skip must be followed by a number");
      process.exit(1);
    }
    const skipValue = parseInt(skipArg!, 10);
    if (!isNaN(skipValue) && skipValue >= 0) {
      skip = skipValue;
    } else {
      console.error("Error: --skip must be followed by a non-negative number");
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

  const executionModeIndex = args.indexOf("--execution-mode");
  let executionMode: "local" | "daytona" | "runloop" = "local";
  if (executionModeIndex !== -1) {
    const modeArg = args[executionModeIndex + 1];
    if (!modeArg || !["local", "daytona", "runloop"].includes(modeArg)) {
      console.error(
        "Error: --execution-mode must be one of: local, daytona, runloop"
      );
      process.exit(1);
    }
    executionMode = modeArg as "local" | "daytona" | "runloop";
  }

  // Get branch arguments (excluding flags)
  let branchArgs = args.slice(1).filter((arg, index, arr) => {
    if (
      arg === "--all-branches" ||
      arg === "--limit" ||
      arg === "--skip" ||
      arg === "--model" ||
      arg === "--execution-mode"
    ) {
      return false;
    }
    // Skip the value after --limit, --skip, --model, or --execution-mode
    if (
      index > 0 &&
      (arr[index - 1] === "--limit" ||
        arr[index - 1] === "--skip" ||
        arr[index - 1] === "--model" ||
        arr[index - 1] === "--execution-mode")
    ) {
      return false;
    }
    return true;
  });

  // Determine which branches to test
  let branches: string[] | undefined;

  // For remote execution modes, we can't auto-discover branches from a URL
  const isRemoteMode = executionMode !== "local";

  if (hasAllBranchesFlag) {
    if (isRemoteMode) {
      console.error("Error: --all-branches flag not supported in remote execution mode");
      console.error("Please specify branches explicitly, e.g.: main develop feature-x");
      process.exit(1);
    }
    // Explicitly get all branches from the repo
    console.log("Flag --all-branches detected, fetching all branches...");
    branches = await getRepoBranches(repoPath);
    console.log(`Found ${branches.length} branches`);
  } else if (branchArgs.length > 0) {
    // Use specified branches
    branches = branchArgs;
  } else {
    // Default behavior
    if (isRemoteMode) {
      // For remote mode, default to 'main' if no branches specified
      branches = ["main"];
      console.log("No branches specified, defaulting to 'main'");
    } else {
      // For local mode, test all branches
      branches = undefined;
    }
  }

  // Apply skip and limit if specified
  if ((skip !== undefined || limit !== undefined) && branches) {
    const startIndex = skip || 0;
    const endIndex = limit !== undefined ? startIndex + limit : undefined;
    if (skip !== undefined && limit !== undefined) {
      console.log(
        `Skipping ${skip} branches and limiting to ${limit} branches`
      );
    } else if (skip !== undefined) {
      console.log(`Skipping first ${skip} branches`);
    } else if (limit !== undefined) {
      console.log(`Limiting to first ${limit} branches`);
    }
    branches = branches.slice(startIndex, endIndex);
  } else if ((skip !== undefined || limit !== undefined) && !branches) {
    // Need to fetch branches to apply skip/limit
    const startIndex = skip || 0;
    const endIndex = limit !== undefined ? startIndex + limit : undefined;
    if (skip !== undefined && limit !== undefined) {
      console.log(`Fetching branches to skip ${skip} and limit to ${limit}...`);
    } else if (skip !== undefined) {
      console.log(`Fetching branches to skip first ${skip}...`);
    } else if (limit !== undefined) {
      console.log(`Fetching branches to apply limit of ${limit}...`);
    }
    const allBranches = await getRepoBranches(repoPath);
    branches = allBranches.slice(startIndex, endIndex);
  }

  try {
    if (executionMode === "local") {
      await runBenchmark({
        repoPath,
        branches,
        ...(model && { model }),
      });
    } else if (executionMode === "daytona") {
      // Remote execution in Daytona sandbox
      const { runBenchmarkInDaytona } = await import(
        "../src/core/agent/benchmark/remote/daytona-wrapper"
      );

      console.log("🌩️  Execution Mode: Daytona");
      console.log("⚠️  This will create a cloud sandbox and incur charges");
      console.log();

      // Validate repoPath is a URL
      if (!repoPath.startsWith("http")) {
        console.error("Error: Daytona mode requires a git repository URL");
        console.error("Example: https://github.com/user/repo");
        process.exit(1);
      }

      await runBenchmarkInDaytona({
        repoUrl: repoPath,
        branches,
        model: (model || "claude-sonnet-4-5") as AIModel,
      });
    } else if (executionMode === "runloop") {
      // Future: Runloop implementation
      throw new Error("Runloop execution mode not yet implemented");
    }
  } catch (error: any) {
    console.error("Fatal error:", error.message);
    process.exit(1);
  }
}

// Run if called directly (ESM version)
// When bundled, this will be the entry point, so we always run main
main().catch((error) => {
  console.error("Unhandled error:", error);
  process.exit(1);
});

export { runBenchmark, getRepoBranches };
