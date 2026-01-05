#!/usr/bin/env tsx

import { readdirSync, statSync, existsSync } from "fs";
import path from "path";
import {
  runBenchmarkWithDaytona,
  runMultipleBenchmarks,
} from "../src/core/agent/benchmark/remote/daytona-benchmark";
import type { AIModel } from "../src/core/ai";

// Global error handlers to catch silent crashes
process.on("uncaughtException", (error) => {
  console.error("\n❌ UNCAUGHT EXCEPTION:");
  console.error("   Error:", error.message);
  console.error("   Stack:", error.stack);
  process.exit(1);
});

process.on("unhandledRejection", (reason, promise) => {
  console.error("\n❌ UNHANDLED PROMISE REJECTION:");
  console.error("   Reason:", reason);
  console.error("   Promise:", promise);
  // Don't exit immediately - let the error propagate
});

interface CLIOptions {
  repoPath: string;
  benchmarks?: string[];
  model?: AIModel;
  apiKey?: string;
  orgId?: string;
  anthropicKey?: string;
  openrouterKey?: string;
  maxParallel?: number;
  continueRun?: boolean;
  prefix?: string;
  skip?: string[];
  dockerUsername?: string;
  dockerPassword?: string;
  pace?: boolean;
  vulns?: boolean;
}

/**
 * Get list of benchmarks that have already been run by checking ~/.pensar/executions
 * A benchmark is considered "complete" only if its directory contains benchmark_results.json
 * @param prefix Optional prefix to filter by (matches {prefix}-XBEN-* or {prefix}-FullChain* pattern)
 * @param isPace If true, match PACEbench FullChain patterns instead of XBEN
 */
function getCompletedBenchmarks(prefix?: string, isPace?: boolean): string[] {
  const executionsDir = path.join(process.env.HOME || "", ".pensar", "executions");

  if (!existsSync(executionsDir)) {
    return [];
  }

  try {
    const entries = readdirSync(executionsDir);
    const completedBenchmarks = new Set<string>();

    // Build the pattern based on prefix and benchmark type
    const patternPrefix = prefix || "benchmark";

    // Patterns for XBEN benchmarks
    const xbenNewPattern = new RegExp(`^${patternPrefix}-(XBEN-\\d+-\\d+)ses_`);
    const xbenLegacyPattern = new RegExp(`^${patternPrefix}-(XBEN-\\d+-\\d+)-[a-z0-9]+$`);

    // Patterns for PACEbench FullChain benchmarks
    const paceNewPattern = new RegExp(`^${patternPrefix}-(FullChain\\d+)ses_`);
    const paceLegacyPattern = new RegExp(`^${patternPrefix}-(FullChain\\d+)-[a-z0-9]+$`);

    for (const entry of entries) {
      const fullPath = path.join(executionsDir, entry);

      // Check if it's a directory and matches the expected pattern
      if (statSync(fullPath).isDirectory()) {
        let match;
        if (isPace) {
          match = entry.match(paceNewPattern) || entry.match(paceLegacyPattern);
        } else {
          match = entry.match(xbenNewPattern) || entry.match(xbenLegacyPattern);
        }

        if (match && match[1]) {
          // Check if benchmark_results.json exists (indicates completion)
          const resultsFile = path.join(fullPath, "benchmark_results.json");
          if (existsSync(resultsFile)) {
            completedBenchmarks.add(match[1]);
          }
        }
      }
    }

    return Array.from(completedBenchmarks);
  } catch (error: any) {
    console.warn(`Warning: Failed to read executions directory: ${error.message}`);
    return [];
  }
}

/**
 * Enumerate all XBEN-* benchmark directories in /benchmarks
 */
function enumerateXBENBenchmarks(repoPath: string): string[] {
  console.log(`🔍 Enumerating XBEN benchmarks in ${repoPath}/benchmarks...`);

  const benchmarksDir = path.join(repoPath, "benchmarks");

  if (!existsSync(benchmarksDir)) {
    throw new Error(`Benchmarks directory not found: ${benchmarksDir}`);
  }

  try {
    const entries = readdirSync(benchmarksDir);

    const xbenBenchmarks = entries.filter((entry) => {
      const fullPath = path.join(benchmarksDir, entry);
      const isDirectory = statSync(fullPath).isDirectory();
      const isXBEN = entry.startsWith("XBEN");
      return isDirectory && isXBEN;
    });

    console.log(`✅ Found ${xbenBenchmarks.length} XBEN benchmarks: ${xbenBenchmarks.join(", ")}`);

    return xbenBenchmarks;
  } catch (error: any) {
    throw new Error(`Failed to enumerate benchmarks: ${error.message}`);
  }
}

/**
 * Enumerate all FullChain* benchmark directories in /docker/FullChain
 */
function enumeratePACEBenchmarks(repoPath: string): string[] {
  console.log(`🔍 Enumerating PACEbench FullChain challenges in ${repoPath}/docker/FullChain...`);

  const fullchainDir = path.join(repoPath, "docker", "FullChain");

  if (!existsSync(fullchainDir)) {
    throw new Error(`FullChain directory not found: ${fullchainDir}`);
  }

  try {
    const entries = readdirSync(fullchainDir);

    const fullchainBenchmarks = entries.filter((entry) => {
      const fullPath = path.join(fullchainDir, entry);
      const isDirectory = statSync(fullPath).isDirectory();
      const isFullChain = entry.startsWith("FullChain");
      return isDirectory && isFullChain;
    });

    console.log(`✅ Found ${fullchainBenchmarks.length} FullChain challenges: ${fullchainBenchmarks.join(", ")}`);

    return fullchainBenchmarks;
  } catch (error: any) {
    throw new Error(`Failed to enumerate PACEbench challenges: ${error.message}`);
  }
}

/**
 * Get the benchmark path based on benchmark type
 */
function getBenchmarkPath(repoPath: string, benchmarkName: string, isPace: boolean): string {
  if (isPace) {
    return path.join(repoPath, "docker", "FullChain", benchmarkName);
  }
  return path.join(repoPath, "benchmarks", benchmarkName);
}

async function main() {
  const args = process.argv.slice(2);

  if (args.length === 0) {
    console.error("Usage: bun run scripts/daytona-benchmark.ts <repo-path> [options] [XBEN-001-24 XBEN-002-24 ...]");
    console.error();
    console.error("Arguments:");
    console.error("  <repo-path>          Local path to XBEN challenges repository");
    console.error();
    console.error("Options:");
    console.error("  --model <model>              AI model to use (default: claude-sonnet-4-5)");
    console.error("  --daytona-api-key <key>      Daytona API key (default: DAYTONA_API_KEY env)");
    console.error("  --daytona-org-id <id>        Daytona organization ID (optional, default: DAYTONA_ORG_ID env)");
    console.error("  --anthropic-key <key>        Anthropic API key (default: ANTHROPIC_API_KEY env)");
    console.error("  --openrouter-key <key>       OpenRouter API key (default: OPENROUTER_API_KEY env)");
    console.error("  --max-parallel <num>         Max concurrent sandboxes (default: 10)");
    console.error("  --prefix <prefix>            Prefix for benchmark session names and output directories");
    console.error("  --continue                   Skip benchmarks that have already been run");
    console.error("  --skip <benchmarks>          Comma-separated list of benchmarks to skip (e.g., XBEN-001-24,XBEN-002-24)");
    console.error("  --docker-username <user>     Docker Hub username for authenticated pulls (default: DOCKER_USERNAME env)");
    console.error("  --docker-password <pass>     Docker Hub password/token for authenticated pulls (default: DOCKER_PASSWORD env)");
    console.error("  --pace                       Run PACEbench FullChain challenges instead of XBEN");
    console.error("  --vulns                      Enable vulnerability detection mode (requires --pace)");
    console.error();
    console.error("Environment Variables Required:");
    console.error("  DAYTONA_API_KEY              Daytona API key (required)");
    console.error("  ANTHROPIC_API_KEY            Anthropic API key (or --anthropic-key)");
    console.error("  OPENROUTER_API_KEY           OpenRouter API key (or --openrouter-key)");
    console.error();
    console.error("Environment Variables Optional:");
    console.error("  DAYTONA_ORG_ID               Daytona organization ID");
    console.error("  DOCKER_USERNAME              Docker Hub username for authenticated pulls");
    console.error("  DOCKER_PASSWORD              Docker Hub password/token for authenticated pulls");
    console.error();
    console.error("Benchmark Selection:");
    console.error("  • If no benchmarks specified: Automatically runs ALL benchmarks in /benchmarks/XBEN-*");
    console.error("  • If benchmarks specified: Runs only those specific XBEN benchmarks");
    console.error();
    console.error("Examples:");
    console.error("  # Run ALL XBEN benchmarks (auto-discovers all /benchmarks/XBEN-* directories)");
    console.error("  bun run scripts/daytona-benchmark.ts /path/to/xben-challenges");
    console.error();
    console.error("  # Run specific XBEN benchmark(s)");
    console.error("  bun run scripts/daytona-benchmark.ts /path/to/xben-challenges XBEN-001-24");
    console.error("  bun run scripts/daytona-benchmark.ts /path/to/xben-challenges XBEN-001-24 XBEN-002-24");
    console.error();
    console.error("  # Run with custom model and parallel limit");
    console.error("  bun run scripts/daytona-benchmark.ts /path/to/xben-challenges \\");
    console.error("    --model claude-haiku-4-5 --max-parallel 2");
    console.error();
    console.error("How it works:");
    console.error("  - Uses Daytona Docker-in-Docker sandboxes for target isolation");
    console.error("  - Enumerates XBEN-* directories in /benchmarks");
    console.error("  - Uploads each benchmark directory to Daytona sandbox");
    console.error("  - Parses docker-compose to determine target port/URL");
    console.error("  - Runs docker compose up inside sandbox (DinD)");
    console.error("  - Agent runs locally with tool overrides for sandbox execution");
    console.error("  - Commands/HTTP proxied to sandbox (docker commands BLOCKED)");
    console.error("  - Re-runs POCs in sandbox and saves outputs");
    console.error("  - Detects flags in pentest artifacts");
    console.error("  - Generates comprehensive reports (JSON + Markdown)");
    console.error();
    console.error("Differences from local-benchmark:");
    console.error("  ✓ Full isolation between benchmarks (separate sandboxes)");
    console.error("  ✓ Each benchmark runs in its own Docker-in-Docker environment");
    console.error("  ✓ Can run many benchmarks in parallel safely");
    console.error("  ✗ Requires Daytona API key");
    console.error("  ✗ Slower startup due to sandbox provisioning");
    console.error();
    process.exit(1);
  }

  const repoPath = args[0]!;

  // Validate repo path exists
  if (!existsSync(repoPath)) {
    console.error(`Error: Repository path does not exist: ${repoPath}`);
    process.exit(1);
  }

  if (!statSync(repoPath).isDirectory()) {
    console.error(`Error: Path is not a directory: ${repoPath}`);
    process.exit(1);
  }

  // Parse options
  const options: CLIOptions = { repoPath };

  // Parse --model
  const modelIndex = args.indexOf("--model");
  if (modelIndex !== -1) {
    const modelValue = args[modelIndex + 1];
    if (!modelValue) {
      console.error("Error: --model must be followed by a model name");
      process.exit(1);
    }
    options.model = modelValue as AIModel;
  }

  // Parse --daytona-api-key
  const apiKeyIndex = args.indexOf("--daytona-api-key");
  if (apiKeyIndex !== -1) {
    const apiKeyValue = args[apiKeyIndex + 1];
    if (!apiKeyValue) {
      console.error("Error: --daytona-api-key must be followed by a key");
      process.exit(1);
    }
    options.apiKey = apiKeyValue;
  }

  // Parse --daytona-org-id
  const orgIdIndex = args.indexOf("--daytona-org-id");
  if (orgIdIndex !== -1) {
    const orgIdValue = args[orgIdIndex + 1];
    if (!orgIdValue) {
      console.error("Error: --daytona-org-id must be followed by an ID");
      process.exit(1);
    }
    options.orgId = orgIdValue;
  }

  // Parse --anthropic-key
  const anthropicKeyIndex = args.indexOf("--anthropic-key");
  if (anthropicKeyIndex !== -1) {
    const anthropicKeyValue = args[anthropicKeyIndex + 1];
    if (!anthropicKeyValue) {
      console.error("Error: --anthropic-key must be followed by a key");
      process.exit(1);
    }
    options.anthropicKey = anthropicKeyValue;
  }

  // Parse --openrouter-key
  const openrouterKeyIndex = args.indexOf("--openrouter-key");
  if (openrouterKeyIndex !== -1) {
    const openrouterKeyValue = args[openrouterKeyIndex + 1];
    if (!openrouterKeyValue) {
      console.error("Error: --openrouter-key must be followed by a key");
      process.exit(1);
    }
    options.openrouterKey = openrouterKeyValue;
  }

  // Parse --max-parallel
  const maxParallelIndex = args.indexOf("--max-parallel");
  if (maxParallelIndex !== -1) {
    const maxParallelValue = args[maxParallelIndex + 1];
    if (!maxParallelValue) {
      console.error("Error: --max-parallel must be followed by a number");
      process.exit(1);
    }
    const maxParallelNum = parseInt(maxParallelValue, 10);
    if (isNaN(maxParallelNum) || maxParallelNum < 1) {
      console.error("Error: --max-parallel must be a positive number");
      process.exit(1);
    }
    options.maxParallel = maxParallelNum;
  }

  // Parse --prefix
  const prefixIndex = args.indexOf("--prefix");
  if (prefixIndex !== -1) {
    const prefixValue = args[prefixIndex + 1];
    if (!prefixValue) {
      console.error("Error: --prefix must be followed by a prefix string");
      process.exit(1);
    }
    options.prefix = prefixValue;
  }

  // Parse --skip
  const skipIndex = args.indexOf("--skip");
  if (skipIndex !== -1) {
    const skipValue = args[skipIndex + 1];
    if (!skipValue) {
      console.error("Error: --skip must be followed by a comma-separated list of benchmarks");
      process.exit(1);
    }
    options.skip = skipValue.split(",").map((s) => s.trim());
  }

  // Parse --docker-username
  const dockerUsernameIndex = args.indexOf("--docker-username");
  if (dockerUsernameIndex !== -1) {
    const dockerUsernameValue = args[dockerUsernameIndex + 1];
    if (!dockerUsernameValue) {
      console.error("Error: --docker-username must be followed by a username");
      process.exit(1);
    }
    options.dockerUsername = dockerUsernameValue;
  }

  // Parse --docker-password
  const dockerPasswordIndex = args.indexOf("--docker-password");
  if (dockerPasswordIndex !== -1) {
    const dockerPasswordValue = args[dockerPasswordIndex + 1];
    if (!dockerPasswordValue) {
      console.error("Error: --docker-password must be followed by a password/token");
      process.exit(1);
    }
    options.dockerPassword = dockerPasswordValue;
  }

  // Parse --continue
  if (args.includes("--continue")) {
    options.continueRun = true;
  }

  // Parse --pace
  if (args.includes("--pace")) {
    options.pace = true;
  }

  // Parse --vulns
  if (args.includes("--vulns")) {
    options.vulns = true;
  }

  // Parse benchmark arguments (anything that's not a flag or flag value)
  // Flags with values (need to skip the next arg)
  const flagsWithValues = [
    "--model",
    "--daytona-api-key",
    "--daytona-org-id",
    "--anthropic-key",
    "--openrouter-key",
    "--max-parallel",
    "--prefix",
    "--skip",
    "--docker-username",
    "--docker-password",
  ];

  // Boolean flags (no value, don't skip next arg)
  const booleanFlags = [
    "--continue",
    "--pace",
    "--vulns",
  ];

  const benchmarks: string[] = [];
  for (let i = 1; i < args.length; i++) {
    const arg = args[i]!;

    // Skip boolean flags (no value to skip)
    if (booleanFlags.includes(arg)) {
      continue;
    }

    // Skip flags with values and their values
    if (flagsWithValues.includes(arg)) {
      i++; // Also skip the next arg (flag value)
      continue;
    }

    // Skip if this is a value for a previous flag
    if (i > 0 && flagsWithValues.includes(args[i - 1]!)) {
      continue;
    }

    // This is a benchmark name
    benchmarks.push(arg);
  }

  // Validate --vulns requires --pace
  if (options.vulns && !options.pace) {
    console.error("Error: --vulns flag requires --pace flag");
    process.exit(1);
  }

  // If no benchmarks specified, enumerate based on benchmark type
  let targetBenchmarks: string[];
  if (benchmarks.length === 0) {
    if (options.pace) {
      console.log("No benchmarks specified, enumerating all PACEbench FullChain challenges...\n");
      targetBenchmarks = enumeratePACEBenchmarks(repoPath);

      if (targetBenchmarks.length === 0) {
        console.error("Error: No FullChain challenges found in /docker/FullChain directory");
        console.error("Please ensure the repository has /docker/FullChain/FullChain* directories");
        console.error("Or specify benchmarks manually as arguments");
        process.exit(1);
      }
    } else {
      console.log("No benchmarks specified, enumerating all XBEN-* benchmarks...\n");
      targetBenchmarks = enumerateXBENBenchmarks(repoPath);

      if (targetBenchmarks.length === 0) {
        console.error("Error: No XBEN benchmarks found in /benchmarks directory");
        console.error("Please ensure the repository has /benchmarks/XBEN-* directories");
        console.error("Or specify benchmarks manually as arguments");
        process.exit(1);
      }
    }
  } else {
    targetBenchmarks = benchmarks;
    console.log(`Using specified benchmarks: ${targetBenchmarks.join(", ")}\n`);
  }

  // Filter out already-completed benchmarks if --continue flag is set
  if (options.continueRun) {
    const completedBenchmarks = getCompletedBenchmarks(options.prefix, options.pace);
    if (completedBenchmarks.length > 0) {
      console.log(`🔍 Found ${completedBenchmarks.length} already-completed benchmarks${options.prefix ? ` (prefix: ${options.prefix})` : ""}: ${completedBenchmarks.join(", ")}`);
      const originalCount = targetBenchmarks.length;
      targetBenchmarks = targetBenchmarks.filter(b => !completedBenchmarks.includes(b));
      const skippedCount = originalCount - targetBenchmarks.length;
      console.log(`⏭️  Skipping ${skippedCount} benchmarks, ${targetBenchmarks.length} remaining\n`);

      if (targetBenchmarks.length === 0) {
        console.log("✅ All benchmarks have already been completed!");
        process.exit(0);
      }
    } else {
      console.log(`🔍 No previously completed benchmarks found${options.prefix ? ` (prefix: ${options.prefix})` : ""}, running all benchmarks\n`);
    }
  }

  // Filter out explicitly skipped benchmarks
  if (options.skip && options.skip.length > 0) {
    const originalCount = targetBenchmarks.length;
    targetBenchmarks = targetBenchmarks.filter(b => !options.skip!.includes(b));
    const skippedCount = originalCount - targetBenchmarks.length;
    console.log(`⏭️  Skipping ${skippedCount} benchmarks via --skip flag: ${options.skip.join(", ")}`);
    console.log(`   ${targetBenchmarks.length} benchmarks remaining\n`);

    if (targetBenchmarks.length === 0) {
      console.log("❌ All benchmarks have been skipped! Nothing to run.");
      process.exit(1);
    }
  }

  options.benchmarks = targetBenchmarks;

  // Validate environment variables
  const apiKey = options.apiKey || process.env.DAYTONA_API_KEY;
  const orgId = options.orgId || process.env.DAYTONA_ORG_ID;
  const anthropicKey = options.anthropicKey || process.env.ANTHROPIC_API_KEY;
  const openrouterKey = options.openrouterKey || process.env.OPENROUTER_API_KEY;
  const dockerUsername = options.dockerUsername || process.env.DOCKER_USERNAME;
  const dockerPassword = options.dockerPassword || process.env.DOCKER_PASSWORD;

  if (!apiKey) {
    console.error("Error: DAYTONA_API_KEY is required");
    console.error("Set it via environment variable or --daytona-api-key flag");
    process.exit(1);
  }

  if (!anthropicKey && !openrouterKey) {
    console.error("Error: At least one AI API key is required");
    console.error("Set ANTHROPIC_API_KEY or OPENROUTER_API_KEY environment variable");
    console.error("Or use --anthropic-key or --openrouter-key flag");
    process.exit(1);
  }

  // Display configuration
  console.log("\n" + "=".repeat(80));
  console.log("DAYTONA DOCKER-IN-DOCKER BENCHMARK RUNNER");
  console.log("=".repeat(80));
  console.log(`Repository: ${options.repoPath}`);
  console.log(`Benchmark Type: ${options.pace ? "PACEbench FullChain" : "XBEN"}${options.vulns ? " (vulnerability detection mode)" : ""}`);
  console.log(`Benchmarks: ${targetBenchmarks.join(", ")}`);
  console.log(`Total Benchmarks: ${targetBenchmarks.length}`);
  console.log(`Model: ${options.model || "claude-sonnet-4-5"}`);
  console.log(`Max Parallel: ${options.maxParallel || 10}`);
  if (orgId) {
    console.log(`Daytona Org: ${orgId}`);
  }
  if (options.prefix) {
    console.log(`Prefix: ${options.prefix}`);
  }
  console.log(`AI Keys: ${anthropicKey ? "Anthropic ✓" : ""} ${openrouterKey ? "OpenRouter ✓" : ""}`);
  console.log(`Docker Hub: ${dockerUsername ? `${dockerUsername} ✓` : "Not configured (may hit rate limits)"}`);
  console.log("=".repeat(80));
  console.log();
  console.log("Architecture:");
  console.log("  • Creates Daytona sandbox with Docker-in-Docker (DinD)");
  console.log("  • Uploads benchmark directory to sandbox");
  console.log("  • Parses docker-compose for target port");
  console.log("  • Runs docker compose inside sandbox (nested containers)");
  console.log("  • Agent runs locally with tool overrides");
  console.log("  • Commands/HTTP requests execute in sandbox");
  console.log("  • Docker commands BLOCKED to prevent cheating");
  console.log("  • Re-runs POCs in sandbox and saves outputs");
  console.log("  • Detects flags in pentest artifacts");
  console.log("  • Generates JSON + Markdown reports");
  console.log("=".repeat(80) + "\n");

  try {
    if (targetBenchmarks.length === 1) {
      // Single benchmark - run directly
      console.log(`Running single benchmark: ${targetBenchmarks[0]}`);
      const benchmarkPath = getBenchmarkPath(repoPath, targetBenchmarks[0]!, !!options.pace);
      await runBenchmarkWithDaytona({
        benchmarkPath,
        benchmarkName: targetBenchmarks[0]!,
        model: (options.model || "claude-sonnet-4-5") as AIModel,
        apiKey,
        orgId,
        anthropicKey,
        openrouterKey,
        prefix: options.prefix,
        dockerUsername,
        dockerPassword,
        benchmarkType: options.pace ? "pace" : "xben",
        vulnsMode: options.vulns,
      });
    } else {
      // Multiple benchmarks - run in parallel
      console.log(`Running parallel benchmark for ${targetBenchmarks.length} benchmarks`);
      await runMultipleBenchmarks({
        repoPath,
        benchmarks: targetBenchmarks,
        model: (options.model || "claude-sonnet-4-5") as AIModel,
        apiKey,
        orgId,
        anthropicKey,
        openrouterKey,
        maxParallel: options.maxParallel || 10,
        prefix: options.prefix,
        dockerUsername,
        dockerPassword,
        benchmarkType: options.pace ? "pace" : "xben",
        vulnsMode: options.vulns,
      });
    }

    console.log("\n✅ Benchmark execution completed successfully!");
  } catch (error: any) {
    console.error("\n❌ Benchmark execution failed:");
    console.error(error.message);
    if (error.stack) {
      console.error("\nStack trace:");
      console.error(error.stack);
    }
    process.exit(1);
  }
}

main().catch((error) => {
  console.error("Unhandled error:", error);
  process.exit(1);
});
