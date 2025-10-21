#!/usr/bin/env bun

/**
 * Pensar - AI-Powered Penetration Testing CLI
 *
 * This is the main entry point for the Pensar CLI tool.
 * It supports:
 * - Default (no args): Launches the OpenTUI-based terminal interface
 * - benchmark command: Runs the benchmark CLI
 */

import { fileURLToPath } from "url";
import { dirname, join } from "path";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

// Get command-line arguments (skip node/bun and script path)
const args = process.argv.slice(2);
const command = args[0];

// Handle different commands
if (command === "benchmark") {
  // Run benchmark CLI
  const benchmarkPath = join(__dirname, "..", "build", "benchmark.js");

  // Remove "benchmark" from args and pass the rest to benchmark script
  process.argv = [process.argv[0], benchmarkPath, ...args.slice(1)];

  // Import and run benchmark
  await import(benchmarkPath);
} else if (command === "--help" || command === "-h") {
  // Show help
  console.log("Pensar - AI-Powered Penetration Testing CLI");
  console.log();
  console.log("Usage:");
  console.log("  pensar              Launch the TUI (Terminal User Interface)");
  console.log("  pensar benchmark    Run the benchmark CLI");
  console.log();
  console.log("Options:");
  console.log("  -h, --help         Show this help message");
  console.log();
  console.log("Benchmark Usage:");
  console.log("  pensar benchmark <repo-path> [options] [branch1 branch2 ...]");
  console.log();
  console.log("Benchmark Options:");
  console.log("  --all-branches       Test all branches in the repository");
  console.log("  --limit <number>     Limit the number of branches to test");
  console.log("  --skip <number>      Skip the first N branches");
  console.log(
    "  --model <model>      Specify the AI model to use (default: claude-sonnet-4-5)"
  );
  console.log();
  console.log("Examples:");
  console.log("  pensar");
  console.log("  pensar benchmark /path/to/vulnerable-app");
  console.log("  pensar benchmark /path/to/app main develop");
  console.log("  pensar benchmark /path/to/app --all-branches --limit 3");
  console.log("  pensar benchmark /path/to/app --model gpt-4o");
} else if (args.length === 0) {
  // No command specified, run the TUI
  const appPath = join(__dirname, "..", "build", "index.js");
  await import(appPath);
} else {
  // Unknown command
  console.error(`Error: Unknown command '${command}'`);
  console.error();
  console.error("Run 'pensar --help' for usage information");
  process.exit(1);
}
