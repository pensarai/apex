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
import { readFileSync } from "fs";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

// Get command-line arguments (skip node/bun and script path)
const args = process.argv.slice(2);
const command = args[0];

// Read package.json for version
const packageJsonPath = join(__dirname, "..", "package.json");
const packageJson = JSON.parse(readFileSync(packageJsonPath, "utf-8"));
const version = packageJson.version;

// Handle different commands
if (command === "benchmark") {
  // Run benchmark CLI
  const benchmarkPath = join(__dirname, "..", "build", "benchmark.js");

  // Remove "benchmark" from args and pass the rest to benchmark script
  process.argv = [process.argv[0], benchmarkPath, ...args.slice(1)];

  // Import and run benchmark
  await import(benchmarkPath);
} else if (command === "swarm") {
  const swarmPath = join(__dirname, "..", "build", "swarm.js");
  process.argv = [process.argv[0], swarmPath, ...args.slice(1)];
  await import(swarmPath);
} else if (command === "quicktest") {
  // Run quicktest CLI
  const quicktestPath = join(__dirname, "..", "build", "quicktest.js");

  // Remove "quicktest" from args and pass the rest to quicktest script
  process.argv = [process.argv[0], quicktestPath, ...args.slice(1)];

  // Import and run quicktest
  await import(quicktestPath);
} else if (command === "pentest") {
  // Run pentest CLI
  const pentestPath = join(__dirname, "..", "build", "pentest.js");

  // Remove "pentest" from args and pass the rest to pentest script
  process.argv = [process.argv[0], pentestPath, ...args.slice(1)];

  // Import and run pentest
  await import(pentestPath);
} else if (command === "version" || command === "--version" || command === "-v") {
  // Show version
  console.log(`v${version}`);
} else if (command === "help" || command === "--help" || command === "-h") {
  // Show help
  console.log("Pensar - AI-Powered Penetration Testing CLI");
  console.log();
  console.log("Usage:");
  console.log("  pensar              Launch the TUI (Terminal User Interface)");
  console.log("  pensar help         Show this help message");
  console.log("  pensar version      Show version number");
  console.log("  pensar benchmark    Run the benchmark CLI");
  console.log("  pensar quicktest    Run a quick penetration test");
  console.log("  pensar pentest      Run a comprehensive penetration test");
  console.log(
    "  pensar swarm        Run parallel pentests on multiple targets"
  );
  console.log();
  console.log("Options:");
  console.log("  -h, --help         Show this help message");
  console.log("  -v, --version      Show version number");
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
  console.log("Quicktest Usage:");
  console.log(
    "  pensar quicktest --target <target> --objective <objective> [options]"
  );
  console.log();
  console.log("Quicktest Options:");
  console.log(
    "  --target <target>        Target URL or IP address to test (required)"
  );
  console.log(
    "  --objective <objective>  Objective or goal of the pentest (required)"
  );
  console.log(
    "  --model <model>          AI model to use (default: claude-sonnet-4-5)"
  );
  console.log(
    "  --headers <mode>         Header mode: none, default, custom (default: default)"
  );
  console.log(
    "  --header <name:value>    Add custom header (requires --headers custom)"
  );
  console.log();
  console.log("Pentest Usage:");
  console.log(
    "  pensar pentest --target <target> [options]"
  );
  console.log();
  console.log("Pentest Options:");
  console.log(
    "  --target <target>        Target domain or organization (required)"
  );
  console.log(
    "  --model <model>          AI model to use (default: claude-sonnet-4-5)"
  );
  console.log(
    "  --headers <mode>         Header mode: none, default, custom (default: default)"
  );
  console.log(
    "  --header <name:value>    Add custom header (requires --headers custom)"
  );
  console.log();
  console.log("Swarm Usage:");
  console.log("  pensar swarm <targets> [options]");
  console.log();
  console.log("Swarm Arguments:");
  console.log("  <targets>                JSON string or path to JSON file");
  console.log();
  console.log("Swarm Options:");
  console.log(
    "  --model <model>          AI model to use (default: claude-sonnet-4-5)"
  );
  console.log(
    "  --headers <mode>         Header mode: none, default, custom (default: default)"
  );
  console.log(
    "  --header <name:value>    Add custom header (requires --headers custom)"
  );
  console.log();
  console.log("Header Modes (for quicktest, pentest, swarm):");
  console.log(
    "  none                     No custom headers added to requests"
  );
  console.log(
    "  default                  Add 'User-Agent: pensar-apex' to all offensive requests"
  );
  console.log(
    "  custom                   Use custom headers defined with --header flag"
  );
  console.log();
  console.log("Examples:");
  console.log("  pensar");
  console.log("  pensar benchmark /path/to/vulnerable-app");
  console.log("  pensar benchmark /path/to/app main develop");
  console.log("  pensar benchmark /path/to/app --all-branches --limit 3");
  console.log(
    "  pensar quicktest --target http://localhost:3000 --objective 'Find SQL injection'"
  );
  console.log(
    "  pensar quicktest --target api.example.com --objective 'API testing' --headers custom --header 'User-Agent: pensar_client123'"
  );
  console.log(
    "  pensar pentest --target example.com"
  );
  console.log(
    "  pensar pentest --target example.com --headers custom --header 'User-Agent: pensar_client123'"
  );
  console.log("  pensar swarm targets.json");
  console.log("  pensar swarm targets.json --headers none");
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
