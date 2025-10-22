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
} else if (command === "--help" || command === "-h") {
  // Show help
  console.log("Pensar - AI-Powered Penetration Testing CLI");
  console.log();
  console.log("Usage:");
  console.log("  pensar              Launch the TUI (Terminal User Interface)");
  console.log("  pensar benchmark    Run the benchmark CLI");
  console.log("  pensar quicktest    Run a quick penetration test");
  console.log(
    "  pensar swarm        Run parallel pentests on multiple targets"
  );
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
  console.log("Quicktest Usage:");
  console.log(
    "  pensar quicktest --target <target> --objective <objective> [--model <model>]"
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
  console.log();
  console.log("Swarm Usage:");
  console.log("  pensar swarm <targets> [--model <model>]");
  console.log();
  console.log("Swarm Arguments:");
  console.log("  <targets>                JSON string or path to JSON file");
  console.log();
  console.log("Swarm Options:");
  console.log(
    "  --model <model>          AI model to use (default: claude-sonnet-4-5)"
  );
  console.log();
  console.log("Targets format (JSON array):");
  console.log("  [");
  console.log("    {");
  console.log('      "target": "api.example.com",');
  console.log('      "objective": "Test API for injection vulnerabilities"');
  console.log("    },");
  console.log("    {");
  console.log('      "target": "admin.example.com",');
  console.log('      "objective": "Test admin panel for auth bypass"');
  console.log("    }");
  console.log("  ]");
  console.log();
  console.log("Examples:");
  console.log("  pensar");
  console.log("  pensar benchmark /path/to/vulnerable-app");
  console.log("  pensar benchmark /path/to/app main develop");
  console.log("  pensar benchmark /path/to/app --all-branches --limit 3");
  console.log("  pensar benchmark /path/to/app --model gpt-4o");
  console.log(
    "  pensar quicktest --target http://localhost:3000 --objective 'Find SQL injection'"
  );
  console.log(
    "  pensar quicktest --target 192.168.1.100 --objective 'Test auth bypass' --model gpt-4o"
  );
  console.log("  pensar swarm targets.json");
  console.log("  pensar swarm targets.json --model gpt-4o");
  console.log(
    '  pensar swarm \'[{"target":"api.example.com","objective":"Test API"}]\''
  );
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
