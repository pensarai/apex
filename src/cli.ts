#!/usr/bin/env bun

/**
 * Pensar - AI-Powered Penetration Testing CLI
 *
 * Unified entry point for standalone binary compilation.
 * All modules are statically imported so Bun can bundle them.
 */

import packageJson from "../package.json";

// Get command-line arguments
const args = process.argv.slice(2);
const command = args[0];
const version = packageJson.version;

function showHelp() {
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
  console.log("  pensar pentest --target <target> [options]");
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
  console.log("  none                     No custom headers added to requests");
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
  console.log("  pensar pentest --target example.com");
  console.log("  pensar swarm targets.json");
}

// Route to the appropriate command
if (command === "version" || command === "--version" || command === "-v") {
  console.log(`v${version}`);
} else if (command === "help" || command === "--help" || command === "-h") {
  showHelp();
} else if (command === "benchmark") {
  // Remove "benchmark" from args before importing (the script parses process.argv)
  process.argv = [process.argv[0]!, process.argv[1]!, ...args.slice(1)];
  await import("../scripts/benchmark.ts");
} else if (command === "quicktest") {
  process.argv = [process.argv[0]!, process.argv[1]!, ...args.slice(1)];
  await import("../scripts/quicktest.ts");
} else if (command === "pentest") {
  process.argv = [process.argv[0]!, process.argv[1]!, ...args.slice(1)];
  await import("../scripts/pentest.ts");
} else if (command === "swarm") {
  process.argv = [process.argv[0]!, process.argv[1]!, ...args.slice(1)];
  await import("../scripts/swarm.ts");
} else if (args.length === 0) {
  // No command specified, run the TUI
  await import("./tui/index.tsx");
} else {
  console.error(`Error: Unknown command '${command}'`);
  console.error();
  console.error("Run 'pensar --help' for usage information");
  process.exit(1);
}
