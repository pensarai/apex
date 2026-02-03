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
  console.log();
  console.log("Options:");
  console.log("  -h, --help         Show this help message");
  console.log("  -v, --version      Show version number");
  console.log();
}

// Route to the appropriate command
if (command === "version" || command === "--version" || command === "-v") {
  console.log(`v${version}`);
} else if (command === "help" || command === "--help" || command === "-h") {
  showHelp();
}else if (args.length === 0) {
  // No command specified, run the TUI
  await import("./tui/index.tsx");
} else {
  console.error(`Error: Unknown command '${command}'`);
  console.error();
  console.error("Run 'pensar --help' for usage information");
  process.exit(1);
}
