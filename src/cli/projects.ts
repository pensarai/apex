#!/usr/bin/env bun

/**
 * pensar projects — List workspace projects
 *
 * Usage:
 *   pensar projects              List all projects
 *   pensar projects --help       Show help
 */

import { listProjects } from "../core/api/issues";

function showHelp(): void {
  console.log("pensar projects — List workspace projects\n");
  console.log("Usage:");
  console.log("  pensar projects              List all projects");
  console.log();
  console.log("Options:");
  console.log("  -h, --help                   Show this help message");
}

async function main(): Promise<void> {
  const args = process.argv.slice(2);

  if (args.includes("--help") || args.includes("-h")) {
    showHelp();
    return;
  }

  try {
    const projects = await listProjects();
    console.log(JSON.stringify(projects, null, 2));
  } catch (err) {
    console.error(
      `\nError: ${err instanceof Error ? err.message : String(err)}`,
    );
    process.exit(1);
  }
}

main();
