#!/usr/bin/env bun

/**
 * pensar projects — List workspace projects
 *
 * Usage:
 *   pensar projects              List all projects
 *   pensar projects --help       Show help
 */

import { listProjects } from "../core/api";

function showHelp(): void {
  process.stdout.write(`pensar projects — List workspace projects

Usage:
  pensar projects              List all projects

Options:
  -h, --help                   Show this help message\n`);
}

async function main(): Promise<void> {
  const args = process.argv.slice(2);

  if (args.includes("--help") || args.includes("-h")) {
    showHelp();
    return;
  }

  try {
    const projects = await listProjects();
    process.stdout.write(`${JSON.stringify(projects, null, 2)}\n`);
  } catch (err) {
    process.stderr.write(
      `\nError: ${err instanceof Error ? err.message : String(err)}\n`,
    );
    process.exit(1);
  }
}

main();
