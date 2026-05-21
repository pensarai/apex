#!/usr/bin/env bun

/**
 * pensar fixes — View security fixes via the Pensar API
 *
 * Usage:
 *   pensar fixes <issueId>          List fixes for an issue
 *   pensar fixes get <fixId>        Get fix details (includes diff)
 */

import { getFix, listFixes } from "../core/api";

function showHelp(): void {
  process.stdout.write(`pensar fixes — View security fixes via the Pensar API

Usage:
  pensar fixes <issueId>         List fixes for an issue
  pensar fixes get <fixId>       Get fix details (includes diff)

Options:
  -h, --help                     Show this help message\n`);
}

async function main(): Promise<void> {
  const args = process.argv.slice(2);
  const sub = args[0];

  if (!sub || sub === "--help" || sub === "-h" || sub === "help") {
    showHelp();
    return;
  }

  try {
    if (sub === "get") {
      const fixId = args[1];
      if (!fixId) {
        process.stderr.write("Error: fix ID is required\n");
        process.stderr.write("Usage: pensar fixes get <fixId>\n");
        process.exit(1);
      }
      const fix = await getFix(fixId);
      process.stdout.write(`${JSON.stringify(fix, null, 2)}\n`);
    } else {
      const fixes = await listFixes(sub);
      process.stdout.write(`${JSON.stringify(fixes, null, 2)}\n`);
    }
  } catch (err) {
    process.stderr.write(
      `\nError: ${err instanceof Error ? err.message : String(err)}\n`,
    );
    process.exit(1);
  }
}

main();
