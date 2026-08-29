#!/usr/bin/env bun

/**
 * pensar fixes — View security fixes via the Pensar API
 *
 * Usage:
 *   pensar fixes <issueId>          List fixes for an issue
 *   pensar fixes get <fixId>        Get fix details (includes diff)
 */

import { getFix, listFixes } from "../core/api";
import { markCommandFailed } from "./command-exit";

function showHelp(): void {
  console.log(`pensar fixes — View security fixes via the Pensar API

Usage:
  pensar fixes <issueId>         List fixes for an issue
  pensar fixes get <fixId>       Get fix details (includes diff)

Options:
  -h, --help                     Show this help message`);
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
        console.error("Error: fix ID is required");
        console.error("Usage: pensar fixes get <fixId>");
        return markCommandFailed();
      }
      const fix = await getFix(fixId);
      console.log(JSON.stringify(fix, null, 2));
    } else {
      const fixes = await listFixes(sub);
      console.log(JSON.stringify(fixes, null, 2));
    }
  } catch (err) {
    console.error(
      `\nError: ${err instanceof Error ? err.message : String(err)}`,
    );
    return markCommandFailed();
  }
}

await main();
