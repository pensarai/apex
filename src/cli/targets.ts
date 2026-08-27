#!/usr/bin/env bun

/**
 * pensar targets — View pentest targets and their agent logs via the Pensar API
 *
 * A "target" is a single attack-surface endpoint exercised during a pentest.
 * Pentest execution logs are persisted against the target (not against the
 * issues it produced), so targets are the way to query the full pentest
 * activity for an endpoint — including runs that produced no issue.
 *
 * All commands operate on the selected workspace (set via `pensar login`).
 *
 * Usage:
 *   pensar targets <pentestId>                       List targets for a pentest
 *   pensar targets logs <targetId> [filters]          List agent logs for a target
 *   pensar targets search <targetId> <query> [opts]   Search agent logs for a target
 */

import {
  listPentestTargets,
  listTargetLogs,
  searchTargetLogs,
} from "../core/api";

function getFlag(flag: string, argv: string[]): string | undefined {
  const idx = argv.indexOf(flag);
  return idx !== -1 && idx + 1 < argv.length ? argv[idx + 1] : undefined;
}

function showHelp(): void {
  console.log(`pensar targets — View pentest targets and their agent logs

A target is a single endpoint tested during a pentest. Pentest logs are stored
per target, so this is how you query the full activity for an endpoint.

All commands operate on the selected workspace (set via \`pensar login\`).

Usage:
  pensar targets <pentestId>                      List targets for a pentest
  pensar targets logs <targetId> [filters]         List agent logs for a target
  pensar targets search <targetId> <query> [opts]  Search agent logs for a target

Logs filters:
  --level <level>       Filter: debug, info, warn, error
  --role <role>         Filter: assistant, user, system, tool-call, tool-result
  --limit <n>           Max entries (default: 100, max: 500)

Search options:
  --level <level>       Filter: debug, info, warn, error
  --role <role>         Filter: assistant, user, system, tool-call, tool-result
  --context <n>         Context lines around matches (default: 3)

Options:
  -h, --help            Show this help message`);
}

type LogLevel = "debug" | "info" | "warn" | "error";
type LogRole = "assistant" | "user" | "system" | "tool-call" | "tool-result";

async function main(): Promise<void> {
  const args = process.argv.slice(2);
  const sub = args[0];

  if (!sub || sub === "--help" || sub === "-h" || sub === "help") {
    showHelp();
    return;
  }

  try {
    if (sub === "logs") {
      const targetId = args[1];
      if (!targetId) {
        console.error("Error: target ID is required");
        console.error(
          "Usage: pensar targets logs <targetId> [--level <level>] [--role <role>] [--limit <n>]",
        );
        process.exit(1);
      }
      const level = getFlag("--level", args) as LogLevel | undefined;
      const role = getFlag("--role", args) as LogRole | undefined;
      const limitStr = getFlag("--limit", args);
      const limit = limitStr ? parseInt(limitStr, 10) : undefined;

      const result = await listTargetLogs(targetId, { level, role, limit });
      console.log(JSON.stringify(result, null, 2));
    } else if (sub === "search") {
      const targetId = args[1];
      const query = args[2];
      if (!targetId || !query) {
        console.error("Error: target ID and query are required");
        console.error(
          "Usage: pensar targets search <targetId> <query> [--level <level>] [--role <role>] [--context <n>]",
        );
        process.exit(1);
      }
      const level = getFlag("--level", args) as LogLevel | undefined;
      const role = getFlag("--role", args) as LogRole | undefined;
      const contextStr = getFlag("--context", args);
      const contextLines = contextStr ? parseInt(contextStr, 10) : undefined;

      const result = await searchTargetLogs(targetId, query, {
        level,
        role,
        contextLines,
      });
      console.log(JSON.stringify(result, null, 2));
    } else if (sub.startsWith("--")) {
      console.error("Error: pentest ID is required");
      console.error("Usage: pensar targets <pentestId>");
      process.exit(1);
    } else {
      const pentestId = sub;
      const targets = await listPentestTargets(pentestId);
      console.log(JSON.stringify(targets, null, 2));
    }
  } catch (err) {
    console.error(
      `\nError: ${err instanceof Error ? err.message : String(err)}`,
    );
    process.exit(1);
  }
}

await main();
