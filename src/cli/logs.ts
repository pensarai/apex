#!/usr/bin/env bun

/**
 * pensar logs — View agent execution logs via the Pensar API
 *
 * Usage:
 *   pensar logs <issueId> [filters]                List agent logs for an issue
 *   pensar logs search <issueId> <query> [opts]    Search agent logs
 */

import { listAgentLogs, searchAgentLogs } from "../core/api";

function getFlag(flag: string, argv: string[]): string | undefined {
  const idx = argv.indexOf(flag);
  return idx !== -1 && idx + 1 < argv.length ? argv[idx + 1] : undefined;
}

function showHelp(): void {
  process.stdout.write(`pensar logs — View agent execution logs via the Pensar API

Usage:
  pensar logs <issueId> [filters]                 List agent logs
  pensar logs search <issueId> <query> [options]  Search agent logs

List filters:
  --level <level>       Filter: debug, info, warn, error
  --role <role>         Filter: assistant, user, system, tool-call, tool-result
  --limit <n>           Max entries (default: 100, max: 500)

Search options:
  --level <level>       Filter: debug, info, warn, error
  --role <role>         Filter: assistant, user, system, tool-call, tool-result
  --context <n>         Context lines around matches (default: 3)

Options:
  -h, --help            Show this help message\n`);
}

async function main(): Promise<void> {
  const args = process.argv.slice(2);
  const sub = args[0];

  if (!sub || sub === "--help" || sub === "-h" || sub === "help") {
    showHelp();
    return;
  }

  try {
    if (sub === "search") {
      const issueId = args[1];
      const query = args[2];
      if (!issueId || !query) {
        process.stderr.write("Error: issue ID and query are required\n");
        process.stderr.write(
          "Usage: pensar logs search <issueId> <query> [--level <level>] [--role <role>] [--context <n>]\n",
        );
        process.exit(1);
      }
      const level = getFlag("--level", args) as
        | "debug"
        | "info"
        | "warn"
        | "error"
        | undefined;
      const role = getFlag("--role", args) as
        | "assistant"
        | "user"
        | "system"
        | "tool-call"
        | "tool-result"
        | undefined;
      const contextStr = getFlag("--context", args);
      const contextLines = contextStr ? parseInt(contextStr, 10) : undefined;

      const result = await searchAgentLogs(issueId, query, {
        level,
        role,
        contextLines,
      });
      process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
    } else {
      const issueId = sub;
      const level = getFlag("--level", args) as
        | "debug"
        | "info"
        | "warn"
        | "error"
        | undefined;
      const role = getFlag("--role", args) as
        | "assistant"
        | "user"
        | "system"
        | "tool-call"
        | "tool-result"
        | undefined;
      const limitStr = getFlag("--limit", args);
      const limit = limitStr ? parseInt(limitStr, 10) : undefined;

      const result = await listAgentLogs(issueId, { level, role, limit });
      process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
    }
  } catch (err) {
    process.stderr.write(
      `\nError: ${err instanceof Error ? err.message : String(err)}\n`,
    );
    process.exit(1);
  }
}

main();
