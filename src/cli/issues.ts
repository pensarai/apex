#!/usr/bin/env bun

/**
 * pensar issues — Manage security issues via the Pensar API
 *
 * Usage:
 *   pensar issues <projectId> [filters]          List issues for a project
 *   pensar issues get <issueId>                   Get issue details
 *   pensar issues update <issueId> [opts]         Update an issue
 */

import { listIssues, getIssue, updateIssue } from "../core/api/issues";

function getFlag(flag: string, argv: string[]): string | undefined {
  const idx = argv.indexOf(flag);
  return idx !== -1 && idx + 1 < argv.length ? argv[idx + 1] : undefined;
}

function showHelp(): void {
  console.log(`pensar issues — Manage security issues via the Pensar API

Usage:
  pensar issues <projectId> [filters]            List issues for a project
  pensar issues get <issueId>                    Get issue details
  pensar issues update <issueId> [options]       Update an issue

List filters:
  --status <status>     Filter: open, closed, false-positive, in-review
  --severity <sev>      Filter: critical, high, medium, low
  --scan <scanId>       Filter by scan ID
  --branch <branch>     Filter by branch

Update options:
  --status <status>         New status
  --closed-reason <reason>  Reason for closing
  --closed-comments <text>  Additional comments
  --false-positive          Flag as false positive
  --fp-reason <reason>      Reason for false positive flag

Options:
  -h, --help                Show this help message`);
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
      const issueId = args[1];
      if (!issueId) {
        console.error("Error: issue ID is required");
        console.error("Usage: pensar issues get <issueId>");
        process.exit(1);
      }
      const issue = await getIssue(issueId);
      console.log(JSON.stringify(issue, null, 2));
    } else if (sub === "update") {
      const issueId = args[1];
      if (!issueId) {
        console.error("Error: issue ID is required");
        console.error(
          "Usage: pensar issues update <issueId> [--status <status>] ...",
        );
        process.exit(1);
      }
      const status = getFlag("--status", args) as
        | "open"
        | "closed"
        | "false-positive"
        | "in-review"
        | undefined;
      const closedReason = getFlag("--closed-reason", args);
      const closedComments = getFlag("--closed-comments", args);
      const userFlaggedFalsePositive = args.includes("--false-positive")
        ? true
        : undefined;
      const userFlaggedFalsePositiveReason = getFlag("--fp-reason", args);

      const result = await updateIssue(issueId, {
        status,
        closedReason,
        closedComments,
        userFlaggedFalsePositive,
        userFlaggedFalsePositiveReason,
      });
      console.log(JSON.stringify(result, null, 2));
    } else {
      const projectId = sub;
      const issues = await listIssues(projectId, {
        scanId: getFlag("--scan", args),
        status: getFlag("--status", args),
        severity: getFlag("--severity", args),
        branch: getFlag("--branch", args),
      });
      console.log(JSON.stringify(issues, null, 2));
    }
  } catch (err) {
    console.error(
      `\nError: ${err instanceof Error ? err.message : String(err)}`,
    );
    process.exit(1);
  }
}

main();
