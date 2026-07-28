#!/usr/bin/env bun

/**
 * pensar issues — Manage security issues via the Pensar API
 *
 * All commands operate on the selected workspace (set via `pensar login`).
 *
 * Usage:
 *   pensar issues [filters]                       List issues in the workspace
 *   pensar issues get <issueId>                   Get issue details
 *   pensar issues update <issueId> [opts]         Update an issue
 *   pensar issues retest <issueId>                Retest an issue
 *   pensar issues link-pr <issueId> --url <url>   Link a pull request to an issue
 *   pensar issues prs <issueId>                   List pull requests linked to an issue
 */

import {
  getIssue,
  linkPullRequest,
  listIssuePullRequests,
  listIssues,
  retestIssue,
  updateIssue,
} from "../core/api";

function getFlag(flag: string, argv: string[]): string | undefined {
  const idx = argv.indexOf(flag);
  return idx !== -1 && idx + 1 < argv.length ? argv[idx + 1] : undefined;
}

function showHelp(): void {
  console.log(`pensar issues — Manage security issues via the Pensar API

All commands operate on the selected workspace (set via \`pensar login\`).

Usage:
  pensar issues [filters]                        List issues in the workspace
  pensar issues get <issueId>                    Get issue details
  pensar issues update <issueId> [options]       Update an issue
  pensar issues retest <issueId>                 Retest an issue
  pensar issues link-pr <issueId> --url <url>    Link a pull request to an issue
  pensar issues prs <issueId>                    List pull requests linked to an issue

<issueId> accepts the issue UUID or its label (e.g. VULN-000123).

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

Link-pr options:
  --url <url>               URL of the pull request to link (required)

Options:
  -h, --help                Show this help message`);
}

async function main(): Promise<void> {
  const args = process.argv.slice(2);
  const sub = args[0];

  if (sub === "--help" || sub === "-h" || sub === "help") {
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
    } else if (sub === "retest") {
      const issueId = args[1];
      if (!issueId) {
        console.error("Error: issue ID is required");
        console.error("Usage: pensar issues retest <issueId>");
        process.exit(1);
      }
      const result = await retestIssue(issueId);
      console.log(JSON.stringify(result, null, 2));
    } else if (sub === "link-pr") {
      const issueId = args[1];
      const url = getFlag("--url", args);
      if (!issueId || issueId.startsWith("--") || !url) {
        console.error("Error: issue ID and --url are required");
        console.error("Usage: pensar issues link-pr <issueId> --url <prUrl>");
        process.exit(1);
      }
      const result = await linkPullRequest(issueId, url);
      console.log(JSON.stringify(result, null, 2));
    } else if (sub === "prs") {
      const issueId = args[1];
      if (!issueId) {
        console.error("Error: issue ID is required");
        console.error("Usage: pensar issues prs <issueId>");
        process.exit(1);
      }
      const result = await listIssuePullRequests(issueId);
      console.log(JSON.stringify(result, null, 2));
    } else if (!sub || sub === "list" || sub.startsWith("--")) {
      const issues = await listIssues({
        scanId: getFlag("--scan", args),
        status: getFlag("--status", args),
        severity: getFlag("--severity", args),
        branch: getFlag("--branch", args),
      });
      console.log(JSON.stringify(issues, null, 2));
    } else {
      console.error(`Error: Unknown subcommand "${sub}"`);
      showHelp();
      process.exit(1);
    }
  } catch (err) {
    console.error(
      `\nError: ${err instanceof Error ? err.message : String(err)}`,
    );
    process.exit(1);
  }
}

main();
