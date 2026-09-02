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
 *   pensar issues comments <issueId>              List review comments on an issue
 *   pensar issues comment <issueId> --body <text> Post a comment on an issue
 */

import type { ClosedDisposition } from "../core/api";
import {
  CLOSED_DISPOSITIONS,
  createIssueComment,
  getIssue,
  linkPullRequest,
  listIssueComments,
  listIssuePullRequests,
  listIssues,
  retestIssue,
  updateIssue,
} from "../core/api";
import { markCommandFailed } from "./command-exit";

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
  pensar issues comments <issueId>               List review comments on an issue
  pensar issues comment <issueId> --body <text>  Post a comment on an issue

<issueId> accepts the issue UUID or its label (e.g. VULN-000123).

Issue responses include "issueLabel" (e.g. VULN-000123, null for issues created
before labels existed) and "url", a deep link to the issue in the Console.

List filters:
  --status <status>     Filter: open, closed, false-positive, in-review
  --severity <sev>      Filter: critical, high, medium, low
  --scan <scanId>       Filter by scan ID
  --branch <branch>     Filter by branch

Update options:
  --status <status>         New status
  --closed-reason <reason>  Reason for closing
  --closed-comments <text>  Additional comments
  --disposition <value>     Why it is closed: resolved, wont-fix, out-of-scope,
                            risk-accepted
  --false-positive          Flag as false positive
  --fp-reason <reason>      Reason for false positive flag

Link-pr options:
  --url <url>               URL of the pull request to link (required)

Comments options:
  --page <n>                Page number (default 1)
  --page-size <n>           Comments per page (default 50, max 200)

Comment options:
  --body <text>             Comment text (required)

Comments are returned oldest first. Posting requires a user login; a workspace
API key has no author to attribute a comment to.

Options:
  -h, --help                Show this help message`);
}

async function main(): Promise<void> {
  const args = process.argv.slice(2);
  const sub = args[0];

  // `--help` anywhere wins, so `pensar issues update --help` prints usage
  // instead of forwarding "--help" through as an issue id.
  if (sub === "help" || args.includes("--help") || args.includes("-h")) {
    showHelp();
    return;
  }

  try {
    if (sub === "get") {
      const issueId = args[1];
      if (!issueId) {
        console.error("Error: issue ID is required");
        console.error("Usage: pensar issues get <issueId>");
        return markCommandFailed();
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
        return markCommandFailed();
      }
      const status = getFlag("--status", args) as
        | "open"
        | "closed"
        | "false-positive"
        | "in-review"
        | undefined;
      const closedReason = getFlag("--closed-reason", args);
      const closedComments = getFlag("--closed-comments", args);
      const dispositionFlag = getFlag("--disposition", args);
      if (
        dispositionFlag !== undefined &&
        !(CLOSED_DISPOSITIONS as readonly string[]).includes(dispositionFlag)
      ) {
        console.error(
          `Error: invalid --disposition "${dispositionFlag}". Accepted: ${CLOSED_DISPOSITIONS.join(", ")}`,
        );
        return markCommandFailed();
      }
      const closedDisposition = dispositionFlag as
        | ClosedDisposition
        | undefined;
      const userFlaggedFalsePositive = args.includes("--false-positive")
        ? true
        : undefined;
      const userFlaggedFalsePositiveReason = getFlag("--fp-reason", args);

      const result = await updateIssue(issueId, {
        status,
        closedReason,
        closedComments,
        closedDisposition,
        userFlaggedFalsePositive,
        userFlaggedFalsePositiveReason,
      });
      console.log(JSON.stringify(result, null, 2));
    } else if (sub === "retest") {
      const issueId = args[1];
      if (!issueId) {
        console.error("Error: issue ID is required");
        console.error("Usage: pensar issues retest <issueId>");
        return markCommandFailed();
      }
      const result = await retestIssue(issueId);
      console.log(JSON.stringify(result, null, 2));
    } else if (sub === "link-pr") {
      const issueId = args[1];
      const url = getFlag("--url", args);
      if (!issueId || issueId.startsWith("--") || !url) {
        console.error("Error: issue ID and --url are required");
        console.error("Usage: pensar issues link-pr <issueId> --url <prUrl>");
        return markCommandFailed();
      }
      const result = await linkPullRequest(issueId, url);
      console.log(JSON.stringify(result, null, 2));
    } else if (sub === "comments") {
      const issueId = args[1];
      if (!issueId || issueId.startsWith("--")) {
        console.error("Error: issue ID is required");
        console.error("Usage: pensar issues comments <issueId>");
        return markCommandFailed();
      }
      const page = getFlag("--page", args);
      const pageSize = getFlag("--page-size", args);
      const result = await listIssueComments(issueId, {
        page: page ? Number(page) : undefined,
        pageSize: pageSize ? Number(pageSize) : undefined,
      });
      console.log(JSON.stringify(result, null, 2));
    } else if (sub === "comment") {
      const issueId = args[1];
      const body = getFlag("--body", args);
      if (!issueId || issueId.startsWith("--") || !body) {
        console.error("Error: issue ID and --body are required");
        console.error('Usage: pensar issues comment <issueId> --body "<text>"');
        return markCommandFailed();
      }
      const result = await createIssueComment(issueId, body);
      console.log(JSON.stringify(result, null, 2));
    } else if (sub === "prs") {
      const issueId = args[1];
      if (!issueId) {
        console.error("Error: issue ID is required");
        console.error("Usage: pensar issues prs <issueId>");
        return markCommandFailed();
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
      return markCommandFailed();
    }
  } catch (err) {
    console.error(
      `\nError: ${err instanceof Error ? err.message : String(err)}`,
    );
    return markCommandFailed();
  }
}

await main();
