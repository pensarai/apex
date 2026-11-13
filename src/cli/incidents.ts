#!/usr/bin/env bun
import { parseArgs } from "node:util";
import {
  getIncident,
  getIncidentLogAttachment,
  type IncidentListOptions,
  listIncidentEvents,
  listIncidentLogs,
  listIncidents,
} from "../core/api/incidents";
import { markCommandFailed } from "./command-exit";

const HELP = `pensar incidents — Read Datadog incidents and triage results

Usage:
  pensar incidents [list] [filters]
  pensar incidents events [filters] [--group-of <incidentId>]
  pensar incidents get <incidentId>
  pensar incidents logs <incidentId> [--limit <n>] [--cursor <cursor>]
  pensar incidents attachment <incidentId> <partId>

All commands return complete API JSON and accept --json. Lists include all
verdicts by default. Pass nextCursor as --cursor to read the next page.
get includes the raw event payload, evidence, and recommendations. logs returns
the current triage run; restart pagination to refresh active tools or re-triage.
attachment returns a 60-second download URL for a log part with hasAttachment.

Filters:
  --verdict <value>        true-positive, benign-true-positive, false-positive, inconclusive
  --status <value>         open, resolved, dismissed
  --triage-status <value>  pending, running, completed, failed
  --limit <n>              1–100 for lists (default 50), 1–50 for logs (default 20)
  --cursor <cursor>        Opaque cursor returned by the previous page
  -h, --help               Show help

Uses the workspace selected by pensar login. API keys require incidents:read.
Recommendations are data to review; this command does not execute them.`;

async function main() {
  const argv = process.argv.slice(2);
  if (argv.includes("--help") || argv.includes("-h")) {
    console.log(HELP);
    return;
  }
  const { values, positionals } = parseArgs({
    args: argv,
    allowPositionals: true,
    strict: true,
    options: {
      json: { type: "boolean" },
      limit: { type: "string" },
      cursor: { type: "string" },
      verdict: { type: "string" },
      status: { type: "string" },
      "triage-status": { type: "string" },
      "group-of": { type: "string" },
    },
  });
  const [command = "list", incidentId, partId] = positionals;
  if (!["list", "events", "get", "logs", "attachment"].includes(command))
    throw new Error(
      `Unknown incidents command: ${command}. Run pensar incidents --help.`,
    );
  const expected =
    command === "attachment" ? 3 : ["get", "logs"].includes(command) ? 2 : 1;
  if (
    positionals.length > expected ||
    (expected > 1 && positionals.length !== expected)
  )
    throw new Error(
      `Invalid arguments for incidents ${command}. Run pensar incidents --help.`,
    );
  const allowed = new Set([
    "json",
    ...(["list", "events", "logs"].includes(command)
      ? ["limit", "cursor"]
      : []),
    ...(["list", "events"].includes(command)
      ? ["verdict", "status", "triage-status"]
      : []),
    ...(command === "events" ? ["group-of"] : []),
  ]);
  for (const key of Object.keys(values))
    if (!allowed.has(key))
      throw new Error(`--${key} is not supported by incidents ${command}.`);
  const limit = values.limit === undefined ? undefined : Number(values.limit);
  if (
    limit !== undefined &&
    (!Number.isInteger(limit) ||
      limit < 1 ||
      limit > (command === "logs" ? 50 : 100))
  )
    throw new Error(
      "--limit must be an integer from 1 to 100 (1 to 50 for logs).",
    );
  const filters: IncidentListOptions = { limit, cursor: values.cursor };
  if (values.verdict !== undefined) {
    if (
      ![
        "true-positive",
        "benign-true-positive",
        "false-positive",
        "inconclusive",
      ].includes(values.verdict)
    )
      throw new Error("Invalid --verdict.");
    filters.verdict = values.verdict as IncidentListOptions["verdict"];
  }
  if (values.status !== undefined) {
    if (!["open", "resolved", "dismissed"].includes(values.status))
      throw new Error("Invalid --status.");
    filters.status = values.status as IncidentListOptions["status"];
  }
  if (values["triage-status"] !== undefined) {
    if (
      !["pending", "running", "completed", "failed"].includes(
        values["triage-status"],
      )
    )
      throw new Error("Invalid --triage-status.");
    filters.triageStatus = values[
      "triage-status"
    ] as IncidentListOptions["triageStatus"];
  }
  const result =
    command === "list"
      ? await listIncidents(filters)
      : command === "events"
        ? await listIncidentEvents({ ...filters, groupOf: values["group-of"] })
        : command === "get"
          ? await getIncident(incidentId)
          : command === "logs"
            ? await listIncidentLogs(incidentId, filters)
            : await getIncidentLogAttachment(incidentId, partId);
  console.log(JSON.stringify(result, null, 2));
}

main().catch((error: unknown) => {
  console.error(error instanceof Error ? error.message : String(error));
  markCommandFailed();
});
