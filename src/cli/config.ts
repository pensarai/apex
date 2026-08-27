#!/usr/bin/env bun

// `pensar config headers` — manage global default HTTP headers in
// ~/.pensar/config.json. Snapshotted into new sessions at create time;
// existing sessions are not retroactively updated.

import { config } from "../core/config";
import {
  formatParseError,
  parseHeaderLine,
  parseHeadersFromFile,
} from "../core/http/parse";
import {
  type HeaderRecord,
  isSensitiveHeaderName,
  renderHeaderValue,
} from "../core/http/types";
import { markCommandFailed } from "./command-exit";

function showHelp(): void {
  console.log(`pensar config headers — Manage global default HTTP headers

Usage:
  pensar config headers list [--show]
  pensar config headers add    "Name: Value"
  pensar config headers set    "Name: Value"
  pensar config headers remove <Name>
  pensar config headers clear  [--yes]
  pensar config headers import <file>

Notes:
  - Stored in ~/.pensar/config.json under \`defaultHeaders\`.
  - New sessions snapshot these at create time. Existing sessions are
    not retroactively updated — use the operator /headers command or
    edit per-session config directly.
  - Values containing 'authorization', 'cookie', 'token', 'key',
    'secret', or 'password' are masked by default. Pass --show to
    reveal them in 'list'.`);
}

function printHeaders(headers: HeaderRecord, showSecrets: boolean): void {
  const entries = Object.entries(headers);
  if (entries.length === 0) {
    console.log("(no default headers configured)");
    return;
  }
  for (const [name, value] of entries) {
    const sensitive = isSensitiveHeaderName(name) ? "*" : " ";
    console.log(
      `${sensitive} ${name}: ${renderHeaderValue(name, value, showSecrets)}`,
    );
  }
}

async function loadDefaults(): Promise<HeaderRecord> {
  const cfg = await config.get();
  return cfg.defaultHeaders ? { ...cfg.defaultHeaders } : {};
}

async function saveDefaults(headers: HeaderRecord): Promise<void> {
  await config.update({
    defaultHeaders: headers,
    defaultHeadersUpdatedAt: new Date().toISOString(),
  });
}

async function cmdList(args: string[]): Promise<void> {
  const showSecrets = args.includes("--show");
  const headers = await loadDefaults();
  printHeaders(headers, showSecrets);
}

async function cmdAdd(args: string[], allowOverwrite: boolean): Promise<void> {
  const value = args[0];
  if (!value) {
    console.error('Error: expected "Name: Value" argument');
    return markCommandFailed();
  }
  const parsed = parseHeaderLine(value);
  if (!parsed.ok) {
    console.error(`Invalid header:\n${formatParseError(parsed.error)}`);
    return markCommandFailed();
  }
  const headers = await loadDefaults();
  const canonical = Object.keys(headers).find(
    (k) => k.toLowerCase() === parsed.value.name.toLowerCase(),
  );
  if (canonical && !allowOverwrite) {
    console.error(
      `Header "${canonical}" already exists. Use \`pensar config headers set\` to overwrite.`,
    );
    return markCommandFailed();
  }
  if (canonical && canonical !== parsed.value.name) {
    delete headers[canonical];
  }
  headers[parsed.value.name] = parsed.value.value;
  await saveDefaults(headers);
  console.log(`Updated default header: ${parsed.value.name}`);
}

async function cmdRemove(args: string[]): Promise<void> {
  const name = args[0];
  if (!name) {
    console.error("Error: expected <Name> argument");
    return markCommandFailed();
  }
  const headers = await loadDefaults();
  const canonical = Object.keys(headers).find(
    (k) => k.toLowerCase() === name.toLowerCase(),
  );
  if (!canonical) {
    console.error(`No default header named "${name}".`);
    return markCommandFailed();
  }
  delete headers[canonical];
  await saveDefaults(headers);
  console.log(`Removed default header: ${canonical}`);
}

async function cmdClear(args: string[]): Promise<void> {
  const confirmed = args.includes("--yes") || args.includes("-y");
  if (!confirmed) {
    console.error(
      "Refusing to clear without confirmation. Pass --yes to proceed.",
    );
    return markCommandFailed();
  }
  await saveDefaults({});
  console.log("Cleared all default headers.");
}

async function cmdImport(args: string[]): Promise<void> {
  const file = args[0];
  if (!file) {
    console.error("Error: expected <file> argument");
    return markCommandFailed();
  }
  const parsed = await parseHeadersFromFile(file);
  if (!parsed.ok) {
    for (const err of parsed.error) {
      console.error(`Import error:\n${formatParseError(err)}`);
    }
    return markCommandFailed();
  }
  const next: HeaderRecord = {};
  for (const entry of parsed.value) {
    next[entry.name] = entry.value;
  }
  await saveDefaults(next);
  console.log(
    `Replaced default headers with ${parsed.value.length} entries from ${file}.`,
  );
}

async function main(): Promise<void> {
  const args = process.argv.slice(2);

  if (args.length === 0 || args[0] === "--help" || args[0] === "-h") {
    showHelp();
    return;
  }

  const sub = args[0];
  if (sub !== "headers") {
    console.error(`Unknown 'pensar config' subcommand: ${sub}`);
    console.error("Only 'headers' is supported today.");
    return markCommandFailed();
  }

  const op = args[1];
  const rest = args.slice(2);

  switch (op) {
    case undefined:
    case "list":
      await cmdList(rest);
      break;
    case "add":
      await cmdAdd(rest, /* allowOverwrite */ false);
      break;
    case "set":
      await cmdAdd(rest, /* allowOverwrite */ true);
      break;
    case "remove":
    case "rm":
    case "delete":
      await cmdRemove(rest);
      break;
    case "clear":
      await cmdClear(rest);
      break;
    case "import":
      await cmdImport(rest);
      break;
    case "--help":
    case "-h":
      showHelp();
      break;
    default:
      console.error(`Unknown headers operation: ${op}`);
      showHelp();
      return markCommandFailed();
  }
}

await main().catch((err) => {
  console.error(`\nError: ${err instanceof Error ? err.message : String(err)}`);
  return markCommandFailed();
});
