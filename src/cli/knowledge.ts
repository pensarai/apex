#!/usr/bin/env bun

/**
 * pensar knowledge — Read and edit the workspace knowledge base
 *
 * Usage:
 *   pensar knowledge [filters]              List entries
 *   pensar knowledge get <id>               Get one entry
 *   pensar knowledge add [options]          Add an entry
 *   pensar knowledge update <id> [options]  Edit an entry
 *   pensar knowledge archive <id>           Archive an entry
 */

import { parseArgs } from "node:util";
import {
  archiveKnowledge,
  createKnowledge,
  getKnowledge,
  KNOWLEDGE_CATEGORIES,
  KNOWLEDGE_STATUSES,
  type KnowledgeCategory,
  type KnowledgeInput,
  type KnowledgeStatus,
  listKnowledge,
  updateKnowledge,
} from "../core/api";
import { markCommandFailed } from "./command-exit";

function showHelp(): void {
  console.log(`pensar knowledge — Read and edit the workspace knowledge base

Entries are context that agents use during pentests. A false_positive_pattern
entry suppresses matching findings.

Usage:
  pensar knowledge [filters]              List entries
  pensar knowledge get <id>               Get one entry
  pensar knowledge add [options]          Add an entry
  pensar knowledge update <id> [options]  Edit an entry
  pensar knowledge archive <id>           Archive an entry

Filters and options:
  --title <text>         Entry title (required for add)
  --content <text>       Entry body (required for add)
  --category <category>  ${KNOWLEDGE_CATEGORIES.join(", ")}
                         (required for add)
  --status <status>      ${KNOWLEDGE_STATUSES.join(", ")}
  --tag <tags>           Repeat or separate with commas; a list filter
                         matches entries carrying every tag

Adding, editing and archiving require a user login; a workspace API key can
only read.

Options:
  -h, --help             Show this help message`);
}

function parseCategory(value: string | undefined) {
  if (value === undefined) return undefined;
  if (!(KNOWLEDGE_CATEGORIES as readonly string[]).includes(value)) {
    throw new Error(
      `invalid --category "${value}". Accepted: ${KNOWLEDGE_CATEGORIES.join(", ")}`,
    );
  }
  return value as KnowledgeCategory;
}

function parseStatus(value: string | undefined) {
  if (value === undefined) return undefined;
  if (!(KNOWLEDGE_STATUSES as readonly string[]).includes(value)) {
    throw new Error(
      `invalid --status "${value}". Accepted: ${KNOWLEDGE_STATUSES.join(", ")}`,
    );
  }
  return value as KnowledgeStatus;
}

async function main(): Promise<void> {
  const args = process.argv.slice(2);
  const sub = args[0] && !args[0].startsWith("-") ? args[0] : "list";

  if (sub === "help" || args.includes("--help") || args.includes("-h")) {
    showHelp();
    return;
  }

  try {
    const takesId = sub === "get" || sub === "update" || sub === "archive";
    const id = takesId ? args[1] : undefined;
    if (takesId && (!id || id.startsWith("-"))) {
      throw new Error(`entry ID is required: pensar knowledge ${sub} <id>`);
    }
    const { values } = parseArgs({
      args: args.slice(args[0] === sub ? (takesId ? 2 : 1) : 0),
      options: {
        title: { type: "string" },
        content: { type: "string" },
        category: { type: "string" },
        status: { type: "string" },
        tag: { type: "string", multiple: true },
      },
      strict: true,
      allowPositionals: false,
    });
    const tags = values.tag?.flatMap((t) => t.split(",")).filter(Boolean);
    const input: KnowledgeInput = {
      title: values.title,
      content: values.content,
      category: parseCategory(values.category),
      status: parseStatus(values.status),
      tags,
    };

    let result: unknown;
    if (sub === "list") {
      result = await listKnowledge({
        category: input.category,
        status: input.status,
        tags,
      });
    } else if (sub === "get") {
      result = await getKnowledge(id!);
    } else if (sub === "add") {
      if (!input.title || !input.content || !input.category) {
        throw new Error("--title, --content and --category are required");
      }
      result = await createKnowledge(input);
    } else if (sub === "update") {
      result = await updateKnowledge(id!, input);
    } else if (sub === "archive") {
      result = await archiveKnowledge(id!);
    } else {
      console.error(`Error: Unknown subcommand "${sub}"`);
      showHelp();
      return markCommandFailed();
    }
    console.log(JSON.stringify(result, null, 2));
  } catch (err) {
    console.error(
      `\nError: ${err instanceof Error ? err.message : String(err)}`,
    );
    return markCommandFailed();
  }
}

await main();
