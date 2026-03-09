import { tool } from "ai";
import { z } from "zod";
import { join } from "path";
import {
  writeFileSync,
  readFileSync,
  mkdirSync,
  existsSync,
} from "fs";
import type { ToolContext } from "./types";

const FINDINGS_FILE = "findings.json";

interface ScratchpadFinding {
  category: string;
  data: string;
  timestamp: string;
}

function getFindingsPath(ctx: ToolContext): string {
  return join(ctx.session.scratchpadPath, FINDINGS_FILE);
}

function readFindingsFile(ctx: ToolContext): ScratchpadFinding[] {
  const filePath = getFindingsPath(ctx);
  if (!existsSync(filePath)) return [];
  try {
    return JSON.parse(readFileSync(filePath, "utf-8"));
  } catch {
    return [];
  }
}

function writeFindingsFile(
  ctx: ToolContext,
  findings: ScratchpadFinding[],
): void {
  const dir = ctx.session.scratchpadPath;
  if (!existsSync(dir)) {
    mkdirSync(dir, { recursive: true });
  }
  writeFileSync(getFindingsPath(ctx), JSON.stringify(findings, null, 2));
}

export function writeFinding(ctx: ToolContext) {
  return tool({
    description: `Persist an important discovery to the session scratchpad. Use this to record services, endpoints, credentials, vulnerabilities, flags, or notes that should survive context compaction. These findings persist even if the conversation is summarized.`,
    inputSchema: z.object({
      category: z
        .enum([
          "service",
          "endpoint",
          "credential",
          "vulnerability",
          "flag",
          "note",
        ])
        .describe("Category of finding"),
      data: z
        .string()
        .describe(
          "The finding data to persist (e.g. 'Port 8080 open - Apache httpd 2.4.41', 'admin:password123', 'FLAG{example}')",
        ),
    }),
    execute: async ({ category, data }): Promise<string> => {
      const findings = readFindingsFile(ctx);

      // Deduplicate: skip if exact same category+data already exists
      const exists = findings.some(
        (f) => f.category === category && f.data === data,
      );
      if (exists) {
        return `Finding already recorded: [${category}] ${data}`;
      }

      findings.push({
        category,
        data,
        timestamp: new Date().toISOString(),
      });

      writeFindingsFile(ctx, findings);
      return `Finding recorded: [${category}] ${data} (${findings.length} total findings in scratchpad)`;
    },
  });
}

export function readFindings(ctx: ToolContext) {
  return tool({
    description: `Read all findings from the session scratchpad. Returns all persisted discoveries (services, endpoints, credentials, vulnerabilities, flags, notes) that have been recorded during this session.`,
    inputSchema: z.object({
      category: z
        .enum([
          "service",
          "endpoint",
          "credential",
          "vulnerability",
          "flag",
          "note",
          "all",
        ])
        .default("all")
        .describe("Filter by category, or 'all' for everything"),
    }),
    execute: async ({ category }): Promise<string> => {
      const findings = readFindingsFile(ctx);

      if (findings.length === 0) {
        return "No findings in scratchpad yet.";
      }

      const filtered =
        category === "all"
          ? findings
          : findings.filter((f) => f.category === category);

      if (filtered.length === 0) {
        return `No findings with category '${category}'. Total findings: ${findings.length}.`;
      }

      const lines = filtered.map((f) => `[${f.category}] ${f.data}`);
      return `Scratchpad findings (${filtered.length}/${findings.length}):\n${lines.join("\n")}`;
    },
  });
}

/**
 * Load scratchpad findings for injection into summarization prompts.
 * Returns formatted string or empty string if no findings.
 */
export function loadScratchpadFindings(scratchpadPath: string): string {
  const filePath = join(scratchpadPath, FINDINGS_FILE);
  if (!existsSync(filePath)) return "";

  try {
    const findings: ScratchpadFinding[] = JSON.parse(
      readFileSync(filePath, "utf-8"),
    );
    if (findings.length === 0) return "";

    const lines = findings.map((f) => `- [${f.category}] ${f.data}`);
    return `## Scratchpad Findings (Persisted)\n${lines.join("\n")}`;
  } catch {
    return "";
  }
}
