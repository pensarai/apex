import { tool } from "ai";
import { z } from "zod";
import { execSync } from "child_process";
import type { ToolContext } from "./types";

const DEFAULT_MAX_FILE_SIZE = 100 * 1024 * 1024; // 100 MB per member
const DEFAULT_MAX_FILES = 10_000;
const DEFAULT_MAX_TOTAL_SIZE = 1024 * 1024 * 1024; // 1 GB decompressed total

export const extractArchiveInputSchema = z.object({
  archivePath: z
    .string()
    .describe(
      "Absolute path to the archive file (e.g. /work/artifact.zip). Supports .zip, .tar, .tar.gz, .tgz.",
    ),
  outputDir: z
    .string()
    .describe(
      "Absolute path to an empty/nonexistent directory to extract into (e.g. /work/extracted). Will be created if it doesn't exist.",
    ),
  maxFileSize: z
    .number()
    .int()
    .positive()
    .optional()
    .describe(
      `Maximum size of any single extracted file in bytes (default ${DEFAULT_MAX_FILE_SIZE} = 100 MB). Protects against zip bombs.`,
    ),
  maxFiles: z
    .number()
    .int()
    .positive()
    .optional()
    .describe(
      `Maximum number of files to extract (default ${DEFAULT_MAX_FILES}). Protects against entry-count bombs.`,
    ),
  maxTotalSize: z
    .number()
    .int()
    .positive()
    .optional()
    .describe(
      `Maximum total decompressed size in bytes (default ${DEFAULT_MAX_TOTAL_SIZE} = 1 GB). Protects against total-size bombs.`,
    ),
  toolCallDescription: z
    .string()
    .describe(
      "A concise, human-readable description of what this tool call is doing (e.g., 'Extracting uploaded artifact for signature scan')",
    ),
});

export type ExtractArchiveInput = z.infer<typeof extractArchiveInputSchema>;

export type ExtractArchiveResult = {
  success: boolean;
  filesExtracted: string[];
  totalSize: number;
  format: "zip" | "tar" | "tar.gz" | "unknown";
  errors: string[];
  error?: string;
};

type Runner = (cmd: string, timeoutSec?: number) => Promise<{
  stdout: string;
  stderr: string;
  exitCode: number;
}>;

function runnerFor(ctx: ToolContext): Runner {
  if (ctx.sandbox) {
    const sandbox = ctx.sandbox;
    return async (cmd, timeoutSec = 120) => {
      const r = await sandbox.execute(cmd, { timeout: timeoutSec });
      return { stdout: r.stdout, stderr: r.stderr, exitCode: r.exitCode };
    };
  }
  return async (cmd) => {
    try {
      const stdout = execSync(cmd, {
        encoding: "utf8",
        maxBuffer: 50 * 1024 * 1024,
        stdio: ["ignore", "pipe", "pipe"],
      });
      return { stdout, stderr: "", exitCode: 0 };
    } catch (err) {
      const e = err as { stdout?: string; stderr?: string; status?: number };
      return {
        stdout: e.stdout ?? "",
        stderr: e.stderr ?? "",
        exitCode: e.status ?? 1,
      };
    }
  };
}

function detectFormat(path: string): ExtractArchiveResult["format"] {
  const lower = path.toLowerCase();
  if (lower.endsWith(".zip")) return "zip";
  if (lower.endsWith(".tar.gz") || lower.endsWith(".tgz")) return "tar.gz";
  if (lower.endsWith(".tar")) return "tar";
  return "unknown";
}

/**
 * Parse `unzip -l` output. Columns are: Length, Date, Time, Name. We only
 * care about Length and Name for pre-extraction size / entry validation.
 */
function parseUnzipListing(raw: string): Array<{ name: string; size: number }> {
  const lines = raw.split("\n");
  const entries: Array<{ name: string; size: number }> = [];
  for (const line of lines) {
    const m = line.match(/^\s*(\d+)\s+\S+\s+\S+\s+(.+)$/);
    if (!m) continue;
    const size = parseInt(m[1], 10);
    const name = m[2].trim();
    if (!name || name === "Name") continue;
    if (name.endsWith("/")) continue; // skip dir entries
    entries.push({ name, size });
  }
  return entries;
}

/**
 * Parse `tar -tzvf` output. Columns roughly: mode, owner/group, size, date,
 * time, name. We only care about size and name.
 */
function parseTarListing(raw: string): Array<{ name: string; size: number }> {
  const lines = raw.split("\n");
  const entries: Array<{ name: string; size: number }> = [];
  for (const line of lines) {
    if (!line.trim()) continue;
    // Mode must start with - or d or l etc. for a valid entry line
    if (!/^[-dlbcpshDlwrwxXstST][-dlbcpshDrwxXstST]/.test(line)) continue;
    const cols = line.trim().split(/\s+/);
    if (cols.length < 6) continue;
    const size = parseInt(cols[2], 10);
    if (Number.isNaN(size)) continue;
    const name = cols.slice(5).join(" ");
    if (!name || name.endsWith("/")) continue;
    // Reject symlinks (first char 'l')
    if (line[0] === "l") continue;
    entries.push({ name, size });
  }
  return entries;
}

function sanitizeEntries(
  entries: Array<{ name: string; size: number }>,
  caps: {
    maxFileSize: number;
    maxFiles: number;
    maxTotalSize: number;
  },
): { allowed: Array<{ name: string; size: number }>; errors: string[] } {
  const errors: string[] = [];
  const allowed: Array<{ name: string; size: number }> = [];
  let total = 0;
  for (const entry of entries) {
    if (entry.name.includes("..") || entry.name.startsWith("/")) {
      errors.push(
        `skip (path-traversal): ${entry.name}`,
      );
      continue;
    }
    if (entry.size > caps.maxFileSize) {
      errors.push(
        `skip (>${caps.maxFileSize}B): ${entry.name} (${entry.size}B)`,
      );
      continue;
    }
    if (total + entry.size > caps.maxTotalSize) {
      errors.push(
        `skip (cumulative >${caps.maxTotalSize}B): ${entry.name}`,
      );
      continue;
    }
    if (allowed.length >= caps.maxFiles) {
      errors.push(`skip (>${caps.maxFiles} entries): ${entry.name}`);
      continue;
    }
    allowed.push(entry);
    total += entry.size;
  }
  return { allowed, errors };
}

/**
 * Extract a ZIP / TAR / TAR.GZ archive with zip-bomb and path-traversal
 * protections. Emits a `file_write` detection event for every member
 * extracted, so the assertion layer sees ground-truth evidence of what
 * the archive actually contained.
 */
export function extractArchive(ctx: ToolContext) {
  return tool({
    description: `Extract a ZIP / TAR / TAR.GZ archive into a fresh directory with safety caps.

Safety guards (all configurable, reasonable defaults):
  • maxFileSize per member (default 100 MB)
  • maxFiles total entries (default 10,000)
  • maxTotalSize cumulative decompressed (default 1 GB)
  • symlink entries are rejected outright
  • path-traversal entries (../ or absolute) are rejected outright

Emits one \`file_write\` detection event per actually-extracted member, so
the run's assertion layer has evidence of what the archive really contained.
You do NOT need to call \`emit_detection_event\` for these.

Runs through the sandbox when available; otherwise uses local unzip/tar
binaries. Uses \`unzip\` for .zip and \`tar\` for .tar / .tar.gz / .tgz.`,
    inputSchema: extractArchiveInputSchema,
    execute: async (input): Promise<ExtractArchiveResult> => {
      const format = detectFormat(input.archivePath);
      if (format === "unknown") {
        return {
          success: false,
          filesExtracted: [],
          totalSize: 0,
          format: "unknown",
          errors: [],
          error: `Unsupported archive format for ${input.archivePath}. Supported: .zip, .tar, .tar.gz, .tgz.`,
        };
      }

      const caps = {
        maxFileSize: input.maxFileSize ?? DEFAULT_MAX_FILE_SIZE,
        maxFiles: input.maxFiles ?? DEFAULT_MAX_FILES,
        maxTotalSize: input.maxTotalSize ?? DEFAULT_MAX_TOTAL_SIZE,
      };
      const run = runnerFor(ctx);
      const errors: string[] = [];
      const archive = input.archivePath.replace(/'/g, "'\\''");
      const outDir = input.outputDir.replace(/'/g, "'\\''");

      try {
        // 1. List entries without extracting
        let listingCmd: string;
        if (format === "zip") {
          listingCmd = `unzip -l '${archive}'`;
        } else {
          listingCmd = `tar -tzvf '${archive}'`;
        }
        const listing = await run(listingCmd, 60);
        if (listing.exitCode !== 0) {
          return {
            success: false,
            filesExtracted: [],
            totalSize: 0,
            format,
            errors: [],
            error: `Listing failed (exit ${listing.exitCode}): ${listing.stderr || listing.stdout}`,
          };
        }

        const rawEntries =
          format === "zip"
            ? parseUnzipListing(listing.stdout)
            : parseTarListing(listing.stdout);

        const { allowed, errors: skips } = sanitizeEntries(rawEntries, caps);
        errors.push(...skips);

        if (allowed.length === 0) {
          return {
            success: true,
            filesExtracted: [],
            totalSize: 0,
            format,
            errors,
            error:
              errors.length > 0
                ? "No entries passed safety filters."
                : "Archive is empty.",
          };
        }

        // 2. Create output directory and extract only the allowed entries.
        await run(`mkdir -p '${outDir}'`, 10);

        let extractCmd: string;
        if (format === "zip") {
          // Use explicit list of files to extract (space-separated, quoted).
          const fileArgs = allowed
            .map((e) => `'${e.name.replace(/'/g, "'\\''")}'`)
            .join(" ");
          extractCmd = `unzip -o '${archive}' ${fileArgs} -d '${outDir}'`;
        } else {
          const fileArgs = allowed
            .map((e) => `'${e.name.replace(/'/g, "'\\''")}'`)
            .join(" ");
          extractCmd = `tar -xzvf '${archive}' -C '${outDir}' ${fileArgs}`;
        }
        const extract = await run(extractCmd, 300);
        if (extract.exitCode !== 0) {
          return {
            success: false,
            filesExtracted: [],
            totalSize: 0,
            format,
            errors,
            error: `Extraction failed (exit ${extract.exitCode}): ${extract.stderr || extract.stdout}`,
          };
        }

        // 3. Emit file_write events for every successfully extracted member.
        let totalSize = 0;
        const filesExtracted: string[] = [];
        for (const entry of allowed) {
          const absPath = `${input.outputDir}/${entry.name}`;
          filesExtracted.push(absPath);
          totalSize += entry.size;
          ctx.eventBus?.emit("detection_event", {
            kind: "file_write",
            severity: "low",
            source: "sandbox",
            summary: `Extracted archive member: ${entry.name} (${entry.size}B)`,
            data: {
              archivePath: input.archivePath,
              memberName: entry.name,
              memberSize: entry.size,
              extractedPath: absPath,
              format,
            },
          });
        }

        return {
          success: true,
          filesExtracted,
          totalSize,
          format,
          errors,
        };
      } catch (error) {
        return {
          success: false,
          filesExtracted: [],
          totalSize: 0,
          format,
          errors,
          error: error instanceof Error ? error.message : String(error),
        };
      }
    },
  });
}
