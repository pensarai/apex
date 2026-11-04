import { createHash } from "node:crypto";
import { lstatSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { lstat, realpath } from "node:fs/promises";
import { join } from "node:path";
import { agentLogsDir } from "./agentScratch";
import type { ToolContext } from "./types";

// Results within these bounds stay inline; the reference notice is bounded
// by the same budget.
export const TOOL_OUTPUT_MAX_BYTES = 50 * 1024;
export const TOOL_OUTPUT_MAX_LINES = 2_000;
const REFERENCE_PREFIX = "tool-output:";
const UUID =
  /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;

function outputDirectory(ctx: ToolContext): string {
  return join(agentLogsDir(ctx), "tool-output");
}

// Retained-output failures surface in model-visible tool results, so the
// host outputDirectory must never appear in them — only the errno survives.
export function unavailableToolOutputMessage(err: unknown): string {
  const code = (err as NodeJS.ErrnoException | undefined)?.code;
  return `Referenced tool output is unavailable${code ? ` (${code})` : ""}`;
}

async function rethrowUnavailable<T>(op: () => Promise<T>): Promise<T> {
  try {
    return await op();
  } catch (err: unknown) {
    throw new Error(unavailableToolOutputMessage(err));
  }
}

export async function resolveToolOutput(
  ctx: ToolContext,
  reference: string,
): Promise<string | undefined> {
  if (!reference.startsWith(REFERENCE_PREFIX)) return undefined;
  const id = reference.slice(REFERENCE_PREFIX.length);
  if (!UUID.test(id)) throw new Error("Invalid tool-output reference");
  const directory = outputDirectory(ctx);
  const dirInfo = await rethrowUnavailable(() => lstat(directory));
  if (!dirInfo.isDirectory() || dirInfo.isSymbolicLink()) {
    throw new Error("Tool-output directory is not an ordinary directory");
  }
  const file = join(
    await rethrowUnavailable(() => realpath(directory)),
    `${id}.txt`,
  );
  const info = await rethrowUnavailable(() => lstat(file));
  if (!info.isFile() || info.isSymbolicLink() || info.nlink !== 1) {
    throw new Error("Tool-output reference is not an ordinary owned file");
  }
  return file;
}

export function persistToolOutput(
  logsPath: string,
  toolCallId: string,
  text: string,
): string {
  try {
    const directory = join(logsPath, "tool-output");
    mkdirSync(directory, { recursive: true });
    const info = lstatSync(directory);
    if (!info.isDirectory() || info.isSymbolicLink()) {
      throw new Error("not an ordinary output directory");
    }
    // SDK prepareStep rebuilds raw history; unchanged output must reuse its spill.
    const digest = createHash("sha256")
      .update(toolCallId)
      .update("\0")
      .update(text)
      .digest();
    digest[6] = (digest[6] & 0x0f) | 0x40;
    digest[8] = (digest[8] & 0x3f) | 0x80;
    const hex = digest.subarray(0, 16).toString("hex");
    const id = `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
    const file = join(directory, `${id}.txt`);
    try {
      writeFileSync(file, text, { flag: "wx", mode: 0o600 });
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "EEXIST") throw error;
      const existing = lstatSync(file);
      if (
        !existing.isFile() ||
        existing.isSymbolicLink() ||
        existing.nlink !== 1 ||
        readFileSync(file, "utf8") !== text
      ) {
        throw new Error("retained output is not an ordinary matching file");
      }
    }
    return `${REFERENCE_PREFIX}${id}`;
  } catch (error) {
    throw new Error(unavailableToolOutputMessage(error));
  }
}

function utf8Prefix(text: string, bytes: number): string {
  const encoded = Buffer.from(text);
  let end = Math.min(Math.max(0, bytes), encoded.length);
  while (end > 0 && end < encoded.length && (encoded[end] & 0xc0) === 0x80)
    end--;
  return encoded.subarray(0, end).toString("utf8");
}

function utf8Suffix(text: string, bytes: number): string {
  const encoded = Buffer.from(text);
  let start = Math.max(0, encoded.length - Math.max(0, bytes));
  while (start < encoded.length && (encoded[start] & 0xc0) === 0x80) start++;
  return encoded.subarray(start).toString("utf8");
}

function lineCount(text: string): number {
  let count = 1;
  for (const char of text) if (char === "\n") count++;
  return count;
}

export function boundedOutputPreview(
  text: string,
  marker: string,
  maxBytes = TOOL_OUTPUT_MAX_BYTES,
  maxLines = TOOL_OUTPUT_MAX_LINES,
): string {
  const allLines = text.split("\n");
  if (allLines.length <= maxLines && Buffer.byteLength(text) <= maxBytes)
    return text;
  const bytes = maxBytes - Buffer.byteLength(marker) - 4;
  const lines = maxLines - lineCount(marker) - 3;
  if (bytes <= 0 || lines <= 0) {
    return utf8Prefix(marker, maxBytes)
      .split("\n")
      .slice(0, maxLines)
      .join("\n");
  }
  const headLines = Math.ceil(lines / 2);
  const tailLines = Math.floor(lines / 2);
  if (allLines.length > lines) {
    const head = allLines.slice(0, headLines).join("\n");
    const tail = allLines.slice(-tailLines).join("\n");
    if (Buffer.byteLength(head) + Buffer.byteLength(tail) <= bytes) {
      return `${head}\n\n${marker}\n\n${tail}`;
    }
    return `${utf8Prefix(head, Math.ceil(bytes / 2))}\n\n${marker}\n\n${utf8Suffix(tail, Math.floor(bytes / 2))}`;
  }
  return `${utf8Prefix(text, Math.ceil(bytes / 2))}\n\n${marker}\n\n${utf8Suffix(text, Math.floor(bytes / 2))}`;
}

type TextToolResult = {
  success: boolean;
  error: string;
  command?: string;
  exitCode?: number;
  truncated?: boolean;
  stdoutTruncated?: boolean;
  stderrTruncated?: boolean;
};

export async function toolOutputForModel<T extends TextToolResult>(
  ctx: ToolContext,
  toolCallId: string,
  output: T,
): Promise<{ type: "json"; value: T } | { type: "text"; value: string }> {
  const serialized = JSON.stringify(output);
  const rendered = Object.entries(output)
    .map(
      ([key, value]) =>
        `${key}:\n${typeof value === "string" ? value : JSON.stringify(value)}`,
    )
    .join("\n\n");
  if (
    Buffer.byteLength(serialized) <= TOOL_OUTPUT_MAX_BYTES &&
    lineCount(rendered) <= TOOL_OUTPUT_MAX_LINES
  ) {
    return { type: "json", value: output };
  }

  const status = `success=${output.success}${output.exitCode === undefined ? "" : `; exitCode=${output.exitCode}`}; capture=${output.truncated || output.stdoutTruncated || output.stderrTruncated ? "INCOMPLETE" : "as returned by executor"}`;
  let notice: string;
  try {
    const reference = persistToolOutput(
      agentLogsDir(ctx),
      toolCallId,
      rendered,
    );
    notice = `${reference}\nCaptured result saved. Use read_file (line or byte windows) or grep with this reference.`;
  } catch {
    notice = "Failed to save captured result. Omitted evidence is unavailable.";
  }
  // Keep the reference first so cascading context-budget previews retain it.
  const header = `${notice}\n${status}\n`;
  return {
    type: "text",
    value: `${header}${boundedOutputPreview(rendered, "... output omitted ...", TOOL_OUTPUT_MAX_BYTES - Buffer.byteLength(header), TOOL_OUTPUT_MAX_LINES - lineCount(header))}`,
  };
}
