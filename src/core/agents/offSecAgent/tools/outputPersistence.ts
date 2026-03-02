import { existsSync, mkdirSync, writeFileSync } from "fs";
import { join } from "path";
import type { SessionInfo } from "../../../session";

/**
 * Threshold in characters above which command output is persisted to file
 * and a file path is returned instead of inline output.
 */
export const OUTPUT_SIZE_THRESHOLD = 10000;

/**
 * Result of persisting output to a file
 */
export interface PersistedOutput {
  /** Absolute path to the output file */
  filePath: string;
  /** Relative path from session root for display */
  relativePath: string;
}

/**
 * Generate a unique filename for command output
 */
function generateOutputFilename(command: string, suffix?: string): string {
  const timestamp = new Date().toISOString().replace(/[:.]/g, "-");
  const sanitizedCmd = command
    .split(/\s+/)[0]
    .replace(/[^a-zA-Z0-9_-]/g, "_")
    .substring(0, 30);
  const suffixPart = suffix ? `_${suffix}` : "";
  return `${timestamp}_${sanitizedCmd}${suffixPart}.txt`;
}

/**
 * Persist command output to the terminals directory.
 * Creates the directory if it doesn't exist.
 *
 * @param session - The session containing the terminalsPath
 * @param command - The command that was executed (used for filename)
 * @param stdout - Standard output from the command
 * @param stderr - Standard error from the command
 * @param exitCode - Exit code of the command (optional)
 * @returns The persisted output info with file paths
 */
export function persistCommandOutput(
  session: SessionInfo,
  command: string,
  stdout: string,
  stderr: string,
  exitCode?: number,
): PersistedOutput {
  const terminalsPath = session.terminalsPath;

  if (!existsSync(terminalsPath)) {
    mkdirSync(terminalsPath, { recursive: true });
  }

  const filename = generateOutputFilename(command);
  const filePath = join(terminalsPath, filename);

  const content = formatOutputContent(command, stdout, stderr, exitCode);
  writeFileSync(filePath, content);

  return {
    filePath,
    relativePath: `terminals/${filename}`,
  };
}

/**
 * Persist POC execution output to a file alongside the POC.
 * The output file is named similarly to the POC with a .output.txt suffix.
 *
 * @param session - The session containing paths
 * @param pocFilename - The POC filename (e.g., poc_my_script.sh)
 * @param stdout - Standard output from POC execution
 * @param stderr - Standard error from POC execution
 * @param exitCode - Exit code of the POC
 * @param description - Description of what the POC does
 * @returns The persisted output info with file paths
 */
export function persistPocOutput(
  session: SessionInfo,
  pocFilename: string,
  stdout: string,
  stderr: string,
  exitCode: number,
  description?: string,
): PersistedOutput {
  const terminalsPath = session.terminalsPath;

  if (!existsSync(terminalsPath)) {
    mkdirSync(terminalsPath, { recursive: true });
  }

  const baseName = pocFilename.replace(/\.[^.]+$/, "");
  const timestamp = new Date().toISOString().replace(/[:.]/g, "-");
  const filename = `${baseName}_${timestamp}.output.txt`;
  const filePath = join(terminalsPath, filename);

  const content = formatPocOutputContent(
    pocFilename,
    stdout,
    stderr,
    exitCode,
    description,
  );
  writeFileSync(filePath, content);

  return {
    filePath,
    relativePath: `terminals/${filename}`,
  };
}

/**
 * Format command output content for persistence
 */
function formatOutputContent(
  command: string,
  stdout: string,
  stderr: string,
  exitCode?: number,
): string {
  const lines: string[] = [
    "=" .repeat(80),
    "COMMAND EXECUTION OUTPUT",
    "=" .repeat(80),
    "",
    `Timestamp: ${new Date().toISOString()}`,
    `Command: ${command}`,
  ];

  if (exitCode !== undefined) {
    lines.push(`Exit Code: ${exitCode}`);
  }

  lines.push("");
  lines.push("-".repeat(80));
  lines.push("STDOUT:");
  lines.push("-".repeat(80));
  lines.push(stdout || "(no output)");
  lines.push("");

  if (stderr) {
    lines.push("-".repeat(80));
    lines.push("STDERR:");
    lines.push("-".repeat(80));
    lines.push(stderr);
    lines.push("");
  }

  lines.push("=".repeat(80));

  return lines.join("\n");
}

/**
 * Format POC output content for persistence
 */
function formatPocOutputContent(
  pocFilename: string,
  stdout: string,
  stderr: string,
  exitCode: number,
  description?: string,
): string {
  const lines: string[] = [
    "=".repeat(80),
    "POC EXECUTION OUTPUT",
    "=".repeat(80),
    "",
    `Timestamp: ${new Date().toISOString()}`,
    `POC File: ${pocFilename}`,
    `Exit Code: ${exitCode}`,
    `Success: ${exitCode === 0 ? "Yes" : "No"}`,
  ];

  if (description) {
    lines.push(`Description: ${description}`);
  }

  lines.push("");
  lines.push("-".repeat(80));
  lines.push("STDOUT:");
  lines.push("-".repeat(80));
  lines.push(stdout || "(no output)");
  lines.push("");

  if (stderr) {
    lines.push("-".repeat(80));
    lines.push("STDERR:");
    lines.push("-".repeat(80));
    lines.push(stderr);
    lines.push("");
  }

  lines.push("=".repeat(80));

  return lines.join("\n");
}

/**
 * Check if output should be persisted based on size threshold.
 * Returns true if the combined output exceeds the threshold.
 */
export function shouldPersistOutput(stdout: string, stderr: string): boolean {
  const totalLength = (stdout?.length || 0) + (stderr?.length || 0);
  return totalLength > OUTPUT_SIZE_THRESHOLD;
}
