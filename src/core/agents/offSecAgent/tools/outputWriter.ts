import { writeFile, mkdir } from "fs/promises";
import { join } from "path";
import type { SessionInfo } from "../../../session";

export interface OutputFileResult {
  outputFilePath: string;
  outputFileRelativePath: string;
}

export async function writeToolOutput(
  session: SessionInfo,
  toolName: string,
  content: string,
): Promise<OutputFileResult> {
  const timestamp = new Date().toISOString().replace(/[:.]/g, "-");
  const fileName = `${toolName}-${timestamp}.txt`;
  const outputFilePath = join(session.outputsPath, fileName);
  const outputFileRelativePath = `outputs/${fileName}`;

  await mkdir(session.outputsPath, { recursive: true });
  await writeFile(outputFilePath, content, "utf-8");

  return {
    outputFilePath,
    outputFileRelativePath,
  };
}

export const OUTPUT_THRESHOLDS = {
  EXECUTE_COMMAND: 50000,
  HTTP_REQUEST: 5000,
} as const;

export function createOutputReference(
  outputFilePath: string,
  truncatedPreview: string,
  totalLength: number,
): string {
  return `${truncatedPreview}

---
Output truncated (${totalLength} bytes total). Full output saved to: ${outputFilePath}
Use the read_file tool to analyze the complete output.`;
}
