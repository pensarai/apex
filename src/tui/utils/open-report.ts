import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { REPORT_FILENAME_MD } from "../../core/report";
import { openFileInDefaultApp } from "./open-file";

/**
 * Open the pentest report for a session in the user's default viewer.
 * Returns a promise that resolves to an error message string, or "" on success.
 */
export async function openSessionReport(
  sessionRootPath: string,
): Promise<string> {
  const reportPath = join(sessionRootPath, REPORT_FILENAME_MD);

  if (!existsSync(reportPath)) {
    return "Report not found";
  }

  return openFileInDefaultApp(reportPath);
}

/**
 * Read the raw markdown content of a session's pentest report.
 * Returns the content string or null if the report doesn't exist.
 */
export function readSessionReport(sessionRootPath: string): string | null {
  const reportPath = join(sessionRootPath, REPORT_FILENAME_MD);
  if (!existsSync(reportPath)) return null;
  try {
    return readFileSync(reportPath, "utf-8");
  } catch {
    return null;
  }
}
