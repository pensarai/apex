import { existsSync } from "fs";
import { join } from "path";
import { REPORT_FILENAME_MD } from "../../core/report";

/**
 * Open the pentest report for a session in the user's default viewer.
 * Returns an error message string, or "" on success.
 */
export function openSessionReport(sessionRootPath: string): string {
  const reportPath = join(sessionRootPath, REPORT_FILENAME_MD);

  if (!existsSync(reportPath)) {
    return "Report not found";
  }

  try {
    const platform = process.platform;
    if (platform === "darwin") {
      Bun.spawn(["open", reportPath]);
    } else if (platform === "win32") {
      Bun.spawn(["cmd", "/c", "start", reportPath]);
    } else {
      Bun.spawn(["xdg-open", reportPath]);
    }
    return "";
  } catch {
    return "Error opening report";
  }
}
