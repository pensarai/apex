import { existsSync, readFileSync } from "fs";
import { join } from "path";
import { REPORT_FILENAME_MD } from "../../core/report";

const NO_EDITOR_MSG =
  "No app found for .md files — set a default markdown editor";

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

  try {
    const platform = process.platform;
    let proc: ReturnType<typeof Bun.spawn>;

    if (platform === "darwin") {
      proc = Bun.spawn(["open", reportPath], {
        stderr: "pipe",
        stdout: "pipe",
      });
    } else if (platform === "win32") {
      proc = Bun.spawn(["cmd", "/c", "start", "", reportPath], {
        stderr: "pipe",
        stdout: "pipe",
      });
    } else {
      proc = Bun.spawn(["xdg-open", reportPath], {
        stderr: "pipe",
        stdout: "pipe",
      });
    }

    const exitCode = await proc.exited;
    if (exitCode !== 0) {
      return NO_EDITOR_MSG;
    }
    return "";
  } catch {
    return NO_EDITOR_MSG;
  }
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
