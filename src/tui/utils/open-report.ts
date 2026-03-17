import { existsSync } from "fs";
import { join } from "path";
import { REPORT_FILENAME_MD } from "../../core/report";

/**
 * Open the pentest report for a session in the user's default viewer.
 * Awaits the spawned process and checks its exit code so failures
 * (e.g. no default .md handler on Linux) are reported cleanly.
 *
 * Returns an error message string, or "" on success.
 */
export async function openSessionReport(
  sessionRootPath: string,
): Promise<string> {
  const reportPath = join(sessionRootPath, REPORT_FILENAME_MD);

  if (!existsSync(reportPath)) {
    return `Report not found at: ${reportPath}`;
  }

  try {
    const platform = process.platform;
    let cmd: string[];

    if (platform === "darwin") {
      cmd = ["open", reportPath];
    } else if (platform === "win32") {
      cmd = ["cmd", "/c", "start", "", reportPath];
    } else {
      cmd = ["xdg-open", reportPath];
    }

    const proc = Bun.spawn(cmd, {
      stdout: "ignore",
      stderr: "pipe",
    });

    const exitCode = await proc.exited;

    if (exitCode !== 0) {
      return `No default application found to open .md files. Report saved to: ${reportPath}`;
    }

    return "";
  } catch {
    return `Could not open report. Report saved to: ${reportPath}`;
  }
}
