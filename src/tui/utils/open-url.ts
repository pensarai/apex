const OPEN_FAILED_MSG = "Couldn't open browser — visit the URL shown instead";

/**
 * Open a URL in the user's default browser.
 * Child stdio is suppressed so launcher errors (e.g. xdg-open's
 * "Can't open display") never leak into the TUI's terminal.
 * Returns "" on success, or an error message string on failure.
 */
export async function openUrlInBrowser(url: string): Promise<string> {
  try {
    const platform = process.platform;
    let proc: ReturnType<typeof Bun.spawn>;

    if (platform === "darwin") {
      proc = Bun.spawn(["open", url], {
        stdout: "ignore",
        stderr: "ignore",
      });
    } else if (platform === "win32") {
      proc = Bun.spawn(["cmd", "/c", "start", "", url], {
        stdout: "ignore",
        stderr: "ignore",
      });
    } else {
      proc = Bun.spawn(["xdg-open", url], {
        stdout: "ignore",
        stderr: "ignore",
      });
    }

    const exitCode = await proc.exited;
    if (exitCode !== 0) {
      return OPEN_FAILED_MSG;
    }
    return "";
  } catch {
    return OPEN_FAILED_MSG;
  }
}
