const NO_APP_MSG = "No app found to open file — set a default application";

/**
 * Open a file in the user's default OS application.
 * Returns "" on success, or an error message string on failure.
 */
export async function openFileInDefaultApp(filePath: string): Promise<string> {
  try {
    const platform = process.platform;
    let proc: ReturnType<typeof Bun.spawn>;

    if (platform === "darwin") {
      proc = Bun.spawn(["open", filePath], {
        stderr: "pipe",
        stdout: "pipe",
      });
    } else if (platform === "win32") {
      proc = Bun.spawn(["cmd", "/c", "start", "", filePath], {
        stderr: "pipe",
        stdout: "pipe",
      });
    } else {
      proc = Bun.spawn(["xdg-open", filePath], {
        stderr: "pipe",
        stdout: "pipe",
      });
    }

    const exitCode = await proc.exited;
    if (exitCode !== 0) {
      return NO_APP_MSG;
    }
    return "";
  } catch {
    return NO_APP_MSG;
  }
}
