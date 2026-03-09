import { spawnSync } from "child_process";

/**
 * Copy text to the system clipboard.
 *
 * Uses platform-specific tools:
 *  - macOS: pbcopy
 *  - Linux (Wayland): wl-copy
 *  - Linux (X11): xclip / xsel
 *  - Windows: clip
 *
 * Returns true on success, false on failure.
 */
export function copyToClipboard(text: string): boolean {
  const platform = process.platform;

  try {
    if (platform === "darwin") {
      return spawn("pbcopy", text);
    }

    if (platform === "win32") {
      return spawn("clip", text);
    }

    // Linux — try Wayland first, then X11 tools
    if (process.env.WAYLAND_DISPLAY) {
      if (spawn("wl-copy", text)) return true;
    }

    if (spawn("xclip", text, ["-selection", "clipboard"])) return true;
    if (spawn("xsel", text, ["--clipboard", "--input"])) return true;
    if (spawn("wl-copy", text)) return true;

    return false;
  } catch {
    return false;
  }
}

function spawn(cmd: string, input: string, args: string[] = []): boolean {
  try {
    const result = spawnSync(cmd, args, {
      input,
      timeout: 3000,
      stdio: ["pipe", "ignore", "ignore"],
    });
    return result.status === 0;
  } catch {
    return false;
  }
}
