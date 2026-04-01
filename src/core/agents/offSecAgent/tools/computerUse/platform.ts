/**
 * Platform detection and desktop automation backend.
 *
 * Linux  → xdotool + scrot/import (ImageMagick)
 * macOS  → cliclick + screencapture
 *
 * Each backend implements the same {@link DesktopBackend} interface so
 * individual tools stay platform-agnostic.
 */

import {
  execSync,
  type ExecSyncOptionsWithStringEncoding,
} from "child_process";

const EXEC_OPTS: ExecSyncOptionsWithStringEncoding = {
  encoding: "utf-8",
  timeout: 15_000,
  stdio: ["pipe", "pipe", "pipe"],
};

export type Platform = "linux" | "darwin" | "unsupported";

export function detectPlatform(): Platform {
  const p = process.platform;
  if (p === "linux") return "linux";
  if (p === "darwin") return "darwin";
  return "unsupported";
}

export interface ScreenSize {
  width: number;
  height: number;
}

export interface MousePosition {
  x: number;
  y: number;
}

// ---------------------------------------------------------------------------
// Desktop backend interface
// ---------------------------------------------------------------------------

export interface DesktopBackend {
  /** Take a screenshot and return the file path to the PNG. */
  screenshot(outputPath: string): string;

  /** Move the mouse to absolute coordinates. */
  mouseMove(x: number, y: number): void;

  /** Click at the current (or specified) position. */
  mouseClick(
    button?: "left" | "right" | "middle",
    x?: number,
    y?: number,
  ): void;

  /** Double-click at the current (or specified) position. */
  mouseDoubleClick(x?: number, y?: number): void;

  /** Type text via keyboard (handles special characters). */
  typeText(text: string): void;

  /** Press a key or key combination (e.g. "Return", "ctrl+c", "alt+Tab"). */
  keyPress(keys: string): void;

  /** Get current mouse position. */
  getMousePosition(): MousePosition;

  /** Get screen dimensions. */
  getScreenSize(): ScreenSize;

  /** Drag from one point to another. */
  mouseDrag(startX: number, startY: number, endX: number, endY: number): void;

  /** Scroll the mouse wheel. Positive = down, negative = up. */
  scroll(amount: number, x?: number, y?: number): void;

  /** Get the title of the currently active window. */
  getActiveWindowTitle(): string;
}

// ---------------------------------------------------------------------------
// Linux backend (xdotool + scrot)
// ---------------------------------------------------------------------------

function exec(cmd: string): string {
  return execSync(cmd, EXEC_OPTS).trim();
}

export class LinuxBackend implements DesktopBackend {
  screenshot(outputPath: string): string {
    exec(
      `scrot -o "${outputPath}" 2>/dev/null || import -window root "${outputPath}"`,
    );
    return outputPath;
  }

  mouseMove(x: number, y: number): void {
    exec(`xdotool mousemove ${x} ${y}`);
  }

  mouseClick(
    button: "left" | "right" | "middle" = "left",
    x?: number,
    y?: number,
  ): void {
    const btnMap = { left: 1, middle: 2, right: 3 } as const;
    if (x != null && y != null) {
      exec(`xdotool mousemove ${x} ${y} click ${btnMap[button]}`);
    } else {
      exec(`xdotool click ${btnMap[button]}`);
    }
  }

  mouseDoubleClick(x?: number, y?: number): void {
    if (x != null && y != null) {
      exec(`xdotool mousemove ${x} ${y} click --repeat 2 --delay 80 1`);
    } else {
      exec(`xdotool click --repeat 2 --delay 80 1`);
    }
  }

  typeText(text: string): void {
    exec(`xdotool type --clearmodifiers -- ${JSON.stringify(text)}`);
  }

  keyPress(keys: string): void {
    exec(`xdotool key --clearmodifiers ${keys}`);
  }

  getMousePosition(): MousePosition {
    const raw = exec("xdotool getmouselocation --shell");
    const xMatch = raw.match(/X=(\d+)/);
    const yMatch = raw.match(/Y=(\d+)/);
    return {
      x: xMatch ? parseInt(xMatch[1]!, 10) : 0,
      y: yMatch ? parseInt(yMatch[1]!, 10) : 0,
    };
  }

  getScreenSize(): ScreenSize {
    const raw = exec("xdotool getdisplaygeometry");
    const [w, h] = raw.split(" ").map(Number);
    return { width: w ?? 0, height: h ?? 0 };
  }

  mouseDrag(startX: number, startY: number, endX: number, endY: number): void {
    exec(
      `xdotool mousemove ${startX} ${startY} mousedown 1 mousemove ${endX} ${endY} mouseup 1`,
    );
  }

  scroll(amount: number, x?: number, y?: number): void {
    if (x != null && y != null) {
      exec(`xdotool mousemove ${x} ${y}`);
    }
    const button = amount > 0 ? 5 : 4;
    const clicks = Math.abs(amount);
    exec(`xdotool click --repeat ${clicks} --delay 50 ${button}`);
  }

  getActiveWindowTitle(): string {
    try {
      return exec("xdotool getactivewindow getwindowname");
    } catch {
      return "(unknown)";
    }
  }
}

// ---------------------------------------------------------------------------
// macOS backend (cliclick + screencapture)
// ---------------------------------------------------------------------------

export class DarwinBackend implements DesktopBackend {
  screenshot(outputPath: string): string {
    exec(`screencapture -x "${outputPath}"`);
    return outputPath;
  }

  mouseMove(x: number, y: number): void {
    exec(`cliclick m:${x},${y}`);
  }

  mouseClick(
    button: "left" | "right" | "middle" = "left",
    x?: number,
    y?: number,
  ): void {
    const prefix = button === "right" ? "rc" : "c";
    if (x != null && y != null) {
      exec(`cliclick ${prefix}:${x},${y}`);
    } else {
      const pos = this.getMousePosition();
      exec(`cliclick ${prefix}:${pos.x},${pos.y}`);
    }
  }

  mouseDoubleClick(x?: number, y?: number): void {
    if (x != null && y != null) {
      exec(`cliclick dc:${x},${y}`);
    } else {
      const pos = this.getMousePosition();
      exec(`cliclick dc:${pos.x},${pos.y}`);
    }
  }

  typeText(text: string): void {
    exec(`cliclick t:${JSON.stringify(text)}`);
  }

  keyPress(keys: string): void {
    exec(`cliclick kp:${keys}`);
  }

  getMousePosition(): MousePosition {
    const raw = exec("cliclick p");
    const match = raw.match(/(\d+),(\d+)/);
    return {
      x: match ? parseInt(match[1]!, 10) : 0,
      y: match ? parseInt(match[2]!, 10) : 0,
    };
  }

  getScreenSize(): ScreenSize {
    const raw = exec(
      `system_profiler SPDisplaysDataType | grep Resolution | head -1`,
    );
    const match = raw.match(/(\d+)\s*x\s*(\d+)/);
    return {
      width: match ? parseInt(match[1]!, 10) : 0,
      height: match ? parseInt(match[2]!, 10) : 0,
    };
  }

  mouseDrag(startX: number, startY: number, endX: number, endY: number): void {
    exec(`cliclick dd:${startX},${startY} du:${endX},${endY}`);
  }

  scroll(amount: number, x?: number, y?: number): void {
    if (x != null && y != null) {
      exec(`cliclick m:${x},${y}`);
    }
    const direction = amount > 0 ? "down" : "up";
    const clicks = Math.abs(amount);
    for (let i = 0; i < clicks; i++) {
      exec(`cliclick "kp:${direction === "down" ? "arrow-down" : "arrow-up"}"`);
    }
  }

  getActiveWindowTitle(): string {
    try {
      return exec(
        `osascript -e 'tell application "System Events" to get name of first application process whose frontmost is true'`,
      );
    } catch {
      return "(unknown)";
    }
  }
}

// ---------------------------------------------------------------------------
// Factory
// ---------------------------------------------------------------------------

let _cached: DesktopBackend | null = null;

export function getDesktopBackend(): DesktopBackend {
  if (_cached) return _cached;

  const platform = detectPlatform();
  switch (platform) {
    case "linux":
      _cached = new LinuxBackend();
      break;
    case "darwin":
      _cached = new DarwinBackend();
      break;
    default:
      throw new Error(
        `Computer use tools are not supported on platform: ${process.platform}. ` +
          `Supported: linux (xdotool), macOS (cliclick).`,
      );
  }
  return _cached;
}
