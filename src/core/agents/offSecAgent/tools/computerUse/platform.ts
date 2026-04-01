/**
 * Platform detection and desktop automation backend.
 *
 * Linux   → xdotool + scrot/import (ImageMagick)
 * macOS   → cliclick + screencapture
 * Windows → PowerShell + .NET System.Windows.Forms / user32.dll
 *
 * Each backend implements the same {@link DesktopBackend} interface so
 * individual tools stay platform-agnostic.
 */

import {
  execFileSync,
  execSync,
  type ExecSyncOptionsWithStringEncoding,
} from "child_process";

const EXEC_OPTS: ExecSyncOptionsWithStringEncoding = {
  encoding: "utf-8",
  timeout: 15_000,
  stdio: ["pipe", "pipe", "pipe"],
};

export type Platform = "linux" | "darwin" | "win32" | "unsupported";

export function detectPlatform(): Platform {
  const p = process.platform;
  if (p === "linux") return "linux";
  if (p === "darwin") return "darwin";
  if (p === "win32") return "win32";
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
    execFileSync("xdotool", ["key", "--clearmodifiers", keys], EXEC_OPTS);
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
    execFileSync("cliclick", [`kp:${keys}`], EXEC_OPTS);
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
// Windows backend (PowerShell + .NET System.Windows.Forms / user32.dll)
// ---------------------------------------------------------------------------

/**
 * Run a PowerShell snippet and return trimmed stdout.
 *
 * Uses `-NoProfile -NonInteractive -Command` so startup is fast and
 * there is no profile pollution. The snippet can use any .NET class
 * available in the default PowerShell/.NET runtime.
 */
function ps(script: string): string {
  return execSync(
    `powershell -NoProfile -NonInteractive -Command ${JSON.stringify(script)}`,
    EXEC_OPTS,
  ).trim();
}

/**
 * Shared C# helper that is injected once per PowerShell call when we need
 * mouse or keyboard simulation via `user32.dll` P/Invoke.
 */
const WIN32_INPUT_TYPE = `
Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
public class Win32Input {
    [DllImport("user32.dll")] public static extern bool SetCursorPos(int X, int Y);
    [DllImport("user32.dll")] public static extern bool GetCursorPos(out POINT lpPoint);
    [DllImport("user32.dll")] public static extern void mouse_event(uint dwFlags, int dx, int dy, int dwData, int dwExtraInfo);
    [DllImport("user32.dll")] public static extern IntPtr GetForegroundWindow();
    [DllImport("user32.dll", CharSet=CharSet.Auto)] public static extern int GetWindowText(IntPtr hWnd, System.Text.StringBuilder lpString, int nMaxCount);
    [StructLayout(LayoutKind.Sequential)] public struct POINT { public int X; public int Y; }

    public const uint MOUSEEVENTF_LEFTDOWN   = 0x0002;
    public const uint MOUSEEVENTF_LEFTUP     = 0x0004;
    public const uint MOUSEEVENTF_RIGHTDOWN  = 0x0008;
    public const uint MOUSEEVENTF_RIGHTUP    = 0x0010;
    public const uint MOUSEEVENTF_MIDDLEDOWN = 0x0020;
    public const uint MOUSEEVENTF_MIDDLEUP   = 0x0040;
    public const uint MOUSEEVENTF_WHEEL      = 0x0800;
}
"@
`;

export class WindowsBackend implements DesktopBackend {
  screenshot(outputPath: string): string {
    ps(
      `Add-Type -AssemblyName System.Windows.Forms; ` +
        `$bmp = New-Object System.Drawing.Bitmap([System.Windows.Forms.Screen]::PrimaryScreen.Bounds.Width, [System.Windows.Forms.Screen]::PrimaryScreen.Bounds.Height); ` +
        `$g = [System.Drawing.Graphics]::FromImage($bmp); ` +
        `$g.CopyFromScreen(0, 0, 0, 0, $bmp.Size); ` +
        `$bmp.Save('${outputPath.replace(/'/g, "''")}'); ` +
        `$g.Dispose(); $bmp.Dispose()`,
    );
    return outputPath;
  }

  mouseMove(x: number, y: number): void {
    ps(`${WIN32_INPUT_TYPE} [Win32Input]::SetCursorPos(${x}, ${y})`);
  }

  mouseClick(
    button: "left" | "right" | "middle" = "left",
    x?: number,
    y?: number,
  ): void {
    const downUp =
      button === "right"
        ? "[Win32Input]::MOUSEEVENTF_RIGHTDOWN, [Win32Input]::MOUSEEVENTF_RIGHTUP"
        : button === "middle"
          ? "[Win32Input]::MOUSEEVENTF_MIDDLEDOWN, [Win32Input]::MOUSEEVENTF_MIDDLEUP"
          : "[Win32Input]::MOUSEEVENTF_LEFTDOWN, [Win32Input]::MOUSEEVENTF_LEFTUP";

    const movePrefix =
      x != null && y != null ? `[Win32Input]::SetCursorPos(${x}, ${y}); ` : "";

    ps(
      `${WIN32_INPUT_TYPE} ${movePrefix}` +
        `$d, $u = ${downUp}; ` +
        `[Win32Input]::mouse_event($d, 0, 0, 0, 0); ` +
        `Start-Sleep -Milliseconds 30; ` +
        `[Win32Input]::mouse_event($u, 0, 0, 0, 0)`,
    );
  }

  mouseDoubleClick(x?: number, y?: number): void {
    const movePrefix =
      x != null && y != null ? `[Win32Input]::SetCursorPos(${x}, ${y}); ` : "";

    ps(
      `${WIN32_INPUT_TYPE} ${movePrefix}` +
        `[Win32Input]::mouse_event([Win32Input]::MOUSEEVENTF_LEFTDOWN, 0, 0, 0, 0); ` +
        `[Win32Input]::mouse_event([Win32Input]::MOUSEEVENTF_LEFTUP, 0, 0, 0, 0); ` +
        `Start-Sleep -Milliseconds 80; ` +
        `[Win32Input]::mouse_event([Win32Input]::MOUSEEVENTF_LEFTDOWN, 0, 0, 0, 0); ` +
        `[Win32Input]::mouse_event([Win32Input]::MOUSEEVENTF_LEFTUP, 0, 0, 0, 0)`,
    );
  }

  typeText(text: string): void {
    ps(
      `Add-Type -AssemblyName System.Windows.Forms; ` +
        `[System.Windows.Forms.SendKeys]::SendWait(${JSON.stringify(text)})`,
    );
  }

  keyPress(keys: string): void {
    const mapped = mapKeysToSendKeys(keys);
    ps(
      `Add-Type -AssemblyName System.Windows.Forms; ` +
        `[System.Windows.Forms.SendKeys]::SendWait('${mapped}')`,
    );
  }

  getMousePosition(): MousePosition {
    const raw = ps(
      `${WIN32_INPUT_TYPE} $p = New-Object Win32Input+POINT; ` +
        `[Win32Input]::GetCursorPos([ref]$p); "$($p.X),$($p.Y)"`,
    );
    const [xStr, yStr] = raw.split(",");
    return {
      x: parseInt(xStr ?? "0", 10),
      y: parseInt(yStr ?? "0", 10),
    };
  }

  getScreenSize(): ScreenSize {
    const raw = ps(
      `Add-Type -AssemblyName System.Windows.Forms; ` +
        `$s = [System.Windows.Forms.Screen]::PrimaryScreen.Bounds; "$($s.Width),$($s.Height)"`,
    );
    const [wStr, hStr] = raw.split(",");
    return {
      width: parseInt(wStr ?? "0", 10),
      height: parseInt(hStr ?? "0", 10),
    };
  }

  mouseDrag(startX: number, startY: number, endX: number, endY: number): void {
    ps(
      `${WIN32_INPUT_TYPE} ` +
        `[Win32Input]::SetCursorPos(${startX}, ${startY}); ` +
        `[Win32Input]::mouse_event([Win32Input]::MOUSEEVENTF_LEFTDOWN, 0, 0, 0, 0); ` +
        `Start-Sleep -Milliseconds 50; ` +
        `[Win32Input]::SetCursorPos(${endX}, ${endY}); ` +
        `Start-Sleep -Milliseconds 50; ` +
        `[Win32Input]::mouse_event([Win32Input]::MOUSEEVENTF_LEFTUP, 0, 0, 0, 0)`,
    );
  }

  scroll(amount: number, x?: number, y?: number): void {
    const movePrefix =
      x != null && y != null ? `[Win32Input]::SetCursorPos(${x}, ${y}); ` : "";
    const wheelDelta = amount > 0 ? -120 : 120;
    const clicks = Math.abs(amount);

    let script = `${WIN32_INPUT_TYPE} ${movePrefix}`;
    for (let i = 0; i < clicks; i++) {
      script += `[Win32Input]::mouse_event([Win32Input]::MOUSEEVENTF_WHEEL, 0, 0, ${wheelDelta}, 0); `;
      if (i < clicks - 1) script += `Start-Sleep -Milliseconds 50; `;
    }
    ps(script);
  }

  getActiveWindowTitle(): string {
    try {
      return ps(
        `${WIN32_INPUT_TYPE} ` +
          `$h = [Win32Input]::GetForegroundWindow(); ` +
          `$sb = New-Object System.Text.StringBuilder(256); ` +
          `[Win32Input]::GetWindowText($h, $sb, 256); $sb.ToString()`,
      );
    } catch {
      return "(unknown)";
    }
  }
}

/**
 * Map xdotool-style key names to .NET SendKeys format.
 *
 * Handles modifier combos like "ctrl+c" → "^c" and named keys
 * like "Return" → "{ENTER}".
 */
function mapKeysToSendKeys(keys: string): string {
  const NAMED: Record<string, string> = {
    return: "{ENTER}",
    enter: "{ENTER}",
    escape: "{ESC}",
    tab: "{TAB}",
    backspace: "{BACKSPACE}",
    delete: "{DELETE}",
    space: " ",
    up: "{UP}",
    down: "{DOWN}",
    left: "{LEFT}",
    right: "{RIGHT}",
    home: "{HOME}",
    end: "{END}",
    page_up: "{PGUP}",
    page_down: "{PGDN}",
    f1: "{F1}",
    f2: "{F2}",
    f3: "{F3}",
    f4: "{F4}",
    f5: "{F5}",
    f6: "{F6}",
    f7: "{F7}",
    f8: "{F8}",
    f9: "{F9}",
    f10: "{F10}",
    f11: "{F11}",
    f12: "{F12}",
  };

  const parts = keys.split("+");
  let prefix = "";
  let mainKey = "";

  for (const part of parts) {
    const lower = part.toLowerCase().trim();
    if (lower === "ctrl" || lower === "control") {
      prefix += "^";
    } else if (lower === "alt") {
      prefix += "%";
    } else if (lower === "shift") {
      prefix += "+";
    } else if (lower === "super" || lower === "win") {
      // SendKeys has no native Win key — skip (best effort)
      prefix += "";
    } else {
      mainKey = NAMED[lower] ?? part;
    }
  }

  return prefix + mainKey;
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
    case "win32":
      _cached = new WindowsBackend();
      break;
    default:
      throw new Error(
        `Computer use tools are not supported on platform: ${process.platform}. ` +
          `Supported: Linux (xdotool), macOS (cliclick), Windows (PowerShell).`,
      );
  }
  return _cached;
}
