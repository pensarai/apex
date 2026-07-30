/**
 * Pure, per-OS command builders for the desktop environment.
 *
 * These produce the exact shell strings the runner hands to `DesktopExec`.
 * Deterministic string builders (no I/O) so every OS dialect is unit-tested in
 * isolation — installing/launching a desktop app is a deterministic transform,
 * not a model judgement.
 */
import type { BuildManifest, DesktopOs, ReadinessCheck } from "./types";

// Escape a script body for embedding inside a single-quoted shell argument.
function singleQuote(body: string): string {
  return `'${body.replace(/'/g, `'\\''`)}'`;
}

// PowerShell single-quote escaping doubles the quote.
function psQuote(body: string): string {
  return `'${body.replace(/'/g, "''")}'`;
}

// Manifest strings are literals, but PowerShell's -like treats these as
// wildcards — backtick-escape them so the match stays literal.
function escapeLikePattern(value: string): string {
  return value.replace(/([`*?[\]])/g, "`$1");
}

/**
 * Wrap an install/teardown script body in the OS's shell. Windows scripts run
 * under PowerShell; Linux/macOS under bash. The body itself is author-supplied
 * (or synthesized by the Console recipe) and already OS-appropriate.
 */
export function shellRun(os: DesktopOs, scriptBody: string): string {
  if (os === "windows") {
    return `powershell -NoProfile -NonInteractive -Command ${psQuote(scriptBody)}`;
  }
  return `bash -lc ${singleQuote(scriptBody)}`;
}

function quoteArg(os: DesktopOs, arg: string): string {
  if (os === "windows") return `'${arg.replace(/'/g, "''")}'`;
  return `"${arg.replace(/(["\\$`])/g, "\\$1")}"`;
}

// Where a backgrounded linux/macOS app's stdout+stderr land, so the readiness
// log-line check has something to grep.
const LAUNCH_LOG_PATH = "/tmp/pensar-app.log";

/**
 * Build a command that launches the app in the background so the runner can
 * proceed to readiness checks. Requires `launch.executablePath`.
 */
export function launchCommand(
  os: DesktopOs,
  launch: BuildManifest["launch"],
): string {
  if (!launch.executablePath) {
    throw new Error(
      "launch.executablePath is required to launch a desktop app",
    );
  }
  const args = (launch.args ?? []).map((a) => quoteArg(os, a)).join(" ");
  // Manifests are parsed JSON: only inline entries that actually carry a
  // string value (secretRef-only entries, and nulls, are not inlined).
  const envPairs = (launch.environment ?? []).filter(
    (e): e is { name: string; value: string } =>
      typeof e.name === "string" && typeof e.value === "string",
  );

  if (os === "windows") {
    const argList = launch.args?.length
      ? ` -ArgumentList ${launch.args.map((a) => quoteArg(os, a)).join(",")}`
      : "";
    const env = envPairs
      .map((e) => `$env:${e.name}=${quoteArg(os, e.value)}; `)
      .join("");
    const wd = launch.workingDirectory
      ? ` -WorkingDirectory ${quoteArg(os, launch.workingDirectory)}`
      : "";
    return `powershell -NoProfile -Command "${env}Start-Process -FilePath ${quoteArg(os, launch.executablePath)}${argList}${wd}"`;
  }

  // linux / macos: cd (if wd) then background the process with env prefix.
  // The redirects must wrap the whole group, not just the app: `cd X && app
  // >log &` backgrounds a subshell that keeps the executor's stdout/stderr
  // pipes open, so the executor blocks until the app exits.
  const env = envPairs
    .map((e) => `${e.name}=${quoteArg(os, e.value)}`)
    .join(" ");
  const cd = launch.workingDirectory
    ? `cd ${quoteArg(os, launch.workingDirectory)} && `
    : "";
  const run = [env, quoteArg(os, launch.executablePath), args]
    .filter((part) => part !== "")
    .join(" ");
  return `bash -lc ${singleQuote(`{ ${cd}${run}; } </dev/null >${LAUNCH_LOG_PATH} 2>&1 &`)}`;
}

/**
 * A single-shot readiness probe: a command that exits 0 when the app is ready.
 * The runner polls it. `sleep` returns null (the runner just waits). Best-effort
 * for window-title / log-line.
 */
export function readinessProbe(
  os: DesktopOs,
  check: ReadinessCheck,
): string | null {
  switch (check.kind) {
    case "sleep":
      return null;
    case "process": {
      if (os === "windows") {
        // Match the full command line (and fall back to the image name) so the
        // same manifest string — a path fragment or an argv substring — works
        // here as it does under `pgrep -f`. Get-Process -Name only matches the
        // bare image name, which silently never fires for those manifests.
        const pattern = psQuote(`*${escapeLikePattern(check.process)}*`);
        return `powershell -NoProfile -Command "if (Get-CimInstance Win32_Process | Where-Object { $_.CommandLine -like ${pattern} -or $_.Name -like ${pattern} }) { exit 0 } else { exit 1 }"`;
      }
      // pgrep works on linux; macOS ships it too.
      return `pgrep -f ${quoteArg(os, check.process)} >/dev/null`;
    }
    case "port":
      if (os === "windows") {
        return `powershell -NoProfile -Command "if (Get-NetTCPConnection -State Listen -LocalPort ${check.port} -ErrorAction SilentlyContinue) { exit 0 } else { exit 1 }"`;
      }
      if (os === "macos") {
        return `lsof -iTCP:${check.port} -sTCP:LISTEN >/dev/null 2>&1`;
      }
      // linux: prefer ss, but minimal images often ship without iproute2 — fall
      // back to a loopback connect so the probe doesn't silently never fire.
      return `bash -lc ${singleQuote(`ss -ltn 2>/dev/null | grep -q ":${check.port} " || (exec 3<>/dev/tcp/127.0.0.1/${check.port}) 2>/dev/null`)}`;
    case "window-title":
      if (os === "linux") {
        return `bash -lc ${singleQuote(`xdotool search --name ${quoteArg(os, check.titleContains)} >/dev/null 2>&1`)}`;
      }
      if (os === "macos") {
        return `osascript -e 'tell application "System Events" to (name of every window of every process) as string' 2>/dev/null | grep -q ${quoteArg(os, check.titleContains)}`;
      }
      return `powershell -NoProfile -Command "if (Get-Process | Where-Object { $_.MainWindowTitle -like ${psQuote(`*${escapeLikePattern(check.titleContains)}*`)} }) { exit 0 } else { exit 1 }"`;
    case "log-line":
      if (os === "windows") {
        return `powershell -NoProfile -Command "if (Select-String -Path ${psQuote(check.path)} -Pattern ${psQuote(check.contains)} -Quiet) { exit 0 } else { exit 1 }"`;
      }
      return `grep -q ${quoteArg(os, check.contains)} ${quoteArg(os, check.path)}`;
  }
}

// ---------------------------------------------------------------------------
// Computer-use (desktop GUI automation) command builders.
//
// Once a build artifact is installed + launched by the runner, the offensive
// agent DRIVES it: screenshot → click → type → verify. These builders produce
// the exact shell strings for each interaction on the three desktop OSes.
//
// Backends:
//   Linux   → xdotool (input) + scrot / ImageMagick `import` (capture)
//   macOS   → cliclick (input) + screencapture (capture)
//   Windows → PowerShell + .NET (System.Windows.Forms / user32.dll P/Invoke)
//
// The strings are executed LOCALLY (the agent runs on the sandbox VM), so a
// POSIX command is handed to `/bin/sh -c` and a Windows command to `cmd.exe`.
// Windows scripts are base64-encoded (`-EncodedCommand`) so multi-line C#
// P/Invoke — which embeds double quotes and newlines — survives cmd.exe's
// quoting rules that `-Command "…"` cannot.
// ---------------------------------------------------------------------------

/** xdotool button numbers. */
const XDOTOOL_BUTTON: Record<"left" | "middle" | "right", number> = {
  left: 1,
  middle: 2,
  right: 3,
};

/**
 * .NET user32 P/Invoke surface, injected once per Windows input script. Emits a
 * `PensarWin32` type providing cursor move/read, synthetic clicks + wheel, and
 * the foreground-window title.
 */
const WIN32_INPUT = `Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
using System.Text;
public class PensarWin32 {
  [DllImport("user32.dll")] public static extern bool SetCursorPos(int X, int Y);
  [DllImport("user32.dll")] public static extern bool GetCursorPos(out POINT lpPoint);
  [DllImport("user32.dll")] public static extern void mouse_event(uint dwFlags, int dx, int dy, int dwData, int dwExtraInfo);
  [DllImport("user32.dll")] public static extern IntPtr GetForegroundWindow();
  [DllImport("user32.dll", CharSet=CharSet.Auto)] public static extern int GetWindowText(IntPtr hWnd, StringBuilder lpString, int nMaxCount);
  [StructLayout(LayoutKind.Sequential)] public struct POINT { public int X; public int Y; }
  public const uint LEFTDOWN=0x0002; public const uint LEFTUP=0x0004;
  public const uint RIGHTDOWN=0x0008; public const uint RIGHTUP=0x0010;
  public const uint MIDDLEDOWN=0x0020; public const uint MIDDLEUP=0x0040;
  public const uint WHEEL=0x0800;
}
"@`;

// Down/up mouse_event flag pair for a button.
const WIN32_CLICK_FLAGS: Record<"left" | "middle" | "right", string> = {
  left: "[PensarWin32]::LEFTDOWN, [PensarWin32]::LEFTUP",
  middle: "[PensarWin32]::MIDDLEDOWN, [PensarWin32]::MIDDLEUP",
  right: "[PensarWin32]::RIGHTDOWN, [PensarWin32]::RIGHTUP",
};

/**
 * Wrap a PowerShell script as a base64 `-EncodedCommand` invocation. Encoding
 * sidesteps all cmd.exe / PowerShell quoting pitfalls for scripts carrying
 * embedded quotes or newlines (the C# P/Invoke block). UTF-16LE is what
 * PowerShell's `-EncodedCommand` expects.
 */
function pwshEncoded(script: string): string {
  const encoded = Buffer.from(script, "utf16le").toString("base64");
  return `powershell -NoProfile -NonInteractive -EncodedCommand ${encoded}`;
}

/** cliclick left/right prefix. cliclick has no middle click — map it to left. */
function cliclickButton(button: "left" | "middle" | "right"): "c" | "rc" {
  return button === "right" ? "rc" : "c";
}

/**
 * Capture the primary screen to `outputPath` (PNG). The computer-use screenshot
 * tool runs this, then reads the file back as base64 for the model.
 */
export function screenshotCommand(os: DesktopOs, outputPath: string): string {
  if (os === "linux") {
    // scrot on most desktops; ImageMagick `import` as a fallback.
    return `scrot -o ${quoteArg(os, outputPath)} 2>/dev/null || import -window root ${quoteArg(os, outputPath)}`;
  }
  if (os === "macos") {
    return `screencapture -x ${quoteArg(os, outputPath)}`;
  }
  return pwshEncoded(
    `Add-Type -AssemblyName System.Windows.Forms; Add-Type -AssemblyName System.Drawing; ` +
      `$b = [System.Windows.Forms.Screen]::PrimaryScreen.Bounds; ` +
      `$bmp = New-Object System.Drawing.Bitmap($b.Width, $b.Height); ` +
      `$g = [System.Drawing.Graphics]::FromImage($bmp); ` +
      `$g.CopyFromScreen(0, 0, 0, 0, $bmp.Size); ` +
      `$bmp.Save('${outputPath.replace(/'/g, "''")}'); ` +
      `$g.Dispose(); $bmp.Dispose()`,
  );
}

/** Move the cursor to absolute (x, y). */
export function mouseMoveCommand(os: DesktopOs, x: number, y: number): string {
  if (os === "linux") return `xdotool mousemove ${x} ${y}`;
  if (os === "macos") return `cliclick m:${x},${y}`;
  return pwshEncoded(`${WIN32_INPUT} [PensarWin32]::SetCursorPos(${x}, ${y})`);
}

/** Click `button` at absolute (x, y). */
export function mouseClickCommand(
  os: DesktopOs,
  button: "left" | "middle" | "right",
  x: number,
  y: number,
): string {
  if (os === "linux") {
    return `xdotool mousemove ${x} ${y} click ${XDOTOOL_BUTTON[button]}`;
  }
  if (os === "macos") {
    return `cliclick ${cliclickButton(button)}:${x},${y}`;
  }
  return pwshEncoded(
    `${WIN32_INPUT} [PensarWin32]::SetCursorPos(${x}, ${y}); ` +
      `$d, $u = ${WIN32_CLICK_FLAGS[button]}; ` +
      `[PensarWin32]::mouse_event($d, 0, 0, 0, 0); ` +
      `Start-Sleep -Milliseconds 30; ` +
      `[PensarWin32]::mouse_event($u, 0, 0, 0, 0)`,
  );
}

/** Double-click (left button) at absolute (x, y). */
export function mouseDoubleClickCommand(
  os: DesktopOs,
  x: number,
  y: number,
): string {
  if (os === "linux") {
    return `xdotool mousemove ${x} ${y} click --repeat 2 --delay 80 1`;
  }
  if (os === "macos") return `cliclick dc:${x},${y}`;
  return pwshEncoded(
    `${WIN32_INPUT} [PensarWin32]::SetCursorPos(${x}, ${y}); ` +
      `[PensarWin32]::mouse_event([PensarWin32]::LEFTDOWN, 0, 0, 0, 0); ` +
      `[PensarWin32]::mouse_event([PensarWin32]::LEFTUP, 0, 0, 0, 0); ` +
      `Start-Sleep -Milliseconds 80; ` +
      `[PensarWin32]::mouse_event([PensarWin32]::LEFTDOWN, 0, 0, 0, 0); ` +
      `[PensarWin32]::mouse_event([PensarWin32]::LEFTUP, 0, 0, 0, 0)`,
  );
}

/** Click-and-drag from (startX, startY) to (endX, endY). */
export function mouseDragCommand(
  os: DesktopOs,
  startX: number,
  startY: number,
  endX: number,
  endY: number,
): string {
  if (os === "linux") {
    return `xdotool mousemove ${startX} ${startY} mousedown 1 mousemove ${endX} ${endY} mouseup 1`;
  }
  if (os === "macos") {
    return `cliclick dd:${startX},${startY} du:${endX},${endY}`;
  }
  return pwshEncoded(
    `${WIN32_INPUT} [PensarWin32]::SetCursorPos(${startX}, ${startY}); ` +
      `[PensarWin32]::mouse_event([PensarWin32]::LEFTDOWN, 0, 0, 0, 0); ` +
      `Start-Sleep -Milliseconds 50; ` +
      `[PensarWin32]::SetCursorPos(${endX}, ${endY}); ` +
      `Start-Sleep -Milliseconds 50; ` +
      `[PensarWin32]::mouse_event([PensarWin32]::LEFTUP, 0, 0, 0, 0)`,
  );
}

/** Type literal `text` via the keyboard (no key-combo interpretation). */
export function typeTextCommand(os: DesktopOs, text: string): string {
  if (os === "linux") {
    return `xdotool type --clearmodifiers -- ${quoteArg(os, text)}`;
  }
  if (os === "macos") {
    return `cliclick ${quoteArg(os, `t:${text}`)}`;
  }
  return pwshEncoded(
    `Add-Type -AssemblyName System.Windows.Forms; ` +
      `[System.Windows.Forms.SendKeys]::SendWait('${escapeSendKeysLiteral(text)}')`,
  );
}

/**
 * Press a key or key combination (e.g. `Return`, `ctrl+c`, `alt+Tab`). Combos
 * are `+`-separated. Each backend has its own key vocabulary, so the string is
 * translated per OS.
 */
export function keyPressCommand(os: DesktopOs, keys: string): string {
  if (os === "linux") {
    // xdotool speaks the same `mod+key` syntax we accept — pass it through.
    return `xdotool key --clearmodifiers ${quoteArg(os, keys)}`;
  }
  if (os === "macos") {
    return `cliclick ${mapKeysToCliclick(keys)
      .map((a) => quoteArg(os, a))
      .join(" ")}`;
  }
  return pwshEncoded(
    `Add-Type -AssemblyName System.Windows.Forms; ` +
      `[System.Windows.Forms.SendKeys]::SendWait('${mapKeysToSendKeys(keys)}')`,
  );
}

/**
 * Scroll the mouse wheel. Positive = down, negative = up. `amount` is the
 * number of wheel notches. Optionally scroll at a specific (x, y).
 */
export function scrollCommand(
  os: DesktopOs,
  amount: number,
  x?: number,
  y?: number,
): string {
  const clicks = Math.max(1, Math.abs(amount));
  const hasPos = typeof x === "number" && typeof y === "number";
  if (os === "linux") {
    const button = amount > 0 ? 5 : 4; // 5 = down, 4 = up
    const move = hasPos ? `mousemove ${x} ${y} ` : "";
    return `xdotool ${move}click --repeat ${clicks} --delay 50 ${button}`;
  }
  if (os === "macos") {
    // cliclick has no wheel primitive — approximate with arrow keys.
    const key = amount > 0 ? "arrow-down" : "arrow-up";
    const move = hasPos ? `m:${x},${y} ` : "";
    const taps = Array.from({ length: clicks }, () => `kp:${key}`).join(" ");
    return `cliclick ${move}${taps}`;
  }
  const wheelDelta = amount > 0 ? -120 : 120; // 120 = one notch; negative = down
  const move = hasPos ? `[PensarWin32]::SetCursorPos(${x}, ${y}); ` : "";
  const wheels = Array.from(
    { length: clicks },
    () =>
      `[PensarWin32]::mouse_event([PensarWin32]::WHEEL, 0, 0, ${wheelDelta}, 0); `,
  ).join("Start-Sleep -Milliseconds 40; ");
  return pwshEncoded(`${WIN32_INPUT} ${move}${wheels}`.trim());
}

/**
 * Report the current desktop state: screen size, cursor position, and the
 * active window title. Output is `KEY=VALUE` lines — `SIZE=W,H`, `POS=X,Y`,
 * `TITLE=…` — so the tool can parse it uniformly across OSes.
 */
export function screenInfoCommand(os: DesktopOs): string {
  if (os === "linux") {
    return (
      `echo "SIZE=$(xdotool getdisplaygeometry 2>/dev/null | tr ' ' ',')"; ` +
      `echo "POS=$(xdotool getmouselocation --shell 2>/dev/null | grep -E '^(X|Y)=' | cut -d= -f2 | paste -sd, -)"; ` +
      `echo "TITLE=$(xdotool getactivewindow getwindowname 2>/dev/null)"`
    );
  }
  if (os === "macos") {
    const size = `osascript -l JavaScript -e 'ObjC.import("AppKit"); var f = $.NSScreen.mainScreen.frame; f.size.width + "," + f.size.height' 2>/dev/null`;
    const title = `osascript -e 'tell application "System Events" to get name of first application process whose frontmost is true' 2>/dev/null`;
    return (
      `echo "SIZE=$(${size})"; ` +
      `echo "POS=$(cliclick p 2>/dev/null)"; ` +
      `echo "TITLE=$(${title})"`
    );
  }
  return pwshEncoded(
    `${WIN32_INPUT} Add-Type -AssemblyName System.Windows.Forms; ` +
      `$s = [System.Windows.Forms.SystemInformation]::PrimaryMonitorSize; ` +
      `Write-Output ("SIZE=" + $s.Width + "," + $s.Height); ` +
      `$p = New-Object PensarWin32+POINT; [PensarWin32]::GetCursorPos([ref]$p); ` +
      `Write-Output ("POS=" + $p.X + "," + $p.Y); ` +
      `$h = [PensarWin32]::GetForegroundWindow(); ` +
      `$sb = New-Object System.Text.StringBuilder 256; ` +
      `[PensarWin32]::GetWindowText($h, $sb, 256) | Out-Null; ` +
      `Write-Output ("TITLE=" + $sb.ToString())`,
  );
}

// ---------------------------------------------------------------------------
// Key-combo translation (internal — validated indirectly via keyPressCommand
// tests). `ctrl+c` style input maps onto each backend's key vocabulary.
// ---------------------------------------------------------------------------

const CLICLICK_MODIFIERS: Record<string, string> = {
  ctrl: "ctrl",
  control: "ctrl",
  alt: "alt",
  option: "alt",
  shift: "shift",
  super: "cmd",
  win: "cmd",
  cmd: "cmd",
  command: "cmd",
};

const CLICLICK_KEYS: Record<string, string> = {
  return: "return",
  enter: "return",
  escape: "esc",
  esc: "esc",
  tab: "tab",
  backspace: "delete",
  delete: "fwd-delete",
  space: "space",
  up: "arrow-up",
  down: "arrow-down",
  left: "arrow-left",
  right: "arrow-right",
  home: "home",
  end: "end",
  page_up: "page-up",
  page_down: "page-down",
};

/**
 * Translate a `mod+key` combo into cliclick args. cliclick taps single keys
 * with `kp:`; modifiers are expressed as surrounding `kd:` / `ku:` (down/up).
 */
function mapKeysToCliclick(keys: string): string[] {
  const modifiers: string[] = [];
  let mainKey = "";
  for (const part of keys.split("+")) {
    const lower = part.toLowerCase().trim();
    const mod = CLICLICK_MODIFIERS[lower];
    if (mod) {
      modifiers.push(mod);
    } else {
      mainKey = CLICLICK_KEYS[lower] ?? part.trim();
    }
  }
  if (modifiers.length === 0) return [`kp:${mainKey}`];
  return [
    ...modifiers.map((m) => `kd:${m}`),
    `kp:${mainKey}`,
    ...[...modifiers].reverse().map((m) => `ku:${m}`),
  ];
}

const SENDKEYS_MODIFIERS: Record<string, string> = {
  ctrl: "^",
  control: "^",
  alt: "%",
  shift: "+",
};

const SENDKEYS_KEYS: Record<string, string> = {
  return: "{ENTER}",
  enter: "{ENTER}",
  escape: "{ESC}",
  esc: "{ESC}",
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
};

/**
 * Translate a `mod+key` combo into a .NET `SendKeys` string (`ctrl+c` → `^c`,
 * `Return` → `{ENTER}`). The Super/Win key has no SendKeys equivalent and is
 * dropped (best-effort).
 */
function mapKeysToSendKeys(keys: string): string {
  let prefix = "";
  let mainKey = "";
  for (const part of keys.split("+")) {
    const lower = part.toLowerCase().trim();
    if (lower === "super" || lower === "win" || lower === "cmd") continue;
    const mod = SENDKEYS_MODIFIERS[lower];
    if (mod) {
      prefix += mod;
    } else {
      mainKey = SENDKEYS_KEYS[lower] ?? part.trim();
    }
  }
  return `${prefix}${mainKey}`;
}

/**
 * Escape literal text for `SendKeys.SendWait`, which treats `+ ^ % ~ ( ) { } [ ]`
 * as control characters — each must be wrapped in braces to type literally.
 * Single quotes are doubled for the surrounding PowerShell single-quoted string.
 */
function escapeSendKeysLiteral(text: string): string {
  return text.replace(/([+^%~(){}[\]])/g, "{$1}").replace(/'/g, "''");
}
