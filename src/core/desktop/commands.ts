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
  const envPairs = (launch.environment ?? [])
    .filter((e) => e.value !== undefined)
    .map((e) => ({ name: e.name, value: e.value as string }));

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
  const env = envPairs
    .map((e) => `${e.name}=${quoteArg(os, e.value)}`)
    .join(" ");
  const cd = launch.workingDirectory
    ? `cd ${quoteArg(os, launch.workingDirectory)} && `
    : "";
  const prefix = env ? `${env} ` : "";
  return `bash -lc ${singleQuote(`${cd}${prefix}${quoteArg(os, launch.executablePath)} ${args} >/tmp/pensar-app.log 2>&1 &`)}`;
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
    case "process":
      if (os === "windows") {
        return `powershell -NoProfile -Command "if (Get-Process -Name ${psQuote(check.process)} -ErrorAction SilentlyContinue) { exit 0 } else { exit 1 }"`;
      }
      // pgrep works on linux; macOS ships it too.
      return `pgrep -f ${quoteArg(os, check.process)} >/dev/null`;
    case "port":
      if (os === "windows") {
        return `powershell -NoProfile -Command "if (Get-NetTCPConnection -State Listen -LocalPort ${check.port} -ErrorAction SilentlyContinue) { exit 0 } else { exit 1 }"`;
      }
      if (os === "macos") {
        return `lsof -iTCP:${check.port} -sTCP:LISTEN >/dev/null 2>&1`;
      }
      // linux: prefer ss, fall back to /proc-based check via grep on the hex port.
      return `bash -lc ${singleQuote(`ss -ltn 2>/dev/null | grep -q ":${check.port} "`)}`;
    case "window-title":
      if (os === "linux") {
        return `bash -lc ${singleQuote(`xdotool search --name ${JSON.stringify(check.titleContains)} >/dev/null 2>&1`)}`;
      }
      if (os === "macos") {
        return `osascript -e 'tell application "System Events" to (name of every window of every process) as string' 2>/dev/null | grep -q ${quoteArg(os, check.titleContains)}`;
      }
      return `powershell -NoProfile -Command "if (Get-Process | Where-Object { $_.MainWindowTitle -like '*${check.titleContains.replace(/'/g, "''")}*' }) { exit 0 } else { exit 1 }"`;
    case "log-line":
      if (os === "windows") {
        return `powershell -NoProfile -Command "if (Select-String -Path ${psQuote(check.path)} -Pattern ${psQuote(check.contains)} -Quiet) { exit 0 } else { exit 1 }"`;
      }
      return `grep -q ${quoteArg(os, check.contains)} ${quoteArg(os, check.path)}`;
  }
}

/** Capture a screenshot of the desktop to `outPath`. */
export function screenshotCommand(os: DesktopOs, outPath: string): string {
  if (os === "windows") {
    // Uses .NET via PowerShell to grab the virtual screen.
    const body = `Add-Type -AssemblyName System.Windows.Forms,System.Drawing; $b=[System.Windows.Forms.SystemInformation]::VirtualScreen; $bmp=New-Object System.Drawing.Bitmap($b.Width,$b.Height); $g=[System.Drawing.Graphics]::FromImage($bmp); $g.CopyFromScreen($b.Location,[System.Drawing.Point]::Empty,$b.Size); $bmp.Save(${psQuote(outPath)})`;
    return `powershell -NoProfile -Command ${psQuote(body)}`;
  }
  if (os === "macos") {
    return `screencapture -x ${quoteArg(os, outPath)}`;
  }
  // linux: scrot or import (ImageMagick); try scrot first.
  return `bash -lc ${singleQuote(`scrot ${outPath} 2>/dev/null || import -window root ${outPath}`)}`;
}
