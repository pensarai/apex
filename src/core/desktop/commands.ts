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
