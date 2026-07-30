/**
 * Local execution runtime for the computer-use tools.
 *
 * CRITICAL execution model: the offensive-security agent runs ON the sandbox
 * VM itself, so desktop automation commands execute LOCALLY via
 * `node:child_process` — never through `ctx.sandbox`. The OS is resolved once
 * from `process.platform`. This mirrors the local-executor pattern in
 * `core/api/desktopBuild.ts` (`localExec`).
 */
import { exec as cpExec } from "node:child_process";
import { promisify } from "node:util";
import type {
  DesktopExec,
  DesktopExecResult,
  DesktopOs,
} from "../../../../desktop";

const pexec = promisify(cpExec);

// Desktop interactions are near-instant; cap so a wedged xdotool / PowerShell
// call can't hang the agent.
const DEFAULT_TIMEOUT_SECONDS = 20;

/**
 * Execute a command on the local machine (the sandbox VM). Failures resolve to
 * a non-success result carrying stderr instead of throwing, so tools can return
 * a structured error to the model.
 */
export const localExec: DesktopExec = async (command, opts) => {
  try {
    const { stdout, stderr } = await pexec(command, {
      cwd: opts?.cwd,
      env: opts?.envVars ? { ...process.env, ...opts.envVars } : process.env,
      timeout: (opts?.timeout ?? DEFAULT_TIMEOUT_SECONDS) * 1000,
      maxBuffer: 32 * 1024 * 1024,
    });
    return { stdout, stderr, exitCode: 0, success: true };
  } catch (e) {
    const err = e as { stdout?: string; stderr?: string; code?: number };
    return {
      stdout: err.stdout ?? "",
      stderr: err.stderr ?? String(e),
      exitCode: typeof err.code === "number" ? err.code : 1,
      success: false,
    };
  }
};

const PLATFORM_TO_OS: Partial<Record<NodeJS.Platform, DesktopOs>> = {
  linux: "linux",
  darwin: "macos",
  win32: "windows",
};

/**
 * Resolve the desktop OS from Node's `process.platform`. Throws on an
 * unsupported platform so the caller fails loud rather than emitting a command
 * for the wrong backend.
 */
export function resolveDesktopOs(
  platform: NodeJS.Platform = process.platform,
): DesktopOs {
  const os = PLATFORM_TO_OS[platform];
  if (!os) {
    throw new Error(
      `Computer-use tools are not supported on platform "${platform}". ` +
        `Supported: linux (xdotool), darwin (cliclick), win32 (PowerShell).`,
    );
  }
  return os;
}

export interface DesktopActionResult {
  success: boolean;
  message: string;
}

/**
 * Run a builder-produced command locally and fold the raw exec result into a
 * `{ success, message }` shape. `label` describes the action for the message.
 */
export async function runDesktopCommand(
  command: string,
  label: string,
): Promise<DesktopActionResult & { raw: DesktopExecResult }> {
  const raw = await localExec(command);
  if (raw.success) {
    return { success: true, message: label, raw };
  }
  const detail = (raw.stderr || raw.stdout).trim();
  return {
    success: false,
    message: detail ? `${label} failed: ${detail}` : `${label} failed`,
    raw,
  };
}
