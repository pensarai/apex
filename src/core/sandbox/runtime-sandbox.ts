/**
 * Runtime Sandbox Module
 *
 * Prevents agent from cheating on benchmarks by blocking access to:
 * 1. Source code directories
 * 2. Docker container internals
 */

import { spawn } from "child_process";

export interface RuntimeSandboxConfig {
  /** Paths to block (source code directories) */
  blockedPaths: string[];
  /** Block Docker exec/inspect/logs commands */
  blockDockerAccess: boolean;
}

export interface ExecuteCommandOpts {
  command: string;
  timeout?: number;
  background?: boolean;
  toolCallDescription?: string;
}

export interface ExecuteCommandResult {
  success: boolean;
  stdout: string;
  stderr: string;
  command: string;
  error?: string;
}

/**
 * Docker commands that give access to container internals
 */
const DOCKER_CHEAT_PATTERNS = [
  /\bdocker\s+exec\b/i,
  /\bdocker\s+cp\b/i,
  /\bdocker\s+inspect\b/i,
  /\bdocker\s+logs\b/i,
  /\bdocker\s+attach\b/i,
  /\bdocker-compose\s+exec\b/i,
  /\bdocker-compose\s+logs\b/i,
  /\bdocker\s+compose\s+exec\b/i,
  /\bdocker\s+compose\s+logs\b/i,
];

/**
 * Check if command accesses blocked paths or Docker internals
 */
export function isCommandBlocked(
  command: string,
  config: RuntimeSandboxConfig
): { blocked: boolean; reason?: string } {
  // Check for Docker cheating
  if (config.blockDockerAccess) {
    for (const pattern of DOCKER_CHEAT_PATTERNS) {
      if (pattern.test(command)) {
        return {
          blocked: true,
          reason: "Docker container access is blocked in sandbox mode",
        };
      }
    }
  }

  // Check for blocked paths
  for (const blockedPath of config.blockedPaths) {
    // Normalize path for matching
    const normalizedPath = blockedPath.replace(/\/+$/, "");

    // Check if command references the blocked path
    if (command.includes(normalizedPath)) {
      return {
        blocked: true,
        reason: `Access to '${blockedPath}' is blocked in sandbox mode`,
      };
    }
  }

  return { blocked: false };
}

/**
 * Create a sandboxed execute_command function
 */
export function createSandboxedExecutor(
  config: RuntimeSandboxConfig
): (opts: ExecuteCommandOpts) => Promise<ExecuteCommandResult> {
  return async (opts: ExecuteCommandOpts): Promise<ExecuteCommandResult> => {
    const { command, timeout = 30000 } = opts;

    // Check if command is blocked
    const check = isCommandBlocked(command, config);
    if (check.blocked) {
      return {
        success: false,
        stdout: "",
        stderr: "",
        command,
        error: `SANDBOX: ${check.reason}`,
      };
    }

    // Execute the command normally
    return new Promise((resolve) => {
      const shellCmd = process.platform === "win32" ? "cmd" : "bash";
      const shellArgs =
        process.platform === "win32" ? ["/c", command] : ["-lc", command];

      const child = spawn(shellCmd, shellArgs, {
        stdio: ["ignore", "pipe", "pipe"],
      });

      let stdout = "";
      let stderr = "";
      let killed = false;

      const timeoutTimer = setTimeout(() => {
        killed = true;
        child.kill("SIGTERM");
      }, timeout);

      child.stdout.on("data", (data) => {
        stdout += data.toString();
      });

      child.stderr.on("data", (data) => {
        stderr += data.toString();
      });

      child.on("close", (code) => {
        clearTimeout(timeoutTimer);
        resolve({
          success: code === 0 && !killed,
          stdout:
            stdout.length > 50000
              ? `${stdout.substring(0, 50000)}...\n\n(truncated)`
              : stdout || "(no output)",
          stderr: stderr || "",
          command,
          error: killed
            ? "Command timed out"
            : code !== 0
              ? `Exit code: ${code}`
              : "",
        });
      });

      child.on("error", (err) => {
        clearTimeout(timeoutTimer);
        resolve({
          success: false,
          error: err.message,
          stdout,
          stderr,
          command,
        });
      });
    });
  };
}
