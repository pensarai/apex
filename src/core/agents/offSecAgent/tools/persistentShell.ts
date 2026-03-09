import { spawn, spawnSync, type ChildProcess } from "child_process";
import { randomBytes } from "crypto";

/** Hard memory safety cap — prevents OOM on pathological output (5 MB). */
const MAX_BUFFER = 5_000_000;

export interface ShellExecuteResult {
  stdout: string;
  stderr: string;
  exitCode: number;
}

/**
 * A long-lived bash process that persists across execute_command calls.
 *
 * Commands are sent to stdin and delimited with unique markers so the
 * caller can extract per-command stdout, stderr, and the exit code.
 * Background processes (`&`) survive between calls because the parent
 * shell never exits.
 */
export class PersistentShell {
  private proc: ChildProcess | null = null;
  private alive = false;
  private disposed = false;
  private readonly cwd?: string;

  /** Allows cancelCurrentCommand() to force-resolve the running execute(). */
  private pendingCancel: ((result: ShellExecuteResult) => void) | null = null;
  /** Snapshot accessors set by execute(), read by cancelCurrentCommand(). */
  private pendingStdout: (() => string) | null = null;
  private pendingStderr: (() => string) | null = null;

  constructor(opts?: { cwd?: string }) {
    this.cwd = opts?.cwd;
  }

  private spawn(): void {
    if (this.disposed) return;

    const shell = process.platform === "win32" ? "cmd" : "bash";
    const args = process.platform === "win32" ? [] : ["--norc", "--noprofile"];

    this.proc = spawn(shell, args, {
      stdio: ["pipe", "pipe", "pipe"],
      cwd: this.cwd,
      // New session so child has no controlling terminal — prevents
      // interactive programs from writing prompts to the TUI's TTY.
      detached: process.platform !== "win32",
      env: {
        ...process.env,
        PS1: "",
        // Hint to CLI tools that we're non-interactive
        CI: "true",
        TERM: "dumb",
        NO_COLOR: "1",
      },
    });

    this.alive = true;

    this.proc.on("close", () => {
      this.alive = false;
      this.proc = null;
    });

    this.proc.on("error", () => {
      this.alive = false;
      this.proc = null;
    });
  }

  private ensureAlive(): void {
    if (!this.alive || !this.proc) {
      this.spawn();
    }
  }

  async execute(
    command: string,
    timeoutSeconds?: number,
    onData?: (chunk: string) => void,
    abortSignal?: AbortSignal,
  ): Promise<ShellExecuteResult> {
    if (this.disposed) {
      return { stdout: "", stderr: "Shell has been disposed", exitCode: 1 };
    }

    if (abortSignal?.aborted) {
      return {
        stdout: "",
        stderr: "Command aborted",
        exitCode: 130,
      };
    }

    this.ensureAlive();

    const proc = this.proc;
    if (!proc || !proc.stdin || !proc.stdout || !proc.stderr) {
      return { stdout: "", stderr: "Failed to spawn shell", exitCode: 1 };
    }

    const marker = `__APEX_${randomBytes(8).toString("hex")}__`;
    const exitMarkerPrefix = `${marker}_EXIT_`;

    return new Promise<ShellExecuteResult>((resolve) => {
      let stdout = "";
      let stderr = "";
      let stdoutTruncated = false;
      let resolved = false;
      let timeoutTimer: ReturnType<typeof setTimeout> | undefined;
      // Declared here so safeResolve can remove it; assigned after definition.
      let onClose: (() => void) | null = null;

      this.pendingStdout = () => stdout;
      this.pendingStderr = () => stderr;

      const safeResolve = (result: ShellExecuteResult) => {
        if (resolved) return;
        resolved = true;
        this.pendingCancel = null;
        this.pendingStdout = null;
        this.pendingStderr = null;
        if (timeoutTimer) clearTimeout(timeoutTimer);
        if (abortCleanup) abortCleanup();
        proc.stdout!.removeListener("data", onStdout);
        proc.stderr!.removeListener("data", onStderr);
        if (onClose) proc.removeListener("close", onClose);
        resolve(result);
      };

      this.pendingCancel = safeResolve;

      // Wire abort signal to cancel running command
      let abortCleanup: (() => void) | undefined;
      if (abortSignal) {
        const onAbort = () => {
          if (resolved) return;
          const pid = proc.pid;
          if (pid && process.platform !== "win32") {
            try {
              spawnSync("pkill", ["-TERM", "-P", pid.toString()], {
                stdio: "ignore",
              });
            } catch {
              // pkill may not be available or no processes matched
            }
          }
          setTimeout(() => {
            safeResolve({
              stdout: stdout || "(no output)",
              stderr: stderr ? stderr + "\n(aborted)" : "(aborted)",
              exitCode: 130,
            });
          }, 500);
        };
        abortSignal.addEventListener("abort", onAbort, { once: true });
        abortCleanup = () => abortSignal.removeEventListener("abort", onAbort);
      }

      const onStdout = (data: Buffer) => {
        const chunk = data.toString();
        if (onData && !chunk.includes(exitMarkerPrefix)) {
          onData(chunk);
        }
        stdout += chunk;

        const markerIdx = stdout.indexOf(exitMarkerPrefix);
        if (markerIdx !== -1) {
          const afterPrefix = stdout.substring(
            markerIdx + exitMarkerPrefix.length,
          );
          const nlIdx = afterPrefix.indexOf("\n");
          const exitStr =
            nlIdx >= 0 ? afterPrefix.substring(0, nlIdx) : afterPrefix;
          const exitCode = parseInt(exitStr, 10);

          let commandOutput = stdout.substring(0, markerIdx);
          if (stdoutTruncated) {
            commandOutput = "(stdout truncated)...\n" + commandOutput;
          }

          safeResolve({
            stdout: commandOutput || "(no output)",
            stderr: stderr || "",
            exitCode: isNaN(exitCode) ? 1 : exitCode,
          });
          return;
        }

        if (stdout.length > MAX_BUFFER) {
          stdout = stdout.substring(stdout.length - MAX_BUFFER);
          stdoutTruncated = true;
        }
      };

      const onStderr = (data: Buffer) => {
        stderr += data.toString();
        if (stderr.length > MAX_BUFFER) {
          stderr = stderr.substring(0, MAX_BUFFER) + "...\n(stderr truncated)";
        }
      };

      proc.stdout!.on("data", onStdout);
      proc.stderr!.on("data", onStderr);

      onClose = () => {
        safeResolve({
          stdout: stdout || "(no output)",
          stderr: stderr || "",
          exitCode: 1,
        });
      };
      proc.once("close", onClose);

      if (timeoutSeconds != null && timeoutSeconds > 0) {
        timeoutTimer = setTimeout(() => {
          if (resolved) return;
          // Kill child processes of the bash shell using signals.
          // Writing to stdin doesn't work because bash is blocked on the
          // foreground command and won't read stdin until it completes.
          const pid = proc.pid;
          if (pid && process.platform !== "win32") {
            try {
              spawnSync("pkill", ["-TERM", "-P", pid.toString()], {
                stdio: "ignore",
              });
            } catch {
              // pkill may not be available or no processes matched
            }
          }
          setTimeout(() => {
            safeResolve({
              stdout: stdout || "(no output)",
              stderr: stderr || "",
              exitCode: 124,
            });
          }, 1_000);
        }, timeoutSeconds * 1_000);
      }

      // Wrap command: capture stderr to temp file, echo exit marker on stdout.
      // The subshell (...) isolates the command so `set -e` etc. don't kill
      // our marker echo, and stderr redirection is clean.
      const wrapped = [
        `__APEX_ERR=$(mktemp 2>/dev/null || echo /tmp/.apex_err_$$)`,
        `( ${command} ) 2>"$__APEX_ERR"`,
        `__APEX_EC=$?`,
        `cat "$__APEX_ERR" >&2`,
        `rm -f "$__APEX_ERR"`,
        `echo "${exitMarkerPrefix}$__APEX_EC"`,
        ``,
      ].join("\n");

      try {
        proc.stdin!.write(wrapped);
      } catch {
        safeResolve({
          stdout: "",
          stderr: "Failed to write to shell stdin",
          exitCode: 1,
        });
      }
    });
  }

  /**
   * Cancel the currently running command without killing the shell.
   * Returns true if a command was running and was cancelled.
   */
  cancelCurrentCommand(): boolean {
    if (!this.pendingCancel || !this.proc) return false;

    const cancel = this.pendingCancel;
    const stdout = this.pendingStdout?.() ?? "";
    const stderr = this.pendingStderr?.() ?? "";

    // Kill child processes of the bash shell using signals.
    // Writing to stdin doesn't work because bash is blocked on the
    // foreground command and won't read stdin until it completes.
    const pid = this.proc.pid;
    if (pid && process.platform !== "win32") {
      try {
        spawnSync("pkill", ["-TERM", "-P", pid.toString()], {
          stdio: "ignore",
        });
      } catch {
        // pkill may not be available or no processes matched
      }
    }

    // Give the process a moment to die, then force-resolve with partial output
    setTimeout(() => {
      cancel({
        stdout: stdout || "(no output)",
        stderr: stderr
          ? stderr + "\n(cancelled by user)"
          : "(cancelled by user)",
        exitCode: 130,
      });
    }, 500);

    return true;
  }

  dispose(): void {
    if (this.disposed) return;
    this.disposed = true;

    if (this.proc) {
      try {
        this.proc.stdin?.write("exit\n");
      } catch {
        // ignore
      }

      const p = this.proc;
      const pid = p.pid;
      setTimeout(() => {
        // Kill the entire process group (detached session) so all
        // child processes are cleaned up, not just the shell itself.
        if (pid && process.platform !== "win32") {
          try {
            process.kill(-pid, "SIGTERM");
          } catch {
            // group may already be gone
          }
        }
        try {
          p.kill("SIGTERM");
        } catch {
          // already dead
        }
        setTimeout(() => {
          if (pid && process.platform !== "win32") {
            try {
              process.kill(-pid, "SIGKILL");
            } catch {
              // group may already be gone
            }
          }
          try {
            p.kill("SIGKILL");
          } catch {
            // already dead
          }
        }, 2_000);
      }, 1_000);
    }

    this.alive = false;
    this.proc = null;
  }
}
