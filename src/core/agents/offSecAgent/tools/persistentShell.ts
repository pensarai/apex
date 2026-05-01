import { spawn, spawnSync, type ChildProcess } from "child_process";
import { randomBytes } from "crypto";

const MAX_BUFFER = 5_000_000;

export interface ShellExecuteResult {
  stdout: string;
  stderr: string;
  exitCode: number;
}

interface PendingCommand {
  // Raw bytes from `tail -f` of the per-command tempfile. Best-effort live UX
  // only — may be partial/empty on platforms where tail block-buffers.
  streamedStdout: string;
  // Bytes from the post-cutover `cat`, the authoritative capture.
  authoritativeStdout: string;
  cutoverSeen: boolean;
  cutoverMarker: string;
  stderr: string;
  stdoutTruncated: boolean;
  exitMarkerPrefix: string;
  onData?: (chunk: string) => void;
  resolve: (result: ShellExecuteResult) => void;
  // When set, overrides bash's reported exit code with a sentinel
  // (124 timeout, 130 abort) so callers see the documented value.
  forcedExitCode: number | null;
  forcedStderrSuffix: string | null;
}

let stdbufAvailable: boolean | null = null;
function hasStdbuf(): boolean {
  if (stdbufAvailable !== null) return stdbufAvailable;
  if (process.platform === "win32") {
    stdbufAvailable = false;
    return false;
  }
  const res = spawnSync("stdbuf", ["--version"], { stdio: "ignore" });
  stdbufAvailable = res.status === 0;
  return stdbufAvailable;
}

/**
 * Strip cutover/exit markers from a buffer for the timeout/abort/close/cancel
 * fallback paths. The happy-path parser strips inline; if a fallback resolver
 * fires before the parser saw the exit-marker chunk (busy event loop), the raw
 * buffer can still contain markers that would otherwise leak to the agent.
 *
 * Prefers `authoritativeStdout` when populated (already partially stripped);
 * otherwise parses `streamedStdout`. Exported for unit testing.
 */
export function extractFallbackStdout(cmd: {
  authoritativeStdout: string;
  streamedStdout: string;
  cutoverMarker: string;
  exitMarkerPrefix: string;
}): string {
  if (cmd.authoritativeStdout) {
    let s = cmd.authoritativeStdout;
    const exitIdx = s.indexOf(cmd.exitMarkerPrefix);
    if (exitIdx !== -1) {
      s = s.substring(0, exitIdx);
    }
    return s || "(no output)";
  }

  let s = cmd.streamedStdout;

  const cutIdx = s.indexOf(cmd.cutoverMarker);
  if (cutIdx !== -1) {
    s = s.substring(cutIdx + cmd.cutoverMarker.length);
    if (s.startsWith("\n")) s = s.substring(1);
  }

  const exitIdx = s.indexOf(cmd.exitMarkerPrefix);
  if (exitIdx !== -1) {
    s = s.substring(0, exitIdx);
  }

  return s || "(no output)";
}

/**
 * Long-lived bash process. Commands are sent to stdin and bracketed with
 * unique markers so per-command stdout/stderr/exit can be extracted.
 * Background processes (`&`) survive between calls.
 */
export class PersistentShell {
  private proc: ChildProcess | null = null;
  private alive = false;
  private disposed = false;
  private readonly cwd?: string;
  private readonly extraEnv?: Record<string, string>;

  private current: PendingCommand | null = null;
  private pendingCancel: ((result: ShellExecuteResult) => void) | null = null;

  // FIFO mutex tail. Each execute() call snapshots, installs a new tail, and
  // awaits its snapshot — serializing concurrent calls so they can't race on
  // `this.current` and cross-contaminate output.
  private writeChain: Promise<void> = Promise.resolve();

  constructor(opts?: { cwd?: string; env?: Record<string, string> }) {
    this.cwd = opts?.cwd;
    this.extraEnv = opts?.env;
  }

  private spawn(): void {
    if (this.disposed) return;

    const shell = process.platform === "win32" ? "cmd" : "bash";
    const args = process.platform === "win32" ? [] : ["--norc", "--noprofile"];

    this.proc = spawn(shell, args, {
      stdio: ["pipe", "pipe", "pipe"],
      cwd: this.cwd,
      // New session so children have no controlling terminal — keeps
      // interactive prompts off the TUI's TTY.
      detached: process.platform !== "win32",
      env: {
        PATH: process.env.PATH ?? "",
        HOME: process.env.HOME ?? "",
        USER: process.env.USER ?? "",
        LANG: process.env.LANG,
        TMPDIR: process.env.TMPDIR,
        ...this.extraEnv,
        PS1: "",
        CI: "true",
        TERM: "dumb",
        NO_COLOR: "1",
      } as Record<string, string | undefined> as NodeJS.ProcessEnv,
    });

    this.alive = true;

    this.proc.stdout?.on("data", (data: Buffer) => this.onStdoutData(data));
    this.proc.stderr?.on("data", (data: Buffer) => this.onStderrData(data));

    this.proc.on("close", () => {
      this.alive = false;
      this.proc = null;
      const cmd = this.current;
      if (cmd) {
        this.current = null;
        this.pendingCancel = null;
        cmd.resolve({
          stdout: extractFallbackStdout(cmd),
          stderr: cmd.stderr || "",
          exitCode: 1,
        });
      }
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

  private onStdoutData(data: Buffer): void {
    const cmd = this.current;
    if (!cmd) return;

    let chunk = data.toString();

    if (!cmd.cutoverSeen) {
      // Search the accumulated buffer so a marker straddling two chunks is found.
      const prevLen = cmd.streamedStdout.length;
      cmd.streamedStdout += chunk;
      const cutIdx = cmd.streamedStdout.indexOf(cmd.cutoverMarker);

      if (cutIdx === -1) {
        if (chunk.length > 0 && cmd.onData) cmd.onData(chunk);
        if (cmd.streamedStdout.length > MAX_BUFFER) {
          cmd.streamedStdout = cmd.streamedStdout.substring(
            cmd.streamedStdout.length - MAX_BUFFER,
          );
        }
        return;
      }

      // Only feed pre-cutover bytes from THIS chunk to onData; earlier chunks
      // already delivered their pre-cutover portion.
      const chunkCutOffset = cutIdx - prevLen;
      if (chunkCutOffset > 0 && cmd.onData) {
        cmd.onData(chunk.substring(0, chunkCutOffset));
      }

      const postMarker = cmd.streamedStdout.substring(
        cutIdx + cmd.cutoverMarker.length,
      );
      cmd.cutoverSeen = true;
      cmd.streamedStdout = "";
      chunk = postMarker.startsWith("\n")
        ? postMarker.substring(1)
        : postMarker;
      if (chunk.length === 0) return;
    }

    cmd.authoritativeStdout += chunk;

    const markerIdx = cmd.authoritativeStdout.indexOf(cmd.exitMarkerPrefix);
    if (markerIdx !== -1) {
      const afterPrefix = cmd.authoritativeStdout.substring(
        markerIdx + cmd.exitMarkerPrefix.length,
      );
      const nlIdx = afterPrefix.indexOf("\n");
      const exitStr =
        nlIdx >= 0 ? afterPrefix.substring(0, nlIdx) : afterPrefix;
      const naturalExitCode = parseInt(exitStr, 10);

      let commandOutput = cmd.authoritativeStdout.substring(0, markerIdx);
      if (cmd.stdoutTruncated) {
        commandOutput = "(stdout truncated)...\n" + commandOutput;
      }

      const effectiveExit =
        cmd.forcedExitCode != null
          ? cmd.forcedExitCode
          : isNaN(naturalExitCode)
            ? 1
            : naturalExitCode;
      const effectiveStderr = cmd.forcedStderrSuffix
        ? (cmd.stderr || "") + cmd.forcedStderrSuffix
        : cmd.stderr || "";

      const resolve = cmd.resolve;
      this.current = null;
      this.pendingCancel = null;
      resolve({
        stdout: commandOutput || "(no output)",
        stderr: effectiveStderr,
        exitCode: effectiveExit,
      });
      return;
    }

    if (cmd.authoritativeStdout.length > MAX_BUFFER) {
      cmd.authoritativeStdout = cmd.authoritativeStdout.substring(
        cmd.authoritativeStdout.length - MAX_BUFFER,
      );
      cmd.stdoutTruncated = true;
    }
  }

  private onStderrData(data: Buffer): void {
    const cmd = this.current;
    if (!cmd) return;

    cmd.stderr += data.toString();
    if (cmd.stderr.length > MAX_BUFFER) {
      cmd.stderr =
        cmd.stderr.substring(0, MAX_BUFFER) + "...\n(stderr truncated)";
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
      return { stdout: "", stderr: "Command aborted", exitCode: 130 };
    }

    const release = await this.acquireTurn();
    try {
      // Re-validate after the queue wait — disposal/abort may have happened
      // while we were queued.
      if (this.disposed) {
        return { stdout: "", stderr: "Shell has been disposed", exitCode: 1 };
      }
      if (abortSignal?.aborted) {
        return { stdout: "", stderr: "Command aborted", exitCode: 130 };
      }

      this.ensureAlive();

      const proc = this.proc;
      if (!proc || !proc.stdin || !proc.stdout || !proc.stderr) {
        return { stdout: "", stderr: "Failed to spawn shell", exitCode: 1 };
      }

      return await new Promise<ShellExecuteResult>((resolve) => {
        let resolved = false;
        let timeoutTimer: ReturnType<typeof setTimeout> | undefined;
        let killEscalationTimer: ReturnType<typeof setTimeout> | undefined;
        let abortCleanup: (() => void) | undefined;

        const marker = `__APEX_${randomBytes(8).toString("hex")}__`;
        const exitMarkerPrefix = `${marker}_EXIT_`;
        const cutoverMarker = `${marker}_CUTOVER`;

        const pending: PendingCommand = {
          streamedStdout: "",
          authoritativeStdout: "",
          cutoverSeen: false,
          cutoverMarker,
          stderr: "",
          stdoutTruncated: false,
          exitMarkerPrefix,
          onData,
          forcedExitCode: null,
          forcedStderrSuffix: null,
          resolve: (result) => {
            if (resolved) return;
            resolved = true;
            if (timeoutTimer) clearTimeout(timeoutTimer);
            if (killEscalationTimer) clearTimeout(killEscalationTimer);
            if (abortCleanup) abortCleanup();
            resolve(result);
          },
        };

        this.current = pending;
        this.pendingCancel = pending.resolve;

        if (abortSignal) {
          const onAbort = () => {
            if (resolved) return;
            pending.forcedExitCode = 130;
            pending.forcedStderrSuffix = pending.stderr
              ? "\n(aborted)"
              : "(aborted)";
            killDescendants(proc.pid, "SIGTERM");
            killEscalationTimer = setTimeout(() => {
              if (resolved) return;
              killDescendants(proc.pid, "SIGKILL");
              setTimeout(() => {
                if (resolved) return;
                pending.resolve({
                  stdout: extractFallbackStdout(pending),
                  stderr:
                    (pending.stderr || "") + (pending.forcedStderrSuffix ?? ""),
                  exitCode: 130,
                });
              }, 2_000);
            }, 500);
          };
          abortSignal.addEventListener("abort", onAbort, { once: true });
          abortCleanup = () =>
            abortSignal.removeEventListener("abort", onAbort);
        }

        if (timeoutSeconds != null && timeoutSeconds > 0) {
          timeoutTimer = setTimeout(() => {
            if (resolved) return;
            pending.forcedExitCode = 124;
            killDescendants(proc.pid, "SIGTERM");
            killEscalationTimer = setTimeout(() => {
              if (resolved) return;
              killDescendants(proc.pid, "SIGKILL");
              setTimeout(() => {
                if (resolved) return;
                pending.resolve({
                  stdout: extractFallbackStdout(pending),
                  stderr: pending.stderr || "",
                  exitCode: 124,
                });
              }, 2_000);
            }, 500);
          }, timeoutSeconds * 1_000);
        }

        // Wrap command:
        //   - brace group `{ ...; }` (NOT a subshell) so cd/export/aliases persist;
        //   - stdin from /dev/null so children can't hijack our command pipe;
        //   - stdout/stderr to per-command tempfiles, streamed live via `tail -f`;
        //   - after the command, kill tail, emit a cutover marker on bash's real
        //     stdout, then `cat` the tempfile. Post-cutover bytes are
        //     authoritative — they bypass tail's libc block-buffering, which is
        //     a no-op `stdbuf` can't fix on macOS/SIP, Alpine, etc.
        const tailCmd = hasStdbuf()
          ? `stdbuf -oL tail -n +1 -f -s 0.05 "$__APEX_OUT"`
          : `tail -n +1 -f -s 0.05 "$__APEX_OUT"`;
        const wrapped = [
          `__APEX_OUT=$(mktemp 2>/dev/null || echo /tmp/.apex_out_$$)`,
          `__APEX_ERR=$(mktemp 2>/dev/null || echo /tmp/.apex_err_$$)`,
          `${tailCmd} 2>/dev/null &`,
          `__APEX_TAIL=$!`,
          `{ ${command}\n} </dev/null >"$__APEX_OUT" 2>"$__APEX_ERR"`,
          `__APEX_EC=$?`,
          `sleep 0.1`,
          `kill "$__APEX_TAIL" 2>/dev/null`,
          `wait "$__APEX_TAIL" 2>/dev/null`,
          `printf '%s\\n' "${cutoverMarker}"`,
          `cat "$__APEX_OUT"`,
          `cat "$__APEX_ERR" >&2`,
          `rm -f "$__APEX_OUT" "$__APEX_ERR"`,
          `echo "${exitMarkerPrefix}$__APEX_EC"`,
          ``,
        ].join("\n");

        try {
          proc.stdin!.write(wrapped);
        } catch {
          pending.resolve({
            stdout: "",
            stderr: "Failed to write to shell stdin",
            exitCode: 1,
          });
        }
      });
    } catch (e) {
      return {
        stdout: "",
        stderr: e instanceof Error ? e.message : String(e),
        exitCode: 1,
      };
    } finally {
      release();
    }
  }

  private async acquireTurn(): Promise<() => void> {
    const myTurn = this.writeChain;
    let release!: () => void;
    this.writeChain = new Promise<void>((res) => {
      release = res;
    });
    await myTurn;
    return release;
  }

  cancelCurrentCommand(): boolean {
    const cmd = this.current;
    if (!cmd || !this.proc) return false;

    cmd.forcedExitCode = 130;
    cmd.forcedStderrSuffix = cmd.stderr
      ? "\n(cancelled by user)"
      : "(cancelled by user)";

    if (this.proc.pid && process.platform !== "win32") {
      killDescendants(this.proc.pid, "SIGTERM");
      setTimeout(() => {
        if (this.proc?.pid) killDescendants(this.proc.pid, "SIGKILL");
        setTimeout(() => {
          cmd.resolve({
            stdout: extractFallbackStdout(cmd),
            stderr: (cmd.stderr || "") + (cmd.forcedStderrSuffix ?? ""),
            exitCode: 130,
          });
        }, 2_000);
      }, 500);
    } else {
      cmd.resolve({
        stdout: extractFallbackStdout(cmd),
        stderr: (cmd.stderr || "") + (cmd.forcedStderrSuffix ?? ""),
        exitCode: 130,
      });
    }

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
        // Kill the whole process group so detached children die too.
        if (pid && process.platform !== "win32") {
          try {
            process.kill(-pid, "SIGTERM");
          } catch {
            // already gone
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
              // already gone
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

/**
 * Walk the process tree under `rootPid` and signal every descendant
 * (deepest first). Does NOT signal `rootPid` — that's the persistent shell.
 * Used instead of `pkill -P` which only hits direct children and leaks
 * pipeline grandchildren.
 */
function killDescendants(
  rootPid: number | undefined,
  signal: NodeJS.Signals,
): void {
  if (!rootPid || process.platform === "win32") return;

  const toKill: number[] = [];
  const queue = [rootPid];

  while (queue.length > 0) {
    const pid = queue.shift()!;
    try {
      const res = spawnSync("pgrep", ["-P", String(pid)], { encoding: "utf8" });
      if (res.status === 0 && res.stdout) {
        for (const line of res.stdout.split("\n")) {
          const child = parseInt(line, 10);
          if (Number.isFinite(child) && child > 0) {
            toKill.push(child);
            queue.push(child);
          }
        }
      }
    } catch {
      // pgrep not available
    }
  }

  // Leaves first so intermediates don't exit before we reach their siblings.
  for (let i = toKill.length - 1; i >= 0; i--) {
    try {
      process.kill(toKill[i], signal);
    } catch {
      // already dead / permission denied
    }
  }
}
