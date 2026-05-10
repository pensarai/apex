import { type ChildProcess, spawn, spawnSync } from "child_process";
import { randomBytes } from "crypto";
import {
  closeSync,
  mkdirSync,
  openSync,
  readFileSync,
  readSync,
  statSync,
  unlinkSync,
} from "fs";
import { tmpdir } from "os";
import { join } from "path";

const MAX_BUFFER = 5_000_000;

// Node-owned per-PID tempfile root. Paths are substituted into the wrapper
// (not `mktemp` inside bash) so kill paths can fs.readFileSync directly —
// Bun's child_process pipe drops bytes written after a descendant signal.
// See #644.
const APEX_TMP_ROOT = join(tmpdir(), `apex-shell-${process.pid}`);
try {
  mkdirSync(APEX_TMP_ROOT, { recursive: true });
} catch {
  // Best-effort; readTempfileCapped surfaces real I/O errors at use time.
}

/**
 * Read up to MAX_BUFFER bytes from `path`. Larger files return the trailing
 * window prefixed with the same truncation sentinel the in-memory path uses,
 * so callers can't tell disk-salvage from pipe-capture truncation. Returns
 * "" on I/O error so callers can substitute their own fallback.
 */
export function readTempfileCapped(path: string): string {
  try {
    const stat = statSync(path);
    if (stat.size === 0) return "";
    if (stat.size <= MAX_BUFFER) {
      return readFileSync(path, "utf-8");
    }
    const fd = openSync(path, "r");
    try {
      const buf = Buffer.alloc(MAX_BUFFER);
      readSync(fd, buf, 0, MAX_BUFFER, stat.size - MAX_BUFFER);
      return "(stdout truncated)...\n" + buf.toString("utf-8");
    } finally {
      closeSync(fd);
    }
  } catch {
    return "";
  }
}

function unlinkSafe(path: string): void {
  try {
    unlinkSync(path);
  } catch {
    // Already gone, race with another process, etc.
  }
}

/** Test-only helper: location of the per-PID tempfile root. */
export function getApexTmpRoot(): string {
  return APEX_TMP_ROOT;
}

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
  // Per-command tempfile paths. Bash `cat`s them on the happy path; kill
  // paths read them from disk before unlink.
  outPath: string;
  errPath: string;
  // Salvage timer from timeout/abort/cancel. On the pending so dispose and
  // cancel can clear it.
  killEscalationTimer?: ReturnType<typeof setTimeout>;
  // Identity token for the active salvage timer — guards against a leaked
  // timer that already dequeued before clearTimeout running its side
  // effects (SIGKILL on stale pids, double-resolve).
  _activeSalvageId?: object;
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
      // If a command was pending, fail it fast rather than letting it wait
      // out its timeout. Prefer disk-read (whatever the user command flushed
      // to the tempfile) over the parsed pipe buffer.
      const cmd = this.current;
      if (cmd) {
        this.current = null;
        this.pendingCancel = null;
        const diskStdout = readTempfileCapped(cmd.outPath);
        const diskStderr = readTempfileCapped(cmd.errPath);
        unlinkSafe(cmd.outPath);
        unlinkSafe(cmd.errPath);
        cmd.resolve({
          stdout: diskStdout || extractFallbackStdout(cmd) || "(no output)",
          stderr: diskStderr || cmd.stderr || "",
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

      // Cleanup is owned by Node now that the wrapper no longer rm's.
      unlinkSafe(cmd.outPath);
      unlinkSafe(cmd.errPath);

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
        let abortCleanup: (() => void) | undefined;

        const nonceHex = randomBytes(8).toString("hex");
        const marker = `__APEX_${nonceHex}__`;
        const exitMarkerPrefix = `${marker}_EXIT_`;
        const cutoverMarker = `${marker}_CUTOVER`;
        const outPath = join(APEX_TMP_ROOT, `${nonceHex}.out`);
        const errPath = join(APEX_TMP_ROOT, `${nonceHex}.err`);

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
          outPath,
          errPath,
          resolve: (result) => {
            if (resolved) return;
            resolved = true;
            if (timeoutTimer) clearTimeout(timeoutTimer);
            if (pending.killEscalationTimer)
              clearTimeout(pending.killEscalationTimer);
            // Invalidate so any in-flight salvage callback that already left
            // the timer queue skips its side effects.
            pending._activeSalvageId = undefined;
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
            pending.killEscalationTimer = scheduleSalvageKill(
              proc.pid,
              pending,
              130,
            );
          };
          abortSignal.addEventListener("abort", onAbort, { once: true });
          abortCleanup = () =>
            abortSignal.removeEventListener("abort", onAbort);
        }

        if (timeoutSeconds != null && timeoutSeconds > 0) {
          timeoutTimer = setTimeout(() => {
            if (resolved) return;
            pending.forcedExitCode = 124;
            pending.killEscalationTimer = scheduleSalvageKill(
              proc.pid,
              pending,
              124,
            );
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
        //   - tempfile paths come from Node, not `mktemp`, so kill paths can
        //     fs.readFileSync them directly. See #644.
        const tailCmd = hasStdbuf()
          ? `stdbuf -oL tail -n +1 -f -s 0.05 "$__APEX_OUT"`
          : `tail -n +1 -f -s 0.05 "$__APEX_OUT"`;
        const shOutPath = `'${outPath.replace(/'/g, `'\\''`)}'`;
        const shErrPath = `'${errPath.replace(/'/g, `'\\''`)}'`;
        const wrapped = [
          `__APEX_OUT=${shOutPath}`,
          `__APEX_ERR=${shErrPath}`,
          // Pre-create so `tail -f` and early-timeout disk reads don't fail.
          `: > "$__APEX_OUT"`,
          `: > "$__APEX_ERR"`,
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
          // Node owns tempfile cleanup so kill paths can read before unlink.
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

  /**
   * Cancel the currently running command without killing the shell.
   * Returns true if a command was running and was cancelled.
   */
  cancelCurrentCommand(): boolean {
    const cmd = this.current;
    if (!cmd || !this.proc) return false;

    cmd.forcedExitCode = 130;
    cmd.forcedStderrSuffix = cmd.stderr
      ? "\n(cancelled by user)"
      : "(cancelled by user)";

    if (this.proc.pid && process.platform !== "win32") {
      cmd.killEscalationTimer = scheduleSalvageKill(this.proc.pid, cmd, 130);
    } else {
      // Windows: no descendant signalling support, but we still own
      // tempfile cleanup.
      unlinkSafe(cmd.outPath);
      unlinkSafe(cmd.errPath);
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

    // Cancel any in-flight salvage-kill so it doesn't read recycled PIDs
    // after we unlink, then sweep the in-flight tempfiles ourselves.
    if (this.current?.killEscalationTimer) {
      clearTimeout(this.current.killEscalationTimer);
    }
    if (this.current) {
      unlinkSafe(this.current.outPath);
      unlinkSafe(this.current.errPath);
    }

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
 * BFS the process tree under `rootPid`, excluding `rootPid` itself. Used
 * instead of `pkill -P` which only hits direct children and leaks pipeline
 * grandchildren.
 */
function enumerateDescendants(rootPid: number | undefined): number[] {
  if (!rootPid || process.platform === "win32") return [];

  const descendants: number[] = [];
  const queue = [rootPid];

  while (queue.length > 0) {
    const pid = queue.shift()!;
    try {
      const res = spawnSync("pgrep", ["-P", String(pid)], { encoding: "utf8" });
      if (res.status === 0 && res.stdout) {
        for (const line of res.stdout.split("\n")) {
          const child = parseInt(line, 10);
          if (Number.isFinite(child) && child > 0) {
            descendants.push(child);
            queue.push(child);
          }
        }
      }
    } catch {
      // pgrep not available
    }
  }

  return descendants;
}

// Leaves first so an intermediate doesn't see a dead child and exit before
// we reach its siblings. Already-dead pids are silently ignored.
function signalPids(pids: number[], signal: NodeJS.Signals): void {
  if (process.platform === "win32") return;
  for (let i = pids.length - 1; i >= 0; i--) {
    try {
      process.kill(pids[i], signal);
    } catch {
      // already dead / permission denied
    }
  }
}

/**
 * Shared kill choreography for timeout/abort/cancel: snapshot descendants,
 * SIGTERM, 200ms grace for stdio flush, disk-read salvage, SIGKILL the
 * snapshot, resolve. Disk-read because Bun's child_process pipe drops bytes
 * written after a descendant signal (#644). PID snapshot is reused so the
 * SIGKILL doesn't hit wrapper helpers (`cat`, `sleep`) bash spawns after
 * SIGTERM — and by then we've already read, so it wouldn't matter anyway.
 */
const SALVAGE_GRACE_MS = 200;

function scheduleSalvageKill(
  rootPid: number | undefined,
  pending: PendingCommand,
  exitCode: number,
): ReturnType<typeof setTimeout> {
  // Two kill paths can fire within the grace window (timeout then cancel);
  // clear any predecessor so its callback can't run stale side effects
  // before the `resolved` guard catches it.
  if (pending.killEscalationTimer) {
    clearTimeout(pending.killEscalationTimer);
  }

  const pids = enumerateDescendants(rootPid);
  signalPids(pids, "SIGTERM");
  const salvageId = {};
  pending._activeSalvageId = salvageId;
  return setTimeout(() => {
    // Skip if a successor timer / dispose has invalidated us.
    if (pending._activeSalvageId !== salvageId) return;

    const diskStdout = readTempfileCapped(pending.outPath);
    const diskStderr = readTempfileCapped(pending.errPath);
    unlinkSafe(pending.outPath);
    unlinkSafe(pending.errPath);

    // Defense-in-depth SIGKILL after we've already read. Bash's wrapper
    // post-cmd helpers (cat, sleep 0.1) may still be running; we don't
    // care about their output anymore.
    signalPids(pids, "SIGKILL");

    pending.resolve({
      stdout: diskStdout || extractFallbackStdout(pending) || "(no output)",
      stderr:
        (diskStderr || pending.stderr || "") +
        (pending.forcedStderrSuffix ?? ""),
      exitCode,
    });
  }, SALVAGE_GRACE_MS);
}
