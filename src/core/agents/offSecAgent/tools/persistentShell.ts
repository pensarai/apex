import { type ChildProcess, spawn, spawnSync } from "node:child_process";
import { randomBytes } from "node:crypto";
import {
  closeSync,
  mkdirSync,
  openSync,
  readFileSync,
  readSync,
  statSync,
  unlinkSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const MAX_BUFFER = 5_000_000;

// Appended to a timed-out command's stderr when the persistent bash itself had
// to be killed and respawned — the caller must re-establish shell context.
const SHELL_RESTART_STDERR_NOTE =
  "(persistent shell restarted: cwd/env/aliases reset — re-establish context)";

// Bounded wait for the killed shell's exit acknowledgement before releasing
// the caller; without it the shell is disabled rather than replaced.
const SHELL_EXIT_ACK_MS = 250;

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
      return `(stdout truncated)...\n${buf.toString("utf-8")}`;
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
  // Mirror of the stdout cutover fence for stderr. A command's real stderr is
  // `cat`'d to bash's stderr only after this marker is emitted on fd2; anything
  // before it is bash's own job-control noise (e.g. "Terminated"/"Killed" from
  // a prior killed sibling) and must not leak into this command's stderr.
  stderrCutoverSeen: boolean;
  stderrPreCutover: string;
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
  // Set by resolve(). The salvage timer reads it to tell "wrapper completed"
  // (kill only stragglers) from "wrapper never advanced" (the shell itself is
  // wedged executing the command).
  settled: boolean;
}

/**
 * Workspace-configured agent environment variables, transported into the
 * sandbox as a single JSON blob (`PENSAR_AGENT_ENV_VARS`) by the platform's
 * dispatch layer. They are merged into every shell's environment so the
 * agent's `execute_command` calls see them — the curated env below
 * deliberately does NOT inherit arbitrary `process.env`, so platform secrets
 * (AGENT_API_TOKEN, AWS creds, …) never leak into the agent's shell, but that
 * also means these workspace vars must be re-introduced explicitly here.
 *
 * Fail-soft: a missing or malformed blob yields no extra vars rather than
 * throwing — a parse failure must not break command execution.
 */
export function readSandboxAgentEnv(): Record<string, string> {
  const raw = process.env.PENSAR_AGENT_ENV_VARS;
  if (!raw) return {};
  try {
    const parsed: unknown = JSON.parse(raw);
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
      return {};
    }
    const out: Record<string, string> = {};
    for (const [k, v] of Object.entries(parsed as Record<string, unknown>)) {
      if (typeof v === "string") out[k] = v;
    }
    return out;
  } catch {
    return {};
  }
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

// GNU tail's `-s` sets the follow poll interval (50ms); BSD tail rejects it
// and would die instantly — a dead monitor silently kills both live
// streaming and the bare-`wait` regression, so gate the flag on support.
let tailSleepAvailable: boolean | null = null;
function hasTailSleep(): boolean {
  if (tailSleepAvailable !== null) return tailSleepAvailable;
  if (process.platform === "win32") {
    tailSleepAvailable = false;
    return false;
  }
  // Without -f the command terminates, so this is a safe usage probe.
  const res = spawnSync("tail", ["-s", "0.05", "/dev/null"], {
    stdio: "ignore",
  });
  tailSleepAvailable = res.status === 0;
  return tailSleepAvailable;
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
        // Workspace-configured agent env vars first (lowest precedence) so the
        // curated essentials below and explicit per-agent `extraEnv` always
        // win — a workspace var can never clobber PATH/HOME or shell controls.
        ...readSandboxAgentEnv(),
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

    const child = this.proc;

    // A killed shell's pipes can flush late; stale bytes must not land in the
    // replacement's pending command.
    child.stdout?.on("data", (data: Buffer) => {
      if (this.proc !== child) return;
      this.onStdoutData(data);
    });
    child.stderr?.on("data", (data: Buffer) => {
      if (this.proc !== child) return;
      this.onStderrData(data);
    });

    // Identity-guarded: a wedged shell's close can land AFTER its replacement
    // spawned and must not clobber the replacement's state or pending command.
    this.proc.on("close", () => {
      if (this.proc !== child) return;
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
      if (this.proc !== child) return;
      // Only mark dead — the close event always follows error and owns the
      // pending rescue; nulling this.proc here would make close's identity
      // guard skip it and strand the command.
      this.alive = false;
    });
  }

  /**
   * Kill the persistent bash itself (wrapper never advanced: the bash, not a
   * descendant, is executing the command) and report the state loss on the
   * pending stderr. Holds the pending until the killed child's exit is
   * observed (bounded) so the FIFO releases only after the old root is dead;
   * without acknowledgement the shell is disabled rather than replaced.
   */
  private killStuckShell(
    pending: PendingCommand,
    salvage: { stdout: string; stderr: string; exitCode: number },
  ): void {
    pending.forcedStderrSuffix = pending.forcedStderrSuffix
      ? `${pending.forcedStderrSuffix}\n${SHELL_RESTART_STDERR_NOTE}`
      : SHELL_RESTART_STDERR_NOTE;

    const child = this.proc;
    this.current = null;
    this.pendingCancel = null;
    this.alive = false;
    this.proc = null;

    const finish = () => {
      // The wrapper will never run its epilogue cat — own the unlink here
      // (the salvage handoff deliberately left the files for a draining
      // epilogue).
      unlinkSafe(pending.outPath);
      unlinkSafe(pending.errPath);
      pending.resolve({
        stdout:
          salvage.stdout || extractFallbackStdout(pending) || "(no output)",
        stderr:
          (salvage.stderr || pending.stderr || "") +
          (pending.forcedStderrSuffix ?? ""),
        exitCode: salvage.exitCode,
      });
    };

    if (!child) {
      finish();
      return;
    }

    let acknowledged = false;
    const acknowledge = () => {
      if (acknowledged) return;
      acknowledged = true;
      clearTimeout(ackTimer);
      finish();
    };
    // SIGKILL submission is not exit acknowledgement — kill(pid, 0) answers
    // for zombies too — so wait for the reaper before releasing the caller.
    const ackTimer = setTimeout(() => {
      if (acknowledged) return;
      // No exit within the grace: never respawn over an unacknowledged kill.
      this.disposed = true;
      finish();
    }, SHELL_EXIT_ACK_MS);

    child.once("exit", acknowledge);
    child.once("close", acknowledge);

    const pid = child.pid;
    if (pid && process.platform !== "win32") {
      // Group signal reaches the wedged root plus anything pgrep missed;
      // SIGKILL cannot be trapped.
      try {
        process.kill(-pid, "SIGTERM");
      } catch {
        // already gone
      }
      try {
        process.kill(-pid, "SIGKILL");
      } catch {
        // already gone
      }
    } else {
      try {
        child.kill("SIGTERM");
      } catch {
        // already gone
      }
      try {
        child.kill("SIGKILL");
      } catch {
        // already gone
      }
    }
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
        commandOutput = `(stdout truncated)...\n${commandOutput}`;
      }

      const effectiveExit =
        cmd.forcedExitCode != null
          ? cmd.forcedExitCode
          : Number.isNaN(naturalExitCode)
            ? 1
            : naturalExitCode;
      // stdout and stderr are separate pipes with no delivery ordering between
      // them, so the exit marker on fd1 can arrive before the command's stderr
      // on fd2 and resolve the call with an empty stderr. The tempfile is
      // closed before the exit code is captured, so read it instead of racing
      // the pipe — every other resolve path already prefers the disk read.
      const diskStderr = readTempfileCapped(cmd.errPath);

      // Cleanup is owned by Node now that the wrapper no longer rm's.
      unlinkSafe(cmd.outPath);
      unlinkSafe(cmd.errPath);

      const effectiveStderr =
        (diskStderr || cmd.stderr || "") + (cmd.forcedStderrSuffix ?? "");

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

    let chunk = data.toString();

    if (!cmd.stderrCutoverSeen) {
      // Discard everything up to and including this command's stderr cutover
      // marker. The command's own stderr is `cat`'d only after the marker, so
      // pre-marker bytes are bash diagnostics (job-control kill messages) that
      // would otherwise be misattributed to this command.
      cmd.stderrPreCutover += chunk;
      const cutIdx = cmd.stderrPreCutover.indexOf(cmd.cutoverMarker);
      if (cutIdx === -1) {
        // Keep only a marker-length tail so a marker straddling chunks is still
        // found; bounded so unexpected pre-cutover output can't grow unbounded.
        if (cmd.stderrPreCutover.length > cmd.cutoverMarker.length) {
          cmd.stderrPreCutover = cmd.stderrPreCutover.substring(
            cmd.stderrPreCutover.length - cmd.cutoverMarker.length,
          );
        }
        return;
      }
      const postMarker = cmd.stderrPreCutover.substring(
        cutIdx + cmd.cutoverMarker.length,
      );
      cmd.stderrCutoverSeen = true;
      cmd.stderrPreCutover = "";
      chunk = postMarker.startsWith("\n")
        ? postMarker.substring(1)
        : postMarker;
      if (chunk.length === 0) return;
    }

    cmd.stderr += chunk;
    if (cmd.stderr.length > MAX_BUFFER) {
      cmd.stderr = `${cmd.stderr.substring(0, MAX_BUFFER)}...\n(stderr truncated)`;
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
      if (!proc?.stdin || !proc.stdout || !proc.stderr) {
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
          stderrCutoverSeen: false,
          stderrPreCutover: "",
          stdoutTruncated: false,
          exitMarkerPrefix,
          onData,
          forcedExitCode: null,
          forcedStderrSuffix: null,
          outPath,
          errPath,
          settled: false,
          resolve: (result) => {
            if (resolved) return;
            resolved = true;
            pending.settled = true;
            if (timeoutTimer) clearTimeout(timeoutTimer);
            // killEscalationTimer is deliberately NOT cleared: the wrapper can
            // complete after a partial kill while a signal-ignoring grandchild
            // survives — the scheduled SIGKILL must still fire.
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
              (salvage) => this.killStuckShell(pending, salvage),
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
              (salvage) => this.killStuckShell(pending, salvage),
            );
          }, timeoutSeconds * 1_000);
        }

        // Wrap command:
        //   - brace group `{ ...; }` (NOT a subshell) so cd/export/aliases persist;
        //   - stdin from /dev/null so children can't hijack our command pipe;
        //   - stdout/stderr to per-command tempfiles, streamed live via `tail -f`;
        //   - the monitor is disowned so a user `wait` (bare) can't see it —
        //     it runs forever, so a job-table wait would deadlock the command
        //     until the tool timeout;
        //   - after the command, TERM+KILL tail, emit a cutover marker on
        //     bash's real stdout, then `cat` the tempfile. Post-cutover bytes
        //     are authoritative — they bypass tail's libc block-buffering,
        //     which is a no-op `stdbuf` can't fix on macOS/SIP, Alpine, etc.
        //   - tempfile paths come from Node, not `mktemp`, so kill paths can
        //     fs.readFileSync them directly. See #644.
        const tailCmd = `${hasStdbuf() ? "stdbuf -oL " : ""}tail -n +1 -f${
          hasTailSleep() ? " -s 0.05" : ""
        } "$__APEX_OUT"`;
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
          // Disown the monitor: bare `wait` waits for all jobs and the
          // monitor never ends. Disowned children are still reaped by bash
          // and still killable by pid (epilogue) and by the salvage paths'
          // descendant walk.
          `disown "$__APEX_TAIL" 2>/dev/null`,
          `{ ${command}\n} </dev/null >"$__APEX_OUT" 2>"$__APEX_ERR"`,
          `__APEX_EC=$?`,
          `sleep 0.1`,
          `kill "$__APEX_TAIL" 2>/dev/null`,
          `kill -9 "$__APEX_TAIL" 2>/dev/null`,
          // Kill submission is not termination acknowledgement: poll until
          // the reaper collects the monitor before the cutover write, or a
          // late monitor write would corrupt the authoritative capture.
          `for __APEX_I in {1..50}; do kill -0 "$__APEX_TAIL" 2>/dev/null || break; sleep 0.01; done`,
          `if kill -0 "$__APEX_TAIL" 2>/dev/null; then`,
          // Monitor death unconfirmed: emit nothing authoritative — the
          // caller's deadline salvage owns the bounded teardown and salvage.
          `  echo "monitor drain unconfirmed; deferring to caller deadline" >> "$__APEX_ERR"`,
          `else`,
          `  printf '%s\\n' "${cutoverMarker}"`,
          `  cat "$__APEX_OUT"`,
          // Stderr cutover fence: marks the boundary between bash's own
          // diagnostics (job-control kill messages from a killed sibling) and
          // this command's real stderr, so the former can't leak into it.
          `  printf '%s\\n' "${cutoverMarker}" >&2`,
          `  cat "$__APEX_ERR" >&2`,
          // Node owns tempfile cleanup so kill paths can read before unlink.
          `  echo "${exitMarkerPrefix}$__APEX_EC"`,
          `fi`,
          ``,
        ].join("\n");

        try {
          proc.stdin?.write(wrapped);
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
      cmd.killEscalationTimer = scheduleSalvageKill(
        this.proc.pid,
        cmd,
        130,
        (salvage) => this.killStuckShell(cmd, salvage),
      );
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

    // Take ownership of the in-flight command BEFORE clearing shell state:
    // after this.proc is null the close guard rejects the killed child's
    // events, so an unresolved pending would strand its caller and the queue.
    const cmd = this.current;
    const child = this.proc;
    this.current = null;
    this.pendingCancel = null;
    this.alive = false;
    this.proc = null;

    if (cmd) {
      // Cancel any in-flight salvage-kill so it doesn't read recycled PIDs
      // after we unlink, then sweep the tempfiles ourselves.
      if (cmd.killEscalationTimer) {
        clearTimeout(cmd.killEscalationTimer);
      }
      const diskStdout = readTempfileCapped(cmd.outPath);
      const diskStderr = readTempfileCapped(cmd.errPath);
      unlinkSafe(cmd.outPath);
      unlinkSafe(cmd.errPath);
      cmd.resolve({
        stdout: diskStdout || extractFallbackStdout(cmd) || "(no output)",
        stderr:
          (diskStderr || cmd.stderr || "") + (cmd.forcedStderrSuffix ?? ""),
        exitCode: cmd.forcedExitCode ?? 1,
      });
    }

    if (child) {
      const pid = child.pid;

      // Kill the process group synchronously so backgrounded subshells
      // die even if the runner process is killed before timers fire.
      if (pid && process.platform !== "win32") {
        try {
          process.kill(-pid, "SIGTERM");
        } catch {
          // already gone
        }
      }
      try {
        child.kill("SIGTERM");
      } catch {
        // already dead
      }

      // SIGKILL escalation on a timer — only needed if SIGTERM is ignored.
      setTimeout(() => {
        if (pid && process.platform !== "win32") {
          try {
            process.kill(-pid, "SIGKILL");
          } catch {
            // already gone
          }
        }
        try {
          child.kill("SIGKILL");
        } catch {
          // already dead
        }
      }, 2_000);
    }
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
 *
 * `onUnrecovered` fires when the wrapper never advanced: the bash itself is
 * executing the command (a pure-builtin loop has no descendant to signal).
 * It receives the salvaged result and takes ownership of resolving the
 * pending.
 */
const SALVAGE_GRACE_MS = 200;

// Second grace before concluding the bash itself is wedged: the wrapper's
// epilogue forks `sleep`, `kill`, `cat` and can lag past the first grace on
// slow machines without the shell actually being stuck — a false "wedged"
// verdict would needlessly restart the shell and lose cd/env state.
const WEDGED_DETERMINATION_MS = 500;

function scheduleSalvageKill(
  rootPid: number | undefined,
  pending: PendingCommand,
  exitCode: number,
  onUnrecovered?: (salvage: {
    stdout: string;
    stderr: string;
    exitCode: number;
  }) => void,
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

    // Read WITHOUT unlinking: if the wrapper is still draining its epilogue,
    // its `cat` needs these files. Unlink ownership stays with the parser
    // (settled path — it already unlinks) or the wedged path (killStuckShell).
    const diskStdout = readTempfileCapped(pending.outPath);
    const diskStderr = readTempfileCapped(pending.errPath);

    // Defense-in-depth SIGKILL after we've already read. Bash's wrapper
    // post-cmd helpers (cat, sleep 0.1) may still be running; we don't
    // care about their output anymore.
    signalPids(pids, "SIGKILL");

    if (!pending.settled) {
      // The wrapper may still be finishing after the descendant kills (its
      // epilogue forks `sleep`, `kill`, `cat`), so only conclude the bash
      // itself is wedged after a second grace — a false verdict needlessly
      // restarts the shell and loses cd/env state. The wedged handoff
      // resolves the pending only after the killed child's exit is observed.
      pending.killEscalationTimer = setTimeout(() => {
        if (pending._activeSalvageId !== salvageId) return;
        if (!pending.settled) {
          onUnrecovered?.({
            stdout: diskStdout,
            stderr: diskStderr,
            exitCode,
          });
        }
      }, WEDGED_DETERMINATION_MS);
      return;
    }

    unlinkSafe(pending.outPath);
    unlinkSafe(pending.errPath);
    pending.resolve({
      stdout: diskStdout || extractFallbackStdout(pending) || "(no output)",
      stderr:
        (diskStderr || pending.stderr || "") +
        (pending.forcedStderrSuffix ?? ""),
      exitCode,
    });
  }, SALVAGE_GRACE_MS);
}
