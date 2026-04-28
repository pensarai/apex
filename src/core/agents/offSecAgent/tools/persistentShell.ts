import { spawn, spawnSync, type ChildProcess } from "child_process";
import { randomBytes } from "crypto";

/** Hard memory safety cap — prevents OOM on pathological output (5 MB). */
const MAX_BUFFER = 5_000_000;

export interface ShellExecuteResult {
  stdout: string;
  stderr: string;
  exitCode: number;
}

interface PendingCommand {
  /**
   * Bytes observed on bash's stdout pipe BEFORE the cutover marker. These
   * come from the background `tail -f` of the per-command tempfile and
   * are best-effort live UX only — on platforms where `tail`'s pipe
   * block-buffers (macOS under SIP even with `stdbuf`), this buffer may
   * be partial or empty. Used for `onData` streaming and as a fallback
   * if the command is killed before the authoritative phase starts.
   */
  streamedStdout: string;
  /**
   * Bytes observed AFTER the cutover marker. Emitted by `cat "$OUT"`
   * through bash's real stdout pipe with no tail/libc intermediary, so
   * this is the authoritative capture of the user command's stdout.
   */
  authoritativeStdout: string;
  /** True once we've seen the per-command cutover marker on the pipe. */
  cutoverSeen: boolean;
  /** The cutover marker string for this command (per-command random). */
  cutoverMarker: string;
  stderr: string;
  stdoutTruncated: boolean;
  exitMarkerPrefix: string;
  onData?: (chunk: string) => void;
  resolve: (result: ShellExecuteResult) => void;
  /**
   * When non-null, overrides whatever exit code bash reports via the
   * marker. Set by the timeout / abort paths so the caller always sees
   * the documented sentinel (124 for timeout, 130 for abort) even when
   * bash's wrapper ran to completion after our kill.
   */
  forcedExitCode: number | null;
  /** Extra stderr appended by abort/timeout paths. */
  forcedStderrSuffix: string | null;
}

/**
 * A long-lived bash process that persists across execute_command calls.
 *
 * Commands are sent to stdin and delimited with unique markers so the
 * caller can extract per-command stdout, stderr, and the exit code.
 * Background processes (`&`) survive between calls because the parent
 * shell never exits.
 *
 * Stability design notes:
 *
 *  - User commands are wrapped in a brace group `{ ...; }` (NOT a subshell)
 *    so that `cd`, `export`, shell functions, and aliases persist across
 *    calls as advertised.
 *  - The user command block has its stdin redirected from `/dev/null` so
 *    that children that read stdin (cat/ssh/sudo/python/mysql/read/…)
 *    cannot hijack the shared pipe that we use to send commands to bash.
 *  - A single persistent `data` listener is attached to the shell's
 *    stdout/stderr at spawn time. Between commands, incoming bytes (e.g.
 *    from backgrounded processes whose fd1 was not redirected) are
 *    actively drained into a discard buffer so the kernel pipe buffer
 *    never fills and blocks the shell.
 *  - On timeout / cancel we walk the process tree under the shell and
 *    SIGTERM → SIGKILL every descendant (not just direct children), so
 *    pipelines and grandchildren cannot be orphaned holding our pipe.
 */
/**
 * Cached once: whether `stdbuf` is available. We use it to line-buffer
 * `tail -f` so command output streams to the caller in near-real-time
 * on platforms where it's effective (Linux glibc).
 *
 * Final stdout correctness does NOT depend on `stdbuf` — the wrapper
 * always emits a post-kill authoritative `cat` of the per-command
 * output tempfile through bash's real stdout pipe, so even when
 * `tail -f` block-buffers (macOS under SIP, Alpine, minimal containers)
 * and its buffer is discarded when we kill it, the caller still gets
 * the full output. `stdbuf` only affects live streaming UX quality.
 */
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
 * Produce a clean stdout string for the timeout / abort / close / cancel
 * fallback resolvers.
 *
 * The happy-path handler (`onStdoutData`) parses the cutover and exit
 * markers as they arrive and only commits stripped bytes to
 * `authoritativeStdout`. When a fallback resolver fires first — because
 * the Node event loop was busy processing AI SDK streams / telemetry /
 * other tool calls while the shell's output was queued on the pipe, so
 * a timeout/abort timer got to run before `onStdoutData` processed the
 * chunk containing the exit marker — the candidate stdout is
 * `streamedStdout`, which is the raw bash pipe accumulator and may still
 * contain the per-command markers verbatim.
 *
 * Observed before this helper (NOCTURNE traces): commands that had in
 * fact completed successfully had their stdout leak as e.g.
 *   `__APEX_7e680629f7b4a78b__CUTOVER\n/debug -> HTTP 404\n...\n__APEX_7e680629f7b4a78b__EXIT_0\n`
 * to the agent as tool output, which the model interpreted as literal
 * strings in the target application's response.
 *
 * This function performs the same stripping the happy-path parser does,
 * so all four fallback paths produce the same shape of stdout a normal
 * completion would.
 *
 * Prefers `authoritativeStdout` when populated (happy path partially
 * ran) since those bytes are already stripped; otherwise parses the raw
 * `streamedStdout`. Exported for direct unit testing — the real-world
 * trigger requires a busy event loop which is hard to force in a
 * deterministic integration test.
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

export class PersistentShell {
  private proc: ChildProcess | null = null;
  private alive = false;
  private disposed = false;
  private readonly cwd?: string;
  private readonly extraEnv?: Record<string, string>;

  /** Single pending command; null between `execute()` calls. */
  private current: PendingCommand | null = null;

  /** Allows cancelCurrentCommand() to force-resolve the running execute(). */
  private pendingCancel: ((result: ShellExecuteResult) => void) | null = null;

  /**
   * FIFO queue for `execute()` calls. Each call awaits the previous tail of
   * the chain before assigning `this.current`, so concurrent calls in the
   * same JS tick can no longer race on a shared pending pointer and
   * cross-contaminate stdout/stderr.
   *
   * Without this, two `execute()` calls in the same microtask both reach
   * `this.current = pending` synchronously — last writer wins — and bash's
   * stdout/stderr handlers (which read `this.current` per chunk) pin both
   * wrappers' bytes onto the second pending. The first pending returns
   * `(no output)`; the second leaks the first's wrapper markers and bash
   * job-control stderr (e.g. SIGTERM messages for processes it didn't
   * spawn). See issue #645 for the full forensic trace.
   */
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
      // New session so child has no controlling terminal — prevents
      // interactive programs from writing prompts to the TUI's TTY.
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
      // If a command was pending, fail it fast rather than letting it
      // wait out its timeout.
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

  /**
   * Single persistent stdout handler. Between commands (`current === null`)
   * incoming bytes are silently dropped so background-process output does
   * not fill the kernel pipe buffer and does not bleed into the next
   * command's captured output.
   *
   * Each wrapped command emits, in order on bash's stdout pipe:
   *   1. Best-effort live bytes from the background `tail -f` (may be
   *      empty if the platform's tail block-buffers).
   *   2. A per-command cutover marker emitted by `printf` after tail is
   *      killed.
   *   3. Authoritative bytes from `cat "$OUT"` through bash's own pipe
   *      (no tail, no libc buffering) — this is the source of truth for
   *      `result.stdout`.
   *   4. The exit marker.
   *
   * We split the incoming stream at the cutover marker:
   *   - Pre-cutover → fed to `onData` for live UX, buffered in
   *     `streamedStdout` as a fallback for kill-before-cutover paths.
   *   - Post-cutover → accumulated in `authoritativeStdout`; exit-marker
   *     detection runs on this buffer, so user command output cannot
   *     accidentally match the exit marker before the authoritative
   *     phase has been bracketed.
   */
  private onStdoutData(data: Buffer): void {
    const cmd = this.current;
    if (!cmd) return;

    let chunk = data.toString();

    if (!cmd.cutoverSeen) {
      // Search the accumulated buffer, not just the new chunk, so a
      // cutover marker that straddles two Buffer reads is still found.
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

      // Feed only the pre-cutover bytes from THIS chunk to onData so we
      // don't re-emit bytes that earlier chunks already delivered.
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
      return {
        stdout: "",
        stderr: "Command aborted",
        exitCode: 130,
      };
    }

    // Take a turn in the FIFO queue. Concurrent calls in the same JS tick
    // would otherwise both reach `this.current = pending` synchronously
    // and cross-contaminate stdout/stderr (issue #645). Each call snapshots
    // the current chain tail, installs a new tail, and waits for the
    // previous tail to resolve. `releaseTurn` is called from
    // `pending.resolve` (wrapped below) so every completion path — happy,
    // timeout, abort, close, cancel, write-error — frees the next caller.
    const myTurn = this.writeChain;
    let releaseTurn!: () => void;
    let turnReleased = false;
    this.writeChain = new Promise<void>((res) => {
      releaseTurn = () => {
        if (turnReleased) return;
        turnReleased = true;
        res();
      };
    });
    await myTurn;

    // A queued call can wait minutes; re-validate runtime state after the
    // wait so disposal or abort during the queue doesn't consume bash time.
    if (this.disposed) {
      releaseTurn();
      return { stdout: "", stderr: "Shell has been disposed", exitCode: 1 };
    }
    if (abortSignal?.aborted) {
      releaseTurn();
      return { stdout: "", stderr: "Command aborted", exitCode: 130 };
    }

    this.ensureAlive();

    const proc = this.proc;
    if (!proc || !proc.stdin || !proc.stdout || !proc.stderr) {
      releaseTurn();
      return { stdout: "", stderr: "Failed to spawn shell", exitCode: 1 };
    }

    return new Promise<ShellExecuteResult>((resolve) => {
      let resolved = false;
      let timeoutTimer: ReturnType<typeof setTimeout> | undefined;
      let killEscalationTimer: ReturnType<typeof setTimeout> | undefined;
      let abortCleanup: (() => void) | undefined;
      // Allocate the per-command markers inside the Promise body so any
      // throw during construction (e.g. exhausted entropy on `randomBytes`)
      // is caught by the outer try/catch below and the queue turn is
      // released — without this, a throw between `await myTurn` and the
      // installation of `pending.resolve` would deadlock the shell.
      let pending: PendingCommand | null = null;

      try {
        const marker = `__APEX_${randomBytes(8).toString("hex")}__`;
        const exitMarkerPrefix = `${marker}_EXIT_`;
        const cutoverMarker = `${marker}_CUTOVER`;

        pending = {
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
            // Release the queue turn before resolving so the next queued
            // execute() can assign `this.current` in the same tick the
            // caller observes the result.
            releaseTurn();
            resolve(result);
          },
        };

        this.current = pending;
        this.pendingCancel = pending.resolve;

        if (abortSignal) {
          const p = pending;
          const onAbort = () => {
            if (resolved) return;
            p.forcedExitCode = 130;
            p.forcedStderrSuffix = p.stderr ? "\n(aborted)" : "(aborted)";
            killDescendants(proc.pid, "SIGTERM");
            killEscalationTimer = setTimeout(() => {
              if (resolved) return;
              killDescendants(proc.pid, "SIGKILL");
              // Fallback: if bash didn't emit a marker within another
              // 2 seconds (shell wedged), resolve with whatever we have.
              setTimeout(() => {
                if (resolved) return;
                p.resolve({
                  stdout: extractFallbackStdout(p),
                  stderr: (p.stderr || "") + (p.forcedStderrSuffix ?? ""),
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
          const p = pending;
          timeoutTimer = setTimeout(() => {
            if (resolved) return;
            p.forcedExitCode = 124;
            // Kill every descendant of the shell, not just direct children:
            // pipelines and nested subshells are grandchildren and `pkill -P`
            // would leak them.
            killDescendants(proc.pid, "SIGTERM");
            killEscalationTimer = setTimeout(() => {
              if (resolved) return;
              killDescendants(proc.pid, "SIGKILL");
              // Fallback: if bash didn't emit a marker within another
              // 2 seconds (shell wedged), resolve with whatever we have.
              setTimeout(() => {
                if (resolved) return;
                p.resolve({
                  stdout: extractFallbackStdout(p),
                  stderr: p.stderr || "",
                  exitCode: 124,
                });
              }, 2_000);
            }, 500);
          }, timeoutSeconds * 1_000);
        }

        // Wrap command:
        //   - brace group `{ ...; }` (NOT a subshell) so `cd`, `export`,
        //     shell functions, aliases, and option changes persist;
        //   - stdin redirected from `/dev/null` so children that read stdin
        //     cannot hijack our command pipe;
        //   - stdout captured to a per-command tempfile (NOT bash's stdout
        //     pipe) and streamed back via a background `tail -f` for live
        //     UX. This prevents backgrounded children whose fd 1 was never
        //     redirected (`nmap -v &`) from bleeding their output into the
        //     next command's captured stdout, because their inherited fd 1
        //     is the tempfile for the command that spawned them, not the
        //     shell's stdout pipe;
        //   - stderr captured to another tempfile and flushed after, so we
        //     can distinguish stdout from stderr without interleaving;
        //   - after the user command finishes we kill the tail, then emit
        //     a per-command cutover marker on bash's real stdout pipe, then
        //     `cat` the stdout tempfile. The post-cutover `cat` bytes are
        //     authoritative: they pass through bash's pipe with no tail /
        //     libc block-buffering intermediary. The Node handler treats
        //     pre-cutover bytes as live-UX streaming only and post-cutover
        //     bytes as the authoritative capture returned in the result.
        //     This is required because `tail`'s stdout is a pipe and
        //     block-buffered by libc; on platforms where `stdbuf` is a
        //     no-op (macOS under SIP, Alpine, minimal containers without
        //     coreutils) the buffered bytes would be discarded when we
        //     kill tail, silently losing all stdout for small commands;
        //   - the exit marker is echoed on bash's real stdout pipe, so the
        //     parent Node handler always sees it immediately regardless of
        //     how much command output the cat has left to flush.
        // When `stdbuf` is available and effective (GNU coreutils on glibc
        // Linux), a fast-polling `stdbuf -oL tail -n +1 -f -s 0.05` is run
        // in the background so live streaming latency is well under 100 ms
        // per chunk. Elsewhere the tail still runs (in case it happens to
        // flush) but the authoritative cat guarantees correctness either
        // way.
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
          // Authoritative cutover: post-marker bytes come through bash's
          // real stdout pipe via `cat`, bypassing any tail/libc buffering.
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
      } catch (e) {
        // Defense in depth: if anything between `await myTurn` and
        // installation of `pending.resolve` threw, the wrapped resolver
        // never ran and the queue turn would leak, deadlocking subsequent
        // execute() calls. Catch, release the turn directly, and surface
        // the error to the caller.
        if (pending) {
          pending.resolve({
            stdout: "",
            stderr: e instanceof Error ? e.message : String(e),
            exitCode: 1,
          });
        } else {
          releaseTurn();
          resolve({
            stdout: "",
            stderr: e instanceof Error ? e.message : String(e),
            exitCode: 1,
          });
        }
      }
    });
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
      killDescendants(this.proc.pid, "SIGTERM");
      setTimeout(() => {
        if (this.proc?.pid) killDescendants(this.proc.pid, "SIGKILL");
        // Fallback resolve if bash's wrapper never emits a marker.
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

/**
 * Walk the process tree under `rootPid` and send `signal` to every
 * descendant (deepest first). Does NOT signal `rootPid` itself — that's
 * the persistent shell we want to keep alive. Used instead of
 * `pkill -P <pid>`, which only hits direct children and so leaks
 * pipeline stages / grandchildren of timed-out commands.
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
      // pgrep not available; nothing we can do
    }
  }

  // Signal leaves first so intermediate processes don't see a dead child
  // and exit before we get to their siblings.
  for (let i = toKill.length - 1; i >= 0; i--) {
    try {
      process.kill(toKill[i], signal);
    } catch {
      // already dead / permission denied
    }
  }
}
