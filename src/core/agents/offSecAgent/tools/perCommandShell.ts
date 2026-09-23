import { type ChildProcess, spawn } from "node:child_process";

// Per-stream in-memory capture limit. The process is NEVER killed for output
// volume — capture keeps draining and reports truncation flags instead.
const MAX_CAPTURE_BYTES = 1024 * 1024;

// Group-TERM grace before SIGKILL (matches the reference executor's 3s flush
// window), the SIGKILL-to-settlement confirmation window, and the
// group-liveness poll cadence. Signal submission is not termination
// acknowledgement: the group itself must be observed gone.
const TERM_GRACE_MS = 3_000;
const EXIT_ACK_MS = 250;
const GROUP_POLL_MS = 25;

/**
 * Workspace-configured agent environment variables, transported into the
 * sandbox as a single JSON blob (`PENSAR_AGENT_ENV_VARS`) by the platform's
 * dispatch layer. They are merged into every command's environment.
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

export interface ShellExecuteOptions {
  /** Working directory for this invocation; defaults to the executor's cwd. */
  cwd?: string;
  /** Per-invocation environment, highest precedence below the shell controls. */
  env?: Record<string, string>;
  /** Deadline in seconds; omit for no deadline (caller abort still applies). */
  timeoutSeconds?: number;
  abortSignal?: AbortSignal;
  /** Live stdout chunks as they arrive (best-effort UX, not authoritative). */
  onData?: (chunk: string) => void;
}

export interface ShellExecuteResult {
  stdout: string;
  stderr: string;
  /** Real exit code, or 124 (timeout) / 130 (abort or cancel) on kill paths. */
  exitCode: number;
  timedOut: boolean;
  stdoutTruncated: boolean;
  stderrTruncated: boolean;
  /**
   * True when the terminating path never observed the process group gone
   * within its bounded window (posix), or on any kill path on win32 where
   * only the leader can be signalled. Cleanup may be incomplete; this is
   * surfaced rather than silently succeeding. Children that left the group
   * (setsid) are not owned and are not claimed.
   */
  cleanupUnconfirmed: boolean;
}

interface ActiveInvocation {
  requestKill: (forcedExit: number) => void;
}

/**
 * Fresh shell per invocation: every `execute` runs the command in a NEW
 * process group with an explicit working directory and the configured,
 * curated environment. Nothing — cwd, exports, functions, background jobs —
 * carries across calls; there is no persistent job table. Children that
 * redirect their stdio survive a completed SUCCESS as ordinary processes;
 * timeout/abort/cancel and completed-nonzero exits all run one terminating
 * path that TERM→KILLs the invocation's own group and settles only once the
 * group is observed gone (bounded). Calls are FIFO-serialized, so
 * cancel/dispose always address exactly one active invocation.
 */
export class PerCommandShell {
  private readonly cwd?: string;
  private readonly extraEnv?: Record<string, string>;
  private disposed = false;
  private active: ActiveInvocation | null = null;
  // The started invocation's settlement promise, and the cached dispose
  // barrier — dispose() is never fire-and-forget, and repeat calls return
  // the same bounded settlement wait.
  private activeCompletion: Promise<unknown> | null = null;
  private disposeBarrier: Promise<void> | null = null;

  // FIFO mutex tail: concurrent execute() calls queue and run one at a time,
  // so `active` names the single in-flight invocation cancel/dispose target.
  private writeChain: Promise<void> = Promise.resolve();

  constructor(opts?: { cwd?: string; env?: Record<string, string> }) {
    this.cwd = opts?.cwd;
    this.extraEnv = opts?.env;
  }

  async execute(
    command: string,
    opts?: ShellExecuteOptions,
  ): Promise<ShellExecuteResult> {
    if (this.disposed) return staticResult("Shell has been disposed", 1);
    if (opts?.abortSignal?.aborted) {
      return staticResult("Command aborted", 130);
    }

    const release = await this.acquireTurn();
    try {
      if (this.disposed) return staticResult("Shell has been disposed", 1);
      if (opts?.abortSignal?.aborted) {
        return staticResult("Command aborted", 130);
      }
      const pending = this.runInvocation(command, opts);
      this.activeCompletion = pending;
      return await pending;
    } finally {
      release();
    }
  }

  private async runInvocation(
    command: string,
    opts?: ShellExecuteOptions,
  ): Promise<ShellExecuteResult> {
    const isWin = process.platform === "win32";
    const shell = isWin ? "cmd" : "bash";
    const args = isWin
      ? ["/d", "/s", "/c", command]
      : ["--norc", "--noprofile", "-c", command];

    return new Promise<ShellExecuteResult>((resolve) => {
      let child: ChildProcess;
      try {
        child = spawn(shell, args, {
          stdio: ["ignore", "pipe", "pipe"],
          cwd: opts?.cwd ?? this.cwd,
          // Own process group on posix: the terminating path signals THIS
          // group only — never another invocation or the session.
          detached: !isWin,
          env: {
            // Workspace-configured vars first (lowest precedence) so the
            // curated essentials and explicit agent extras always win —
            // arbitrary process.env is never inherited.
            ...readSandboxAgentEnv(),
            PATH: process.env.PATH ?? "",
            HOME: process.env.HOME ?? "",
            USER: process.env.USER ?? "",
            LANG: process.env.LANG,
            TMPDIR: process.env.TMPDIR,
            ...this.extraEnv,
            ...opts?.env,
            PS1: "",
            CI: "true",
            TERM: "dumb",
            NO_COLOR: "1",
          } as Record<string, string | undefined> as NodeJS.ProcessEnv,
        });
      } catch (err) {
        resolve(
          staticResult(err instanceof Error ? err.message : String(err), 1),
        );
        return;
      }

      const stdoutCap = makeCapture(MAX_CAPTURE_BYTES);
      const stderrCap = makeCapture(MAX_CAPTURE_BYTES);
      let settled = false;
      let terminating = false;
      let killForcedExit: number | null = null;
      let naturalExit: number | null = null;
      let leaderClosed = false;
      let spawnError: string | undefined;

      // Every timer this invocation arms — all fenced by `settled` and cleared
      // exactly once, when the settlement (post-cleanup) protocol finishes.
      const timers = new Set<ReturnType<typeof setTimeout>>();
      const arm = (fn: () => void, ms: number): void => {
        const t = setTimeout(() => {
          timers.delete(t);
          if (settled) return;
          fn();
        }, ms);
        timers.add(t);
      };
      let abortCleanup: (() => void) | undefined;

      const settle = (result: ShellExecuteResult): void => {
        if (settled) return;
        settled = true;
        for (const t of timers) clearTimeout(t);
        timers.clear();
        abortCleanup?.();
        // Owned handles only: detach the captured pipes so no late data event
        // fires after completion, and unref the ChildProcess so a settlement
        // that raced a live leader (unconfirmed ack) cannot pin the runtime.
        // Unref never kills anything — it only releases our handle.
        detachStream(child.stdout);
        detachStream(child.stderr);
        child.unref();
        if (this.active === invocation) this.active = null;
        resolve(result);
      };

      const resolveFinish = (
        exitCode: number,
        extra?: { unconfirmed?: boolean; note?: string },
      ): void =>
        settle({
          stdout: captureText(stdoutCap),
          stderr:
            (spawnError !== undefined ? `${spawnError}\n` : "") +
            captureText(stderrCap) +
            (extra?.note ? `\n${extra.note}` : "") +
            (killForcedExit === 130 ? "\n(aborted)" : ""),
          exitCode,
          timedOut: killForcedExit === 124,
          stdoutTruncated: stdoutCap.truncated,
          stderrTruncated: stderrCap.truncated,
          cleanupUnconfirmed: extra?.unconfirmed === true,
        });

      const invocation: ActiveInvocation = {
        requestKill: (forcedExit) => {
          // First terminal cause wins: once natural completion has entered
          // the terminating path (or another kill already set the cause), a
          // late deadline/abort must not rewrite the reported outcome.
          if (settled || terminating || killForcedExit !== null) return;
          killForcedExit = forcedExit;
          beginTermination();
        },
      };
      this.active = invocation;

      const finishUntrackedTermination = (): void => {
        resolveFinish(killForcedExit ?? naturalExit ?? 1, {
          unconfirmed: true,
          note: "(descendant cleanup unsupported on this platform)",
        });
      };

      // The ONE terminating path, shared by timeout, caller abort, cancel,
      // dispose, and completed-nonzero exits. On POSIX, group TERM, SIGKILL escalation
      // after the grace, then settle exactly once the group is observed gone
      // — the leader's close alone never settles, so a TERM-resistant
      // descendant cannot outlive the escalation.
      const beginTermination = (): void => {
        if (terminating) return;
        terminating = true;
        const pid = child.pid;
        if (isWin || !pid) {
          if (leaderClosed) {
            finishUntrackedTermination();
            return;
          }
          // Windows terminates the leader immediately; descendants remain untracked.
          try {
            child.kill("SIGTERM");
          } catch {
            // already gone
          }
          if (!settled) arm(finishUntrackedTermination, EXIT_ACK_MS);
          return;
        }
        try {
          process.kill(-pid, "SIGTERM");
        } catch {
          // already gone
        }
        arm(() => {
          try {
            process.kill(-pid, "SIGKILL");
          } catch {
            // already gone
          }
        }, TERM_GRACE_MS);
        const pollGroupGone = (): void => {
          if (settled) return;
          // Only ESRCH confirms the group is gone — EPERM or any other error
          // keeps the escalation pending; unknown is never reported as
          // confirmed cleanup.
          if (groupConfirmedGone(pid)) {
            resolveFinish(killForcedExit ?? naturalExit ?? 1);
            return;
          }
          arm(pollGroupGone, GROUP_POLL_MS);
        };
        arm(pollGroupGone, GROUP_POLL_MS);
        // Bounded hard cap: a group still present after the SIGKILL window
        // (unreapable/D-state members) settles with a truthful unconfirmed.
        arm(() => {
          resolveFinish(killForcedExit ?? naturalExit ?? 1, {
            unconfirmed: true,
            note: "(cleanup unconfirmed: process group still present after the bounded kill window)",
          });
        }, TERM_GRACE_MS + EXIT_ACK_MS);
      };

      if (opts?.timeoutSeconds != null && opts.timeoutSeconds > 0) {
        arm(() => invocation.requestKill(124), opts.timeoutSeconds * 1_000);
      }
      if (opts?.abortSignal) {
        abortCleanup = attachAbort(opts.abortSignal, () =>
          invocation.requestKill(130),
        );
      }

      child.stdout?.on("data", (chunk: Buffer) => {
        if (settled) return;
        captureChunk(stdoutCap, chunk);
        opts?.onData?.(chunk.toString("utf8"));
      });
      child.stderr?.on("data", (chunk: Buffer) => {
        if (settled) return;
        captureChunk(stderrCap, chunk);
      });

      child.on("error", (err) => {
        // Spawn failure (e.g. cwd does not exist) — 'close' follows with a
        // null code; the cause surfaces on stderr. Node's message is terse
        // ("spawn bash ENOENT"), so the cwd hint makes it actionable.
        if (spawnError === undefined) {
          const detail = err instanceof Error ? err.message : String(err);
          const cwdHint = opts?.cwd ?? this.cwd;
          spawnError = cwdHint ? `${detail} (cwd: ${cwdHint})` : detail;
        }
      });
      // Completion is the leader's 'close': exited AND its pipes ended.
      // Redirected-stdio survivors don't hold the pipes, so a successful
      // launcher settles immediately; a child that kept an inherited pipe
      // keeps the invocation pending (deadline/abort still bound it).
      child.on("close", (code) => {
        leaderClosed = true;
        if (spawnError !== undefined) {
          // Spawn failure: nothing was spawned, so there is no group to
          // clean and no meaningful exit code (the close event may carry a
          // platform sentinel like -2). Settle immediately with code 1 and
          // the cause.
          resolveFinish(1);
          return;
        }
        if (terminating) {
          naturalExit = code;
          if (isWin || !child.pid) finishUntrackedTermination();
          // POSIX still waits for the owned group, including surviving descendants.
          return;
        }
        if (code === 0) {
          // Only a completed SUCCESS leaves redirected descendants alive.
          resolveFinish(0);
          return;
        }
        // Completed nonzero: the same terminating path, so a failed launcher
        // never silently leaves its background children alive.
        naturalExit = code;
        beginTermination();
      });
    });
  }

  /**
   * Cancel the invocation currently owned by this executor. Returns true when
   * a live invocation was cancelled; queued invocations and previously
   * completed invocations' surviving services are untouched.
   */
  cancelCurrentCommand(): boolean {
    const inv = this.active;
    if (!inv) return false;
    inv.requestKill(130);
    return true;
  }

  /**
   * Settle and clean the active invocation (if any), refuse further
   * invocations, and drain the FIFO tail of already-queued calls. Returns an
   * idempotent barrier that resolves once every owned invocation — the
   * active one AND previously queued ones — has settled; the 3s kill
   * protocol is never fire-and-forget. Never touches processes left behind
   * by previously completed invocations — those are untracked and owned by
   * their launcher.
   */
  dispose(): Promise<void> {
    if (this.disposed) {
      return this.disposeBarrier ?? Promise.resolve();
    }
    this.disposed = true;
    const pending = this.activeCompletion;
    // Snapshot the FIFO tail: once disposed, queued calls refuse on turn
    // arrival and release immediately, so this chain settles every
    // previously-queued execute. New calls never enqueue after this point.
    const tail = this.writeChain;
    this.active?.requestKill(130);
    this.active = null;
    this.disposeBarrier = (async () => {
      await pending?.catch(() => {});
      await tail;
    })();
    return this.disposeBarrier;
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
}

function staticResult(stderr: string, exitCode: number): ShellExecuteResult {
  return {
    stdout: "",
    stderr,
    exitCode,
    timedOut: false,
    stdoutTruncated: false,
    stderrTruncated: false,
    cleanupUnconfirmed: false,
  };
}

// Group liveness probe: signal 0 against the group id. ONLY ESRCH proves the
// group is gone — EPERM or any other error means "unknown", and the caller
// must keep the escalation pending rather than claim confirmed cleanup.
function groupConfirmedGone(pgid: number): boolean {
  try {
    process.kill(-pgid, 0);
    return false;
  } catch (err) {
    return (err as NodeJS.ErrnoException | null)?.code === "ESRCH";
  }
}

interface CaptureBuffer {
  // One owned, geometrically grown buffer, hard-capped at maxBytes: no
  // per-chunk allocations and no retained pipe-allocated backing storage.
  buf: Buffer;
  used: number;
  truncated: boolean;
  readonly max: number;
}

function makeCapture(maxBytes: number): CaptureBuffer {
  return { buf: Buffer.alloc(0), used: 0, truncated: false, max: maxBytes };
}

function captureChunk(cap: CaptureBuffer, chunk: Buffer): void {
  const room = cap.max - cap.used;
  if (room <= 0) {
    cap.truncated = true;
    return;
  }
  const take = Math.min(chunk.byteLength, room);
  if (take < chunk.byteLength) cap.truncated = true;
  if (cap.buf.byteLength < cap.used + take) {
    let size = cap.buf.byteLength || 64 * 1024;
    while (size < cap.used + take && size < cap.max) size *= 2;
    const next = Buffer.alloc(Math.min(size, cap.max));
    cap.buf.copy(next, 0, 0, cap.used);
    cap.buf = next;
  }
  chunk.copy(cap.buf, cap.used, 0, take);
  cap.used += take;
}

function captureText(cap: CaptureBuffer): string {
  if (cap.used === 0) return "";
  // Full-UTF8 decode of exactly the captured bytes — no reassembly, so
  // multibyte sequences spanning chunk boundaries survive intact.
  return cap.buf.subarray(0, cap.used).toString("utf8");
}

function attachAbort(signal: AbortSignal, onAbort: () => void): () => void {
  const listener = () => onAbort();
  if (signal.aborted) {
    onAbort();
    return () => {};
  }
  signal.addEventListener("abort", listener, { once: true });
  return () => signal.removeEventListener("abort", listener);
}

// Detach a pipe we own so no late event fires after settlement. Surviving
// (redirected-stdio) children never held it; an inherited-pipe straggler
// gets EPIPE.
function detachStream(stream: unknown): void {
  const s = stream as { unref?: () => void; destroy?: () => void } | null;
  try {
    s?.unref?.();
    s?.destroy?.();
  } catch {
    // already gone
  }
}
