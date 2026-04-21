/**
 * Host-side client for the persistent Chromium daemon that runs inside
 * the Daytona sandbox. Pairs with sandbox-pw-daemon/daemon.cjs.
 *
 * Lifecycle: one daemon per sandbox, for the entire sandbox lifetime.
 * `ensureDaemon` is idempotent + memoized (WeakMap). It:
 *
 *   1. reuses an already-healthy daemon if one is running (host-crash
 *      resilience — the sandbox outlives the host process),
 *   2. otherwise uploads daemon.cjs, spawns it with `nohup ... &`,
 *   3. polls for the atomic port file, then curls `/v1/healthz` for
 *      readiness confirmation.
 *
 * `callDaemon` is the one-shot call used by every browser tool. It
 * shells out to `curl` inside the sandbox targeting 127.0.0.1:<port>.
 * On any liveness failure (curl non-zero, timeout, unparseable JSON) it
 * trips a single-budget respawn — kill + re-ensure + replay once. Tool-
 * level `{success: false}` bodies pass through verbatim so the agent can
 * see them.
 *
 * See the plan at ~/.claude/plans/feature-request-add-test-merry-flute.md
 * for the full architectural rationale.
 */

import { fileURLToPath } from "url";
import { readFileSync } from "fs";
import { dirname, resolve } from "path";
import type { UnifiedSandbox } from "./sandbox";

// --- constants ---------------------------------------------------------------

const DAEMON_REMOTE_PATH = "/opt/sandbox-playwright/apex-pw-daemon.cjs";
const PORT_FILE = "/tmp/apex-pw-port";
const LOG_FILE = "/tmp/apex-pw-daemon.log";
const PID_FILE = "/tmp/apex-pw-daemon.pid";
const NODE_MODULES_DIR = "/opt/sandbox-playwright/node_modules";

const READY_POLL_INTERVAL_MS = 250;
const READY_MAX_WAIT_MS = 30_000;
const HEALTH_TIMEOUT_SEC = 2;
const DEFAULT_ACTION_TIMEOUT_SEC = 30;
const CURL_SLACK_SEC = 10;

// Large-payload threshold: below this, args are inlined into the curl
// command as `-d '<escaped>'`. Above it, args are staged to a sandbox
// temp file and curl reads via `-d @/tmp/...`.
const CURL_INLINE_MAX_BYTES = 2048;

// Per-action timeouts mirrored from the daemon's handlers — the host's
// outer `sandbox.execute` timeout is max(action+slack, …). Keeping the
// two in lock-step prevents the host timeout from hiding a daemon-side
// abort with a cleaner error message.
const ACTION_TIMEOUTS_SEC: Record<string, number> = {
  navigate: 34, // 30s nav + 1.5s networkidle budget + 2s handler slack
  snapshot: 15,
  screenshot: 20,
  click: 15,
  fill: 15,
  evaluate: 15,
  press_key: 15,
  console: 5,
  cookies: 5,
  "reload-cookies": 5,
  healthz: HEALTH_TIMEOUT_SEC,
};

// --- daemon source (read at import) -----------------------------------------

// Resolve the daemon's source file relative to THIS module. In ESM the
// canonical idiom is `fileURLToPath(new URL(...))`. The TS tsc layout
// preserves relative paths between compiled output and sibling files,
// so `./sandbox-pw-daemon/daemon.cjs` resolves correctly at runtime
// whether this file is loaded as source (tsx) or compiled.
const DAEMON_SOURCE: string = (() => {
  const here = dirname(fileURLToPath(import.meta.url));
  const daemonPath = resolve(here, "sandbox-pw-daemon", "daemon.cjs");
  return readFileSync(daemonPath, "utf-8");
})();

// --- types -------------------------------------------------------------------

export interface DaemonHandle {
  port: number;
  pid: number | null;
  bootedAt: number;
  playwrightVersion: string;
  respawnCount: number;
}

export interface CallDaemonOpts {
  /**
   * Per-action timeout override in seconds. Defaults come from
   * ACTION_TIMEOUTS_SEC per action. The outer `sandbox.execute` timeout
   * is this value plus CURL_SLACK_SEC.
   */
  timeoutSec?: number;
}

// --- memoization ------------------------------------------------------------

const daemonCache = new WeakMap<UnifiedSandbox, Promise<DaemonHandle>>();

// --- small helpers -----------------------------------------------------------

function sleep(ms: number): Promise<void> {
  return new Promise((r) => setTimeout(r, ms));
}

// Shell-escape a string for safe inclusion between single quotes.
// Single quotes inside the string are closed, escaped, and reopened.
function shSingleQuote(s: string): string {
  return "'" + s.replace(/'/g, "'\\''") + "'";
}

// Upload via the Daytona SDK's native uploadFile when available; fall back
// to base64-heredoc over `execute` so test doubles (execute-only mocks)
// still work. Chunk size is conservative to stay under shell arg length
// limits that vary by runtime.
async function uploadFile(
  sandbox: UnifiedSandbox,
  content: string,
  remotePath: string,
): Promise<void> {
  if (typeof sandbox.uploadFile === "function") {
    await sandbox.uploadFile(content, remotePath);
    return;
  }
  const b64 = Buffer.from(content, "utf-8").toString("base64");
  const CHUNK = 64 * 1024;
  const remoteTmp = `${remotePath}.b64`;
  let written = 0;
  await sandbox.execute(
    `mkdir -p ${shSingleQuote(dirname(remotePath))} && rm -f ${shSingleQuote(remoteTmp)}`,
    { timeout: 10 },
  );
  while (written < b64.length) {
    const chunk = b64.slice(written, written + CHUNK);
    const op = written === 0 ? ">" : ">>";
    await sandbox.execute(
      `printf '%s' '${chunk}' ${op} ${shSingleQuote(remoteTmp)}`,
      { timeout: 30 },
    );
    written += CHUNK;
  }
  const decode = await sandbox.execute(
    `base64 -d ${shSingleQuote(remoteTmp)} > ${shSingleQuote(remotePath)} && rm -f ${shSingleQuote(remoteTmp)}`,
    { timeout: 30 },
  );
  if (!decode.success || decode.exitCode !== 0) {
    throw new Error(
      `sandboxPlaywrightClient: uploadFile fallback failed: ${decode.stderr || decode.stdout}`,
    );
  }
}

// Read the tail of the daemon log — used in error messages so operators
// have breadcrumbs without having to log into the sandbox.
async function readDaemonLogTail(
  sandbox: UnifiedSandbox,
  lines = 80,
): Promise<string> {
  try {
    const r = await sandbox.execute(
      `tail -n ${lines} ${shSingleQuote(LOG_FILE)} 2>/dev/null || true`,
      { timeout: 5 },
    );
    return (r.stdout || "").trim();
  } catch {
    return "";
  }
}

// --- daemon readiness helpers ------------------------------------------------

async function readPort(sandbox: UnifiedSandbox): Promise<number | null> {
  const r = await sandbox.execute(
    `test -f ${shSingleQuote(PORT_FILE)} && cat ${shSingleQuote(PORT_FILE)} || true`,
    { timeout: 5 },
  );
  const value = parseInt((r.stdout || "").trim(), 10);
  return Number.isFinite(value) && value > 0 ? value : null;
}

async function healthCheck(
  sandbox: UnifiedSandbox,
  port: number,
): Promise<{
  ok: boolean;
  pid: number | null;
  playwrightVersion: string;
} | null> {
  const r = await sandbox.execute(
    `curl -s --max-time ${HEALTH_TIMEOUT_SEC} http://127.0.0.1:${port}/v1/healthz`,
    { timeout: HEALTH_TIMEOUT_SEC + 2 },
  );
  if (!r.success || r.exitCode !== 0) return null;
  try {
    const body = JSON.parse(r.stdout || "{}") as {
      ok?: boolean;
      pid?: number;
      playwrightVersion?: string;
    };
    if (body.ok) {
      return {
        ok: true,
        pid: typeof body.pid === "number" ? body.pid : null,
        playwrightVersion: body.playwrightVersion ?? "unknown",
      };
    }
  } catch {
    /* malformed response */
  }
  return null;
}

async function waitForPortFile(sandbox: UnifiedSandbox): Promise<number> {
  const deadline = Date.now() + READY_MAX_WAIT_MS;
  while (Date.now() < deadline) {
    const port = await readPort(sandbox);
    if (port !== null) return port;
    await sleep(READY_POLL_INTERVAL_MS);
  }
  // Log tail helps operators diagnose startup failures — bad
  // executable path, missing Playwright, port already bound, etc.
  const tail = await readDaemonLogTail(sandbox, 120);
  throw new Error(
    `sandboxPlaywrightClient: daemon did not publish ${PORT_FILE} within ${READY_MAX_WAIT_MS / 1000}s.` +
      (tail
        ? ` --- daemon log tail:\n${tail}`
        : ` --- daemon log is empty or unreadable`),
  );
}

// --- ensureDaemon ------------------------------------------------------------

/**
 * Ensure a live Playwright daemon is running inside the sandbox, and
 * return its HTTP port. Memoized per-sandbox via WeakMap.
 *
 * Behavior:
 *   - If a daemon is already running and healthy, reuse it (important
 *     when the apex host crashes and is restarted — the sandbox keeps
 *     running, and we shouldn't spawn a duplicate daemon on top).
 *   - Otherwise upload daemon.cjs, launch via nohup, and poll for ready.
 *   - On any failure, clear cache, include the daemon log tail in the
 *     thrown error so debugging is tractable.
 */
export async function ensureDaemon(
  sandbox: UnifiedSandbox,
): Promise<DaemonHandle> {
  const cached = daemonCache.get(sandbox);
  if (cached) return cached;

  const promise = bootDaemon(sandbox, { respawnCount: 0 });
  daemonCache.set(sandbox, promise);
  promise.catch(() => {
    // Drop failed bootstraps so the next call retries from scratch.
    if (daemonCache.get(sandbox) === promise) daemonCache.delete(sandbox);
  });
  return promise;
}

async function bootDaemon(
  sandbox: UnifiedSandbox,
  opts: { respawnCount: number },
): Promise<DaemonHandle> {
  // 1. If an existing daemon is reachable + healthy, adopt it.
  const existingPort = await readPort(sandbox).catch(() => null);
  if (existingPort !== null) {
    const health = await healthCheck(sandbox, existingPort).catch(() => null);
    if (health?.ok) {
      return {
        port: existingPort,
        pid: health.pid,
        bootedAt: Date.now(),
        playwrightVersion: health.playwrightVersion,
        respawnCount: opts.respawnCount,
      };
    }
  }

  // 2. Clean up any stale daemon + port file before spawning a fresh one.
  //    Also remove Chromium's Singleton* lock files in /tmp/pw-user-data
  //    — after a SIGKILL these aren't cleaned by the dead Chromium and
  //    launchPersistentContext refuses to open a second profile.
  await sandbox.execute(
    `sh -c 'pkill -f apex-pw-daemon 2>/dev/null; ` +
      `rm -f ${shSingleQuote(PORT_FILE)} ${shSingleQuote(PID_FILE)} 2>/dev/null; ` +
      `rm -f /tmp/pw-user-data/Singleton* 2>/dev/null; true'`,
    { timeout: 10 },
  );

  // 3. Upload the daemon script (use native uploadFile when available).
  await uploadFile(sandbox, DAEMON_SOURCE, DAEMON_REMOTE_PATH);

  // 4. Upload a small launcher script + invoke it. Shelling out a
  //    multi-command pipeline through `sh -c` with nested single quotes
  //    is brittle — file-based invocation is resilient to any shell
  //    quoting wobble.
  //
  //    The launcher is deliberately self-idempotent: it pkills any
  //    existing daemon + Singleton lockfiles before forking. If the
  //    underlying `sandbox.execute` infrastructure retries this command
  //    (observed in practice — two daemons were racing for the port
  //    file during the dead-daemon recovery test), the second
  //    invocation's pkill kills the first's daemon before spawning its
  //    own. Last-writer-wins → exactly one daemon.
  const launcherPath = "/opt/sandbox-playwright/apex-pw-launcher.sh";
  const launcherScript = [
    "#!/bin/sh",
    "set -e",
    // idempotent teardown of any prior daemon + Chromium state
    "pkill -f apex-pw-daemon.cjs 2>/dev/null || true",
    `rm -f ${PORT_FILE} ${PID_FILE} 2>/dev/null || true`,
    "rm -f /tmp/pw-user-data/Singleton* 2>/dev/null || true",
    // fresh spawn
    `NODE_PATH=${NODE_MODULES_DIR} nohup node ${DAEMON_REMOTE_PATH} > ${LOG_FILE} 2>&1 &`,
    // brief pause so the fork completes before the launcher exits
    "sleep 0.2",
    "",
  ].join("\n");
  await uploadFile(sandbox, launcherScript, launcherPath);
  const spawnResult = await sandbox.execute(
    `sh ${shSingleQuote(launcherPath)}`,
    { timeout: 15 },
  );
  if (!spawnResult.success) {
    throw new Error(
      `sandboxPlaywrightClient: failed to spawn daemon: exitCode=${spawnResult.exitCode} stdout=${spawnResult.stdout} stderr=${spawnResult.stderr}`,
    );
  }

  // 5. Poll for readiness: port file → curl /healthz succeeds.
  //    After SIGKILL-then-respawn, Chromium's user-data-dir can hold a
  //    stale lock for a second or two (no graceful release). Retry the
  //    health probe a few times so a tight respawn doesn't flake.
  const port = await waitForPortFile(sandbox);
  let health: Awaited<ReturnType<typeof healthCheck>> = null;
  for (let attempt = 0; attempt < 8 && !health?.ok; attempt++) {
    health = await healthCheck(sandbox, port);
    if (!health?.ok) await sleep(500);
  }
  if (!health?.ok) {
    const tail = await readDaemonLogTail(sandbox, 120);
    throw new Error(
      `sandboxPlaywrightClient: daemon bound port ${port} but /healthz is not responding after 8 probes. --- daemon log tail:\n${tail}`,
    );
  }

  return {
    port,
    pid: health.pid,
    bootedAt: Date.now(),
    playwrightVersion: health.playwrightVersion,
    respawnCount: opts.respawnCount,
  };
}

// --- callDaemon --------------------------------------------------------------

/**
 * Invoke a daemon endpoint and return the parsed JSON body.
 *
 * Per-call failure modes, in priority order:
 *   1. curl non-zero exit or timeout → daemon liveness failure;
 *      respawn once and replay.
 *   2. Unparseable JSON → same.
 *   3. `{success: true|false, ...}` body → return verbatim. The tool-
 *      level `{success: false, error: ...}` path is the agent's
 *      feedback channel — never trigger a respawn on it.
 */
export async function callDaemon<T = unknown>(
  sandbox: UnifiedSandbox,
  action: string,
  args: Record<string, unknown> = {},
  opts?: CallDaemonOpts,
): Promise<T> {
  return callWithRetry(sandbox, action, args, opts, 0);
}

async function callWithRetry<T>(
  sandbox: UnifiedSandbox,
  action: string,
  args: Record<string, unknown>,
  opts: CallDaemonOpts | undefined,
  attempt: number,
): Promise<T> {
  const handle = await ensureDaemon(sandbox);
  const timeoutSec =
    opts?.timeoutSec ??
    ACTION_TIMEOUTS_SEC[action] ??
    DEFAULT_ACTION_TIMEOUT_SEC;
  const outerTimeout = timeoutSec + CURL_SLACK_SEC;

  const body = JSON.stringify(args);
  let cmd: string;

  if (Buffer.byteLength(body, "utf-8") <= CURL_INLINE_MAX_BYTES) {
    cmd =
      `curl -s --max-time ${timeoutSec} ` +
      `-H 'content-type: application/json' ` +
      `-X POST ${shSingleQuote(
        `http://127.0.0.1:${handle.port}/v1/${action}`,
      )} ` +
      `-d ${shSingleQuote(body)}`;
  } else {
    // Stage large payloads (evaluate scripts, etc.) to a temp file first
    // so we don't pipe enormous shell-escaped strings through execute.
    const staged = `/tmp/apex-pw-req-${Date.now()}-${Math.random().toString(36).slice(2, 8)}.json`;
    await uploadFile(sandbox, body, staged);
    cmd =
      `curl -s --max-time ${timeoutSec} ` +
      `-H 'content-type: application/json' ` +
      `-X POST ${shSingleQuote(
        `http://127.0.0.1:${handle.port}/v1/${action}`,
      )} ` +
      `-d @${shSingleQuote(staged)}; rm -f ${shSingleQuote(staged)}`;
    cmd = `sh -c ${shSingleQuote(cmd)}`;
  }

  const result = await sandbox.execute(cmd, { timeout: outerTimeout });

  // Parse-and-return path. Any structured JSON — including {success:false,...}
  // — passes through; only liveness failures fall through to respawn.
  //
  // When `attempt > 0`, this is a replay after a single-budget respawn.
  // The fresh daemon has a pristine Chromium context: cookies/localStorage
  // persisted via /tmp/pw-user-data, but in-memory React state, tab
  // selection, and open-page URL all reset. Surface this explicitly to
  // the agent via `_note` so it doesn't waste steps guessing "why is the
  // page blank now?" — see the pentest prompt's SECTION_BROWSER_INTERACTION
  // and the testCase prompt's Rule 4 for the agent-side contract.
  if (result.success && result.exitCode === 0) {
    const stdout = (result.stdout || "").trim();
    if (stdout.length > 0) {
      try {
        const parsed = JSON.parse(stdout);
        if (
          attempt > 0 &&
          parsed &&
          typeof parsed === "object" &&
          !Array.isArray(parsed)
        ) {
          (parsed as Record<string, unknown>)._note =
            "browser daemon was restarted after unresponsiveness; React state has been reset — re-navigate to your target feature and re-enter any input before continuing. Cookies and localStorage persist.";
        }
        return parsed as T;
      } catch {
        /* fall through to respawn path */
      }
    }
  }

  // Liveness failure. Respawn exactly once — infinite retry loops eat
  // workflow budgets silently (the single biggest failure mode for
  // autonomous agent runs). If respawn + replay fails too, surface the
  // error to the caller as a tool-level failure so the agent can adapt.
  if (attempt >= 1) {
    const tail = await readDaemonLogTail(sandbox, 60);
    throw new Error(
      `sandboxPlaywrightClient.callDaemon: action ${action} failed after ` +
        `single-budget respawn. exitCode=${result.exitCode} stdout=${(result.stdout || "").slice(0, 500)} stderr=${(result.stderr || "").slice(0, 500)}` +
        (tail ? ` --- daemon log tail:\n${tail}` : ""),
    );
  }

  // Clear the cache + force a fresh boot on the next ensureDaemon call.
  // Same Chromium-lock cleanup as bootDaemon step 2 — the dead daemon
  // left SingletonLock behind and the fresh Chromium would refuse to
  // open the same user-data-dir without this.
  daemonCache.delete(sandbox);
  await sandbox
    .execute(
      `sh -c 'pkill -f apex-pw-daemon 2>/dev/null; ` +
        `rm -f ${shSingleQuote(PORT_FILE)} ${shSingleQuote(PID_FILE)} 2>/dev/null; ` +
        `rm -f /tmp/pw-user-data/Singleton* 2>/dev/null; true'`,
      { timeout: 10 },
    )
    .catch(() => {});
  // Seed the NEW handle with an incremented respawn count for observability.
  const freshPromise = bootDaemon(sandbox, {
    respawnCount: handle.respawnCount + 1,
  });
  daemonCache.set(sandbox, freshPromise);
  return callWithRetry(sandbox, action, args, opts, attempt + 1);
}

// --- shutdownDaemon (tests only) ---------------------------------------------

/**
 * Gracefully terminate the daemon. Intended for test teardown — on
 * production runs, the daemon dies naturally when the sandbox is
 * destroyed (daytona.delete → kernel cleanup).
 */
export async function shutdownDaemon(sandbox: UnifiedSandbox): Promise<void> {
  const cached = daemonCache.get(sandbox);
  if (!cached) return;
  try {
    const handle = await cached;
    await sandbox.execute(
      `curl -s --max-time 5 -X POST http://127.0.0.1:${handle.port}/v1/shutdown -d '{}' || true`,
      { timeout: 10 },
    );
  } finally {
    daemonCache.delete(sandbox);
  }
}
