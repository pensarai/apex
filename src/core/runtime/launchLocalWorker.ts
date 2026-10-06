import { spawn } from "node:child_process";
import { constants } from "node:fs";
import { type FileHandle, lstat, open } from "node:fs/promises";
import { dirname, isAbsolute, resolve } from "node:path";
import { acquireLocalRunLock } from "./localRunLock";
import { resolveWorkerEndpoint } from "./localWorkerEndpoint";
import {
  LocalWorkerTransportError,
  WorkerConnectionError,
  workerRequest,
} from "./localWorkerTransport";
export interface LaunchLocalWorkerInput {
  runId: string;
  /** Absolute path to the canonical run database. */
  databasePath: string;
  /** Executable/args that serve `agent-runs worker --run <id> --store <db>`. */
  executable: { command: string; args?: string[] };
  startupTimeoutMs?: number;
  probeIntervalMs?: number;
}

export interface LaunchedLocalWorker {
  socketPath: string;
  logPath: string;
}

export interface WorkerExecutable {
  command: string;
  args?: string[];
}

/**
 * Resolve the executable that re-enters this CLI for `agent-runs worker`:
 * a compiled Bun binary embeds its entry (virtual Bun.main under /$bunfs/),
 * source TUI development uses its sibling CLI entry; packages re-run argv[1].
 */
export function resolveWorkerExecutable(
  environment: { execPath?: string; argv1?: string; bunMain?: string } = {
    execPath: process.execPath,
    argv1: process.argv[1],
    bunMain: (globalThis as { Bun?: { main?: string } }).Bun?.main,
  },
): WorkerExecutable {
  const { execPath, argv1, bunMain } = environment;
  if (bunMain?.startsWith("/$bunfs/") || argv1?.startsWith("/$bunfs/")) {
    return { command: execPath ?? process.execPath };
  }
  if (!argv1 || !isAbsolute(argv1)) {
    throw new Error(
      `Cannot resolve the CLI entry for worker launch (argv[1]: ${argv1 ?? "missing"})`,
    );
  }
  const cliEntry = argv1.endsWith("/src/tui/index.tsx")
    ? resolve(dirname(argv1), "../cli.ts")
    : argv1;
  return { command: execPath ?? process.execPath, args: [cliEntry] };
}

const DEFAULT_STARTUP_TIMEOUT_MS = 15_000;
const DEFAULT_PROBE_INTERVAL_MS = 150;
const PROBE_TIMEOUT_MS = 2_000;

// Only an absent or refused endpoint means "no live worker"; anything else
// is a live-but-unusable peer that must be reported, never replaced.
function isEndpointAbsent(error: unknown): boolean {
  const code = (error as NodeJS.ErrnoException | undefined)?.code;
  return code === "ENOENT" || code === "ECONNREFUSED";
}

// A peer tearing itself down answers 503 or rips the connection mid-read;
// the transport retries reads once, but teardown can outlast that retry.
function isPeerRetiring(error: unknown): boolean {
  return (
    error instanceof WorkerConnectionError ||
    (error instanceof LocalWorkerTransportError && error.code === "UNAVAILABLE")
  );
}

function sleepUntilDeadline(
  intervalMs: number,
  deadline: number,
): Promise<boolean> {
  return new Promise((resolveSleep) => {
    const remaining = deadline - Date.now();
    if (remaining <= 0) {
      resolveSleep(false);
      return;
    }
    setTimeout(() => resolveSleep(true), Math.min(intervalMs, remaining));
  });
}

async function openPrivateLog(path: string): Promise<FileHandle> {
  // lstat (never following) rejects a symlinked or non-regular log path
  // before any bytes flow into it.
  const existing = await lstat(path).catch((error: NodeJS.ErrnoException) => {
    if (error.code === "ENOENT") return undefined;
    throw error;
  });
  if (existing && !existing.isFile()) {
    throw new Error(`Worker log path is not a regular file: ${path}`);
  }
  // O_NOFOLLOW in the flags: a symlinked path fails at open, not after.
  const handle = await open(
    path,
    constants.O_WRONLY |
      constants.O_APPEND |
      constants.O_CREAT |
      (constants.O_NOFOLLOW ?? 0),
    0o600,
  ).catch((error: NodeJS.ErrnoException) => {
    if (error.code === "ELOOP") {
      throw new Error(`Worker log path is a symlink: ${path}`);
    }
    throw error;
  });
  try {
    // fd-based: what we opened is what we verify, with no path TOCTOU.
    const info = await handle.stat();
    if (!info.isFile()) {
      throw new Error(`Worker log path is not a regular file: ${path}`);
    }
    const uid = process.getuid?.();
    if (uid !== undefined && info.uid !== uid) {
      throw new Error(`Worker log path is owned by another user: ${path}`);
    }
    const mode = info.mode & 0o777;
    if ((mode & 0o077) !== 0) {
      throw new Error(
        `Worker log permissions are too broad (${mode.toString(8)}): ${path}`,
      );
    }
    return handle;
  } catch (error) {
    await handle.close();
    throw error;
  }
}

/** Spawn the detached local worker for one recorded run. Readiness is
 * established by probing only — a startup timeout never kills the process. */
export async function launchLocalWorker(
  input: LaunchLocalWorkerInput,
): Promise<LaunchedLocalWorker> {
  const {
    runId,
    databasePath,
    executable,
    startupTimeoutMs = DEFAULT_STARTUP_TIMEOUT_MS,
    probeIntervalMs = DEFAULT_PROBE_INTERVAL_MS,
  } = input;

  if (!runId) throw new Error("A run id is required");
  if (!isAbsolute(databasePath)) {
    throw new Error("The run database path must be absolute");
  }
  const canonicalDatabase = resolve(databasePath);

  const endpoint = await resolveWorkerEndpoint(canonicalDatabase, runId);
  const deadline = Date.now() + startupTimeoutMs;
  const probe = () =>
    workerRequest(
      endpoint.socketPath,
      { protocolVersion: 1, method: "snapshot" },
      { timeoutMs: PROBE_TIMEOUT_MS },
    );

  for (;;) {
    try {
      const snapshot = await probe();
      if (snapshot.phase !== "settled") {
        return { socketPath: endpoint.socketPath, logPath: endpoint.logPath };
      }
    } catch (error) {
      if (isEndpointAbsent(error)) {
        // Absence alone is not spawn-safe: the retiring host unlinks its
        // socket before releasing the host lock, so prove release first.
        const lock = await acquireLocalRunLock(
          runId,
          endpoint.lockDatabasePath,
        ).catch((cause: unknown) => {
          if (
            cause instanceof Error &&
            cause.message.includes("held by another executor")
          ) {
            return undefined;
          }
          throw cause;
        });
        if (lock) {
          lock.release();
          break;
        }
      } else if (!isPeerRetiring(error)) {
        throw error;
      }
    }
    // A settled host is retiring and cannot accept another execution.
    if (!(await sleepUntilDeadline(probeIntervalMs, deadline))) {
      throw new Error(
        `Worker for ${runId} did not retire within ${startupTimeoutMs}ms; log: ${endpoint.logPath}`,
      );
    }
  }

  const log = await openPrivateLog(endpoint.logPath);
  let spawnError: Error | undefined;
  let exited: number | null | undefined;
  try {
    const child = spawn(
      executable.command,
      [
        ...(executable.args ?? []),
        "agent-runs",
        "worker",
        "--run",
        runId,
        "--store",
        canonicalDatabase,
      ],
      {
        detached: true,
        stdio: ["ignore", log.fd, log.fd],
      },
    );
    // Listeners are registered before the handle closes so a spawn failure
    // between the two awaits is never unhandled.
    child.once("error", (error) => {
      spawnError ??= error;
    });
    child.once("exit", (code) => {
      exited = code ?? -1;
    });
    child.unref();
  } finally {
    await log.close();
  }

  let lastProbe: unknown;
  for (;;) {
    try {
      const snapshot = await probe();
      if (snapshot.phase !== "settled") {
        return { socketPath: endpoint.socketPath, logPath: endpoint.logPath };
      }
      lastProbe = new Error("Worker has already settled");
    } catch (error) {
      // Post-spawn teardown (our child or a racing peer closing) waits
      // out like retirement; unknown peers stay fatal.
      if (!isEndpointAbsent(error) && !isPeerRetiring(error)) throw error;
      lastProbe = error;
    }
    if (spawnError) {
      throw new Error(
        `Worker process for ${runId} failed to start: ${spawnError.message}`,
      );
    }
    if (!(await sleepUntilDeadline(probeIntervalMs, deadline))) {
      // Our child exiting with the endpoint absent is not proof no peer
      // will serve: a concurrent worker may still be starting. Only the
      // deadline decides, and the failure names the child's fate and log.
      const detail =
        exited !== undefined
          ? `our worker process exited (code ${exited})`
          : "our worker process did not report ready";
      throw new Error(
        `Worker for ${runId} did not become ready within ${startupTimeoutMs}ms: ${detail}; log: ${endpoint.logPath} (probe: ${
          lastProbe instanceof Error ? lastProbe.message : String(lastProbe)
        })`,
      );
    }
  }
}
