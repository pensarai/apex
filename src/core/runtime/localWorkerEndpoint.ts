import { createHash } from "node:crypto";
import { lstat, mkdir, realpath, stat } from "node:fs/promises";
import path from "node:path";
import { RecordedRunSpecSchema } from "./runStore";

export interface WorkerEndpoint {
  /** Private Unix-domain socket the worker serves; mode 0600. */
  socketPath: string;
  /** Private worker log; the opener enforces mode 0600. */
  logPath: string;
  /**
   * Database path for the HOST lock (`acquireLocalRunLock(runId,
   * lockDatabasePath)`) — distinct from the canonical database so hosting
   * exclusion never collides with the run's execution lock.
   */
  lockDatabasePath: string;
}

/** Resolve the private per-run endpoint from a canonical database identity. */
export async function resolveWorkerEndpoint(
  databasePath: string,
  runId: string,
): Promise<WorkerEndpoint> {
  // Detached hosting is macOS/Linux only; refuse before any side effect.
  if (process.platform !== "darwin" && process.platform !== "linux") {
    throw new Error(
      `Local worker hosting is not supported on ${process.platform}`,
    );
  }
  // Admission's runId rule is the single source of truth: a second, tighter
  // cap here would strand runs admitted with longer ids.
  if (!RecordedRunSpecSchema.shape.runId.safeParse(runId).success) {
    throw new Error(`Run id is not a valid endpoint component: ${runId}`);
  }
  if (!path.isAbsolute(databasePath)) {
    throw new Error("The run database path must be absolute");
  }

  const canonical = await realpath(databasePath);
  const info = await stat(canonical);
  if (!info.isFile()) {
    throw new Error("The run database path is not a regular file");
  }

  // Fixed short root instead of TMPDIR (macOS per-user TMPDIR realpaths
  // past the ~104-byte socket limit); the literal root keeps every caller
  // on one endpoint without a canonicalization step.
  const getuid = process.getuid;
  if (getuid === undefined) {
    throw new Error("Local worker hosting requires POSIX process identity");
  }
  const uid = getuid.call(process);
  const workerDir = path.join("/tmp", `pensar-worker-${uid}`);
  await mkdir(workerDir, { recursive: true, mode: 0o700 });
  // lstat, not stat: a pre-existing symlink at our dir name must never be
  // followed into another user's files.
  const dirInfo = await lstat(workerDir);
  if (!dirInfo.isDirectory() || dirInfo.uid !== uid) {
    throw new Error("The worker directory is not owned by this user");
  }
  if ((dirInfo.mode & 0o077) !== 0) {
    throw new Error("The worker directory is not private (mode 0700)");
  }

  // Identity comes from the canonical database, never unchecked user text.
  const digest = createHash("sha256")
    .update(`${canonical}\0${runId}`)
    .digest("hex")
    .slice(0, 16);
  const base = path.join(workerDir, `pensar-${digest}`);
  const endpoint = {
    socketPath: `${base}.sock`,
    logPath: `${base}.log`,
    lockDatabasePath: `${base}.lockdb`,
  };
  if (endpoint.socketPath.length > 104) {
    throw new Error(
      `Worker socket path exceeds the OS limit: ${endpoint.socketPath.length} bytes`,
    );
  }
  return endpoint;
}
