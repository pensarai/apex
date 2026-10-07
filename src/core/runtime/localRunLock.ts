import { mkdir, open, realpath, stat } from "node:fs/promises";
import { createRequire } from "node:module";
import path from "node:path";
import type { ExecutionLock, RecoveryEnvironment } from "./runRecoveryStore";
import { RecordedRunSpecSchema } from "./runStore";

// A separate connection holds the per-run lock; process loss releases it.

interface LockDatabase {
  exec(sql: string): void;
  close(): void;
}

const requireModule = createRequire(import.meta.url);

function openLockConnection(filename: string): LockDatabase {
  const mod = requireModule(
    typeof Bun !== "undefined" ? "bun:sqlite" : "node:sqlite",
  ) as {
    Database?: new (p: string) => LockDatabase;
    DatabaseSync?: new (p: string) => LockDatabase;
  };
  const Ctor = mod.Database ?? mod.DatabaseSync;
  if (!Ctor) throw new Error("SQLite runtime is unavailable");
  return new Ctor(filename);
}

export async function acquireLocalRunLock(
  runId: string,
  databasePath: string,
): Promise<ExecutionLock> {
  // Validate the run id before any filesystem access. Admission's schema is
  // the authority — an id it accepts must be a usable lock file component,
  // or an admitted run can never start or resume.
  if (!RecordedRunSpecSchema.shape.runId.safeParse(runId).success) {
    throw new Error(`Run id is not a valid lock file component: ${runId}`);
  }
  // Canonicalize: a symlink-aliased database path must address the same
  // lock file as the real path, or two executors could each "win". The
  // database file may not exist yet on a first claim — create it first.
  const resolved = path.resolve(databasePath);
  await mkdir(path.dirname(resolved), { recursive: true, mode: 0o700 });
  const dbFile = await open(resolved, "a", 0o600);
  await dbFile.close();
  const canonical = await realpath(resolved);
  const filename = `${canonical}.${runId}.lock`;
  const file = await open(filename, "a", 0o600);
  await file.close();

  const db = openLockConnection(filename);
  let released = false;
  try {
    db.exec("PRAGMA busy_timeout = 0");
    db.exec("BEGIN EXCLUSIVE");
  } catch (cause) {
    try {
      db.close();
    } catch {
      // The acquire failure is the one to surface.
    }
    throw new Error(
      `Execution lock for run ${runId} is held by another executor`,
      { cause },
    );
  }
  return {
    runId,
    release() {
      if (released) return;
      released = true;
      try {
        db.exec("ROLLBACK");
      } catch {
        // A dead connection already released the OS lock.
      }
      try {
        db.close();
      } catch {
        // Same: release must never throw.
      }
    },
  };
}

/** Actual filesystem identity for enrollment — never caller-fabricated. */
export async function captureEnvironment(input: {
  databasePath: string;
  cwdPath: string;
  sessionRoot: string;
  runtimeVersion: string;
}): Promise<RecoveryEnvironment> {
  const os = await import("node:os");
  const capture = async (p: string) => {
    const real = await realpath(p);
    const info = await stat(real);
    return { path: real, dev: info.dev, ino: info.ino };
  };
  const [database, cwd, sessionRoot] = await Promise.all([
    capture(input.databasePath),
    capture(input.cwdPath),
    capture(input.sessionRoot),
  ]);
  return {
    runtimeVersion: input.runtimeVersion,
    host: os.hostname(),
    platform: os.platform(),
    arch: os.arch(),
    databasePath: database.path,
    databaseDev: database.dev,
    databaseIno: database.ino,
    cwdPath: cwd.path,
    cwdDev: cwd.dev,
    cwdIno: cwd.ino,
    sessionRootPath: sessionRoot.path,
    sessionRootDev: sessionRoot.dev,
    sessionRootIno: sessionRoot.ino,
  };
}
