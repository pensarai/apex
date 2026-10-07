import { mkdtempSync, rmSync } from "node:fs";
import { mkdir, open, stat, symlink } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { resolveWorkerEndpoint } from "./localWorkerEndpoint";

// Endpoint tests stay implementation-agnostic: they pin the frozen
// observable contract (determinism, canonicalization, validation, private
// owned locations, path bounds) without assuming root's directory scheme.

let tempRoot: string;

beforeEach(() => {
  tempRoot = mkdtempSync(path.join(tmpdir(), "worker-endpoint-"));
});

afterEach(async () => {
  rmSync(tempRoot, { recursive: true, force: true });
});

async function makeDatabase(name = "runs.sqlite"): Promise<string> {
  const file = path.join(tempRoot, name);
  const handle = await open(file, "a", 0o600);
  await handle.close();
  return file;
}

describe("resolveWorkerEndpoint validation", () => {
  it("rejects a missing database, a relative path, and a malformed run id", async () => {
    await expect(
      resolveWorkerEndpoint(path.join(tempRoot, "absent.sqlite"), "run_ok"),
    ).rejects.toThrow();
    await expect(
      resolveWorkerEndpoint("relative/runs.sqlite", "run_ok"),
    ).rejects.toThrow(/absolute/i);
    await expect(
      resolveWorkerEndpoint(await makeDatabase(), "bad id with spaces"),
    ).rejects.toThrow();
    await expect(
      resolveWorkerEndpoint(await makeDatabase(), "../escape"),
    ).rejects.toThrow();
  });

  it("rejects a database path that is not a regular file", async () => {
    const directory = path.join(tempRoot, "as-directory");
    await mkdir(directory, { recursive: true });
    await expect(resolveWorkerEndpoint(directory, "run_ok")).rejects.toThrow(
      /regular file|not a file/i,
    );
  });

  it("resolves only through a genuine owned directory, never a symlink", async () => {
    const database = await makeDatabase();
    const endpoint = await resolveWorkerEndpoint(database, "run_dir");
    const dir = path.dirname(endpoint.socketPath);
    // lstat, not stat: the endpoint directory itself must be a real
    // directory owned by this user, not a link into another location.
    const info = await import("node:fs/promises").then((m) => m.lstat(dir));
    expect(info.isSymbolicLink()).toBe(false);
    expect(info.isDirectory()).toBe(true);
  });
});

describe("resolveWorkerEndpoint identity", () => {
  it("is deterministic per canonical database and run id", async () => {
    const database = await makeDatabase();
    const first = await resolveWorkerEndpoint(database, "run_alpha");
    const second = await resolveWorkerEndpoint(database, "run_alpha");
    const other = await resolveWorkerEndpoint(database, "run_beta");
    expect(second).toEqual(first);
    expect(other.socketPath).not.toBe(first.socketPath);
    expect(other.logPath).not.toBe(first.logPath);
    expect(other.lockDatabasePath).not.toBe(first.lockDatabasePath);
  });

  it("resolves every run id length admission permits, including 65 and 66 bytes", async () => {
    const database = await makeDatabase();
    // Admission (RecordedRunSpecSchema) accepts run_ plus 1-62 chars, up
    // to 66 bytes; the endpoint must accept exactly that set or an
    // admitted run can never host a worker.
    for (const runId of [
      "run_alpha",
      `run_${"a".repeat(61)}`,
      `run_${"b".repeat(62)}`,
    ]) {
      const endpoint = await resolveWorkerEndpoint(database, runId);
      expect(endpoint.socketPath.length).toBeLessThanOrEqual(104);
    }
    await expect(
      resolveWorkerEndpoint(database, `run_${"c".repeat(63)}`),
    ).rejects.toThrow(/endpoint component/i);
  });

  it("canonicalizes a symlinked database path to the same endpoint", async () => {
    const database = await makeDatabase();
    const alias = path.join(tempRoot, "alias.sqlite");
    await symlink(database, alias, "file");
    const direct = await resolveWorkerEndpoint(database, "run_alias");
    const throughAlias = await resolveWorkerEndpoint(alias, "run_alias");
    expect(throughAlias).toEqual(direct);
  });

  it("derives the host lock from a path distinct from the run database", async () => {
    const database = path.resolve(await makeDatabase());
    const endpoint = await resolveWorkerEndpoint(database, "run_lock");
    // acquireLocalRunLock appends `.<runId>.lock` to its database argument;
    // the host lock file must never collide with the execution lock file.
    expect(`${endpoint.lockDatabasePath}.run_lock.lock`).not.toBe(
      `${database}.run_lock.lock`,
    );
    expect(endpoint.lockDatabasePath).not.toBe(database);
  });
});

describe("resolveWorkerEndpoint privacy and bounds", () => {
  it("places all three files together in a private owned directory", async () => {
    const database = await makeDatabase();
    const endpoint = await resolveWorkerEndpoint(database, "run_priv");
    const dir = path.dirname(endpoint.socketPath);
    expect(path.dirname(endpoint.logPath)).toBe(dir);
    expect(path.dirname(endpoint.lockDatabasePath)).toBe(dir);

    const info = await stat(dir);
    const uid = process.getuid?.();
    if (uid !== undefined) {
      expect(info.uid).toBe(uid);
    }
    expect(info.mode & 0o077).toBe(0);
  });

  it("keeps the socket path inside the OS bound", async () => {
    const database = await makeDatabase();
    const endpoint = await resolveWorkerEndpoint(database, "run_bound");
    expect(endpoint.socketPath.length).toBeLessThanOrEqual(104);
  });

  it("never embeds the run id or database path verbatim in file names", async () => {
    const database = await makeDatabase("secret-database-name.sqlite");
    const endpoint = await resolveWorkerEndpoint(database, "run_secret");
    const name = path.basename(endpoint.socketPath);
    expect(name).not.toContain("run_secret");
    expect(name).not.toContain("secret-database-name");
  });
});
