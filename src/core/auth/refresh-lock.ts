import { chmod, mkdir, open, readFile, rm, stat } from "node:fs/promises";
import os from "node:os";
import path from "node:path";

const LOCK_RETRY_MS = 50;
const LOCK_TIMEOUT_MS = 35_000;
const STALE_LOCK_MS = 30_000;

interface RefreshLockOptions {
  homeDir?: string;
  now?: () => number;
  retryMs?: number;
  staleMs?: number;
  timeoutMs?: number;
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

export async function withAuthRefreshLock<T>(
  action: () => Promise<T>,
  options: RefreshLockOptions = {},
): Promise<T> {
  const homeDir = options.homeDir ?? os.homedir();
  const pensarDir = path.join(homeDir, ".pensar");
  const lockPath = path.join(pensarDir, "auth-refresh.lock");
  const now = options.now ?? Date.now;
  const retryMs = options.retryMs ?? LOCK_RETRY_MS;
  const staleMs = options.staleMs ?? STALE_LOCK_MS;
  const timeoutMs = options.timeoutMs ?? LOCK_TIMEOUT_MS;
  const deadline = now() + timeoutMs;

  await mkdir(pensarDir, { recursive: true, mode: 0o700 });
  await chmod(pensarDir, 0o700).catch(() => {});

  while (true) {
    try {
      const handle = await open(lockPath, "wx", 0o600);
      const pid = process.pid;
      try {
        await handle.writeFile(JSON.stringify({ pid, createdAt: now() }));
        return await action();
      } finally {
        await handle.close().catch(() => {});
        // Only remove if we still own it
        try {
          const content = await readFile(lockPath, "utf8");
          const lock = JSON.parse(content) as { pid: number };
          if (lock.pid === pid) {
            await rm(lockPath, { force: true }).catch(() => {});
          }
        } catch {
          // Lock was already removed or is unreadable
        }
      }
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "EEXIST") throw error;

      const lockStat = await stat(lockPath).catch(() => null);
      if (lockStat && now() - lockStat.mtimeMs > staleMs) {
        await rm(lockPath, { force: true }).catch(() => {});
        continue;
      }
      if (now() >= deadline) {
        throw new Error(
          "Timed out waiting for another Apex process to refresh auth",
        );
      }
      await sleep(retryMs);
    }
  }
}
