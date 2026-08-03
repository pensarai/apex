import { mkdtemp, rm } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { describe, expect, it } from "vitest";
import { withAuthRefreshLock } from "./refresh-lock";

describe("withAuthRefreshLock", () => {
  it("serializes refresh work across callers", async () => {
    const homeDir = await mkdtemp(path.join(os.tmpdir(), "apex-auth-lock-"));
    const events: string[] = [];
    let releaseFirst: () => void = () => {};
    const firstCanFinish = new Promise<void>((resolve) => {
      releaseFirst = resolve;
    });
    let markFirstStarted: () => void = () => {};
    const firstStarted = new Promise<void>((resolve) => {
      markFirstStarted = resolve;
    });

    try {
      const first = withAuthRefreshLock(
        async () => {
          events.push("first:start");
          markFirstStarted();
          await firstCanFinish;
          events.push("first:end");
        },
        { homeDir, retryMs: 5 },
      );
      await firstStarted;
      const second = withAuthRefreshLock(
        async () => {
          events.push("second:start");
          events.push("second:end");
        },
        { homeDir, retryMs: 5 },
      );

      releaseFirst();
      await Promise.all([first, second]);
      expect(events).toEqual([
        "first:start",
        "first:end",
        "second:start",
        "second:end",
      ]);
    } finally {
      await rm(homeDir, { force: true, recursive: true });
    }
  });
});
