import { afterAll, describe, expect, it } from "vitest";

import { PersistentShell } from "./persistentShell";

/**
 * Isolated from persistentShell.test.ts: this case blocks the event loop on
 * purpose, and that file has concurrent tests with upper-bound timing
 * assertions. Vitest runs each file in its own worker, so the block stays here.
 *
 * The bug: stdout and stderr are separate pipes with no delivery ordering
 * between them. The wrapper writes the command's stderr on fd2 and the exit
 * marker on fd1; when libuv serviced the stdout handle first, `onStdoutData`
 * resolved the call with an empty stderr and the fd2 bytes were dropped on the
 * floor (`this.current` was already null). Under CI load this flaked ~1 run in
 * 20. Blocking the loop while both pipes hold queued bytes makes it fire every
 * time — 10/10 before the disk-read fix, 0/10 after.
 */
describe("PersistentShell — stderr/stdout pipe ordering", () => {
  const shells: PersistentShell[] = [];
  afterAll(() => {
    for (const shell of shells) shell.dispose();
  });

  it("keeps stderr when the exit marker wins the race to the event loop", async () => {
    const shell = new PersistentShell();
    shells.push(shell);

    for (let i = 0; i < 3; i++) {
      const a = shell.execute(">&2 echo apex-call-a-stderr", 5);
      const b = shell.execute("echo apex-call-b-stdout", 5);

      // Let both commands reach the shell, then stall libuv so the wrapper
      // finishes and both pipes hold readable bytes at the same moment.
      await new Promise((resolve) => setTimeout(resolve, 40));
      const until = Date.now() + 120;
      while (Date.now() < until) {
        /* block */
      }

      const [ra, rb] = await Promise.all([a, b]);
      expect(ra.exitCode).toBe(0);
      expect(rb.exitCode).toBe(0);
      expect(ra.stderr).toContain("apex-call-a-stderr");
      expect(rb.stderr).not.toContain("apex-call-a-stderr");
      expect(rb.stdout).toContain("apex-call-b-stdout");
    }
  }, 30_000);
});
