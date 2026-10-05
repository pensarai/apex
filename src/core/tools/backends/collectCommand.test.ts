import { describe, expect, it } from "vitest";
import { collectCommand } from "./collectCommand";
import type { CommandEvent } from "./types";

describe("command capture", () => {
  it("bounds retained output while draining the transport to its exit status", async () => {
    let drained = false;
    async function* events(): AsyncGenerator<CommandEvent> {
      yield { type: "stdout", seq: 0, bytes: "x".repeat(1024 * 1024) };
      yield { type: "stdout", seq: 1, bytes: "overflow" };
      yield { type: "stderr", seq: 2, bytes: "failed" };
      drained = true;
      yield { type: "end", exitCode: 7, timedOut: false };
    }
    const result = await collectCommand(events());
    expect(result.stdout.length).toBe(1024 * 1024);
    expect(result).toMatchObject({
      stdoutTruncated: true,
      stderr: "failed",
      exitCode: 7,
    });
    expect(drained).toBe(true);
  });

  it("rejects a transport that never supplies an exit status", async () => {
    async function* events(): AsyncGenerator<CommandEvent> {
      yield { type: "stdout", seq: 0, bytes: "partial" };
    }
    await expect(collectCommand(events())).rejects.toThrow(
      "without an exit status",
    );
  });
});
