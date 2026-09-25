import { describe, expect, test } from "vitest";
import type { UnifiedSandbox } from "./sandbox";
import { serializeSandboxBrowserAction } from "./sandboxPlaywright";

const delay = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

describe("serializeSandboxBrowserAction", () => {
  test("serializes actions across independent callers sharing a sandbox", async () => {
    const sandbox = {} as UnifiedSandbox;
    let active = 0;
    let peak = 0;
    const order: string[] = [];

    const run = (name: string) =>
      serializeSandboxBrowserAction(sandbox, async () => {
        active += 1;
        peak = Math.max(peak, active);
        order.push(`${name}:start`);
        await delay(5);
        order.push(`${name}:end`);
        active -= 1;
      });

    await Promise.all([run("parent"), run("worker")]);

    expect(peak).toBe(1);
    expect(order).toEqual([
      "parent:start",
      "parent:end",
      "worker:start",
      "worker:end",
    ]);
  });

  test("continues the queue after a failed browser action", async () => {
    const sandbox = {} as UnifiedSandbox;
    const failed = serializeSandboxBrowserAction(sandbox, async () => {
      throw new Error("browser crashed");
    });
    const recovered = serializeSandboxBrowserAction(
      sandbox,
      async () => "recovered",
    );

    await expect(failed).rejects.toThrow("browser crashed");
    await expect(recovered).resolves.toBe("recovered");
  });
});
