import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { PersistentShell } from "./persistentShell";

describe("PersistentShell", () => {
  let shell: PersistentShell;

  beforeEach(() => {
    shell = new PersistentShell();
  });

  afterEach(() => {
    shell.dispose();
  });

  it("should execute simple commands", async () => {
    const result = await shell.execute("echo hello");
    expect(result.exitCode).toBe(0);
    expect(result.stdout.trim()).toBe("hello");
  });

  it("should handle command timeout and recover", async () => {
    const result1 = await shell.execute("sleep 10", 1);
    expect(result1.exitCode).not.toBe(0);

    await new Promise((resolve) => setTimeout(resolve, 100));

    const result2 = await shell.execute("echo after_timeout");
    expect(result2.exitCode).toBe(0);
    expect(result2.stdout.trim()).toBe("after_timeout");
  });

  it("should handle multiple timeouts in sequence and recover", async () => {
    const result1 = await shell.execute("sleep 10", 1);
    expect(result1.exitCode).not.toBe(0);

    await new Promise((resolve) => setTimeout(resolve, 100));

    const result2 = await shell.execute("sleep 10", 1);
    expect(result2.exitCode).not.toBe(0);

    await new Promise((resolve) => setTimeout(resolve, 100));

    const result3 = await shell.execute("echo still_works");
    expect(result3.exitCode).toBe(0);
    expect(result3.stdout.trim()).toBe("still_works");
  });

  it("should handle abort signal and recover", async () => {
    const controller = new AbortController();

    setTimeout(() => controller.abort(), 500);

    const result1 = await shell.execute(
      "sleep 10",
      undefined,
      undefined,
      controller.signal,
    );
    expect(result1.exitCode).not.toBe(0);

    await new Promise((resolve) => setTimeout(resolve, 100));

    const result2 = await shell.execute("echo after_abort");
    expect(result2.exitCode).toBe(0);
    expect(result2.stdout.trim()).toBe("after_abort");
  });

  it("should handle cancelled commands and recover", async () => {
    const promise = shell.execute("sleep 10");

    setTimeout(() => {
      shell.cancelCurrentCommand();
    }, 500);

    const result1 = await promise;
    expect(result1.exitCode).not.toBe(0);

    await new Promise((resolve) => setTimeout(resolve, 100));

    const result2 = await shell.execute("echo after_cancel");
    expect(result2.exitCode).toBe(0);
    expect(result2.stdout.trim()).toBe("after_cancel");
  });

  it("should capture stderr correctly", async () => {
    const result = await shell.execute("echo error_message >&2");
    expect(result.stderr).toContain("error_message");
  });

  it("should report non-zero exit codes", async () => {
    const result = await shell.execute("exit 42");
    expect(result.exitCode).toBe(42);
  });

  it("should handle rapid sequential commands after timeout", async () => {
    const result1 = await shell.execute("sleep 5", 1);
    expect(result1.exitCode).not.toBe(0);

    await new Promise((resolve) => setTimeout(resolve, 100));

    for (let i = 0; i < 5; i++) {
      const result = await shell.execute(`echo iteration_${i}`);
      expect(result.exitCode).toBe(0);
      expect(result.stdout.trim()).toBe(`iteration_${i}`);
    }
  });
});
