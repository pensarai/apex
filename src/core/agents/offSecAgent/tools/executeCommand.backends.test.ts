import { describe, expect, it, vi } from "vitest";
import { LocalBackends } from "../../../tools/backends/local";
import type { CommandEvent, ToolBackends } from "../../../tools/backends/types";
import { type ExecuteCommandResult, executeCommand } from "./executeCommand";
import type { ToolContext } from "./types";

function context(overrides: Partial<ToolContext>): ToolContext {
  return {
    agentCwd: "/tmp/backend-workspace",
    session: {
      id: "ses_backend",
      rootPath: "/tmp/backend-workspace",
      targets: [],
    },
    ...overrides,
  } as ToolContext;
}

async function invoke(
  ctx: ToolContext,
  timeout?: number,
): Promise<ExecuteCommandResult> {
  const execute = executeCommand(ctx).execute;
  if (!execute) throw new Error("executeCommand has no execute operation");
  return (await execute(
    {
      command: "printf ok",
      toolCallDescription: "Verify command execution",
      timeout,
    },
    { toolCallId: "command-1", messages: [] },
  )) as ExecuteCommandResult;
}

function backend(events: CommandEvent[]) {
  const run = vi.fn(async function* () {
    yield* events;
  });
  return { run, backends: { command: { run } } as unknown as ToolBackends };
}

describe("executeCommand backend routing", () => {
  it("uses the supplied backend exclusively, preserving timeout, abort and result metadata", async () => {
    const injected = backend([
      { type: "stdout", seq: 0, bytes: "partial" },
      { type: "stderr", seq: 1, bytes: "interrupted" },
      { type: "end", exitCode: 130, timedOut: false, stdoutTruncated: true },
    ]);
    const legacy = vi.fn();
    const controller = new AbortController();
    const ctx = context({
      backends: injected.backends,
      sandbox: { execute: legacy } as never,
      commandShell: { execute: legacy } as never,
      abortSignal: controller.signal,
    });
    const result = await invoke(ctx);
    expect(legacy).not.toHaveBeenCalled();
    expect(injected.run).toHaveBeenCalledWith(
      "printf ok",
      expect.objectContaining({
        timeoutSeconds: 120,
        abortSignal: controller.signal,
      }),
    );
    expect(result).toMatchObject({
      success: false,
      exitCode: 130,
      error: "Command aborted",
      stdoutTruncated: true,
    });
    expect(result.stdout).toContain("INCOMPLETE");
    expect(result.stderr).toBe("interrupted");
  });

  it("rejects invalid timeouts before invoking an injected backend", async () => {
    const injected = backend([]);
    const result = await invoke(
      context({ backends: injected.backends }),
      30_000,
    );
    expect(result.error).toContain("maximum");
    expect(injected.run).not.toHaveBeenCalled();
  });

  it("does not fall back to a legacy executor when an injected backend fails", async () => {
    const run = vi.fn(async function* (): AsyncGenerator<CommandEvent> {
      yield { type: "start" };
      throw new Error("backend unavailable");
    });
    const legacy = vi.fn();
    const result = await invoke(
      context({
        backends: { command: { run } } as unknown as ToolBackends,
        commandShell: { execute: legacy } as never,
      }),
    );
    expect(result.error).toBe("backend unavailable");
    expect(legacy).not.toHaveBeenCalled();
  });

  it("does not invoke a backend after caller cancellation", async () => {
    const injected = backend([]);
    const controller = new AbortController();
    controller.abort();
    const result = await invoke(
      context({ backends: injected.backends, abortSignal: controller.signal }),
    );
    expect(result.error).toBe("Command aborted by user");
    expect(injected.run).not.toHaveBeenCalled();
  });
});

describe("default command backend compatibility", () => {
  it("keeps sandbox execution remote with working directory and configured environment", async () => {
    const execute = vi.fn(async () => ({
      success: true,
      exitCode: 0,
      stdout: "remote",
      stderr: "",
    }));
    const local = vi.fn();
    const ctx = context({
      sandbox: { execute } as never,
      commandShell: { execute: local } as never,
      environmentVariables: { CUSTOM: "configured" },
    });
    const events: CommandEvent[] = [];
    for await (const event of LocalBackends(ctx).command.run("printf ok", {
      timeoutSeconds: 9,
      envVars: { EXTRA: "per-call" },
    }))
      events.push(event);
    expect(local).not.toHaveBeenCalled();
    expect(execute).toHaveBeenCalledWith(
      "printf ok",
      expect.objectContaining({
        cwd: ctx.agentCwd,
        timeout: 9,
        envVars: expect.objectContaining({
          CUSTOM: "configured",
          EXTRA: "per-call",
        }),
      }),
    );
    expect(events).toContainEqual({ type: "stdout", seq: 0, bytes: "remote" });
  });

  it("forwards local cwd and output completeness", async () => {
    const execute = vi.fn(async () => ({
      exitCode: 0,
      stdout: "bounded",
      stderr: "",
      stdoutTruncated: true,
      stderrTruncated: false,
    }));
    const ctx = context({ commandShell: { execute } as never });
    const events: CommandEvent[] = [];
    for await (const event of LocalBackends(ctx).command.run("printf ok"))
      events.push(event);
    expect(execute).toHaveBeenCalledWith(
      "printf ok",
      expect.objectContaining({ cwd: ctx.agentCwd }),
    );
    expect(events.at(-1)).toMatchObject({
      type: "end",
      stdoutTruncated: true,
      stderrTruncated: false,
    });
  });
});
