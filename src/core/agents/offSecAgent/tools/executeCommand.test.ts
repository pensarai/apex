import { describe, expect, it } from "vitest";
import { StaticPromptInjectionLibrary } from "../../../prompt-injections";
import type { SessionInfo } from "../../../session";
import { inProcessSubagentSpawner } from "../subagentSpawner";
import {
  DEFAULT_COMMAND_TIMEOUT_SECONDS,
  type ExecuteCommandInput,
  type ExecuteCommandResult,
  executeCommand,
  MAX_COMMAND_TIMEOUT_SECONDS,
  normalizeExecuteCommandTimeout,
  normalizePromptInjectionPointer,
  redactSecretValues,
} from "./executeCommand";
import { PersistentShell } from "./persistentShell";
import type { UnifiedSandbox } from "./sandbox";
import type { ToolContext } from "./types";

function makeCtx(overrides: Partial<ToolContext> = {}): ToolContext {
  return {
    subagentSpawner: inProcessSubagentSpawner,
    session: {
      id: "ses_test",
      version: "1.0.0",
      targets: [],
      time: { created: Date.now(), updated: Date.now() },
      rootPath: "/tmp/test",
      logsPath: "/tmp/test/logs",
      findingsPath: "/tmp/test/findings",
      scratchpadPath: "/tmp/test/scratchpad",
      pocsPath: "/tmp/test/pocs",
    } as SessionInfo,
    agentCwd: "/tmp/test",
    ...overrides,
  };
}

describe("normalizeExecuteCommandTimeout", () => {
  it("preserves valid second-based timeouts", () => {
    expect(normalizeExecuteCommandTimeout(30)).toBe(30);
    expect(normalizeExecuteCommandTimeout(120)).toBe(120);
  });

  it("converts obvious millisecond values to seconds", () => {
    expect(normalizeExecuteCommandTimeout(30_000)).toBe(30);
    expect(normalizeExecuteCommandTimeout(100_000)).toBe(100);
    expect(normalizeExecuteCommandTimeout(120_000)).toBe(120);
  });

  it("drops invalid timeout values", () => {
    expect(normalizeExecuteCommandTimeout()).toBeUndefined();
    expect(normalizeExecuteCommandTimeout(0)).toBeUndefined();
    expect(normalizeExecuteCommandTimeout(-5)).toBeUndefined();
    expect(normalizeExecuteCommandTimeout(Number.NaN)).toBeUndefined();
  });
});

describe("normalizePromptInjectionPointer", () => {
  it("passes through a real pointer with a trimmed id", () => {
    const pointer = { id: "pi.real", envVar: "CUSTOM_ENV" };
    expect(normalizePromptInjectionPointer(pointer)).toEqual(pointer);
  });

  it("treats placeholder sentinel ids as omitted", () => {
    for (const id of ["__omit__", "null", "NULL", "undefined", "none", ""]) {
      expect(normalizePromptInjectionPointer({ id })).toBeUndefined();
    }
  });

  it("treats whitespace-only, null, and missing pointers as omitted", () => {
    expect(normalizePromptInjectionPointer({ id: "   " })).toBeUndefined();
    expect(normalizePromptInjectionPointer(undefined)).toBeUndefined();
    expect(normalizePromptInjectionPointer({})).toBeUndefined();
    expect(normalizePromptInjectionPointer({ id: null })).toBeUndefined();
  });
});

describe("executeCommand prompt injection pointer", () => {
  it("runs the command normally when given a placeholder sentinel id", async () => {
    const library = new StaticPromptInjectionLibrary([]);

    let capturedCommand = "";
    const persistentShell = {
      execute: async (command: string) => {
        capturedCommand = command;
        return { exitCode: 0, stdout: "ok", stderr: "" };
      },
    } as unknown as ToolContext["persistentShell"];

    const tool = executeCommand(
      makeCtx({ promptInjectionLibrary: library, persistentShell }),
    );
    const result = (await tool.execute?.(
      {
        command: "echo hello",
        promptInjection: { id: "__omit__" },
        toolCallDescription: "Command with a placeholder prompt-injection id",
      },
      { toolCallId: "tc_test", messages: [], abortSignal: undefined },
    )) as ExecuteCommandResult;

    expect(result.success).toBe(true);
    expect(result.error).toBe("");
    // No env wrapping (no `env ... bash -lc`) means no payload pointer was applied.
    expect(capturedCommand).toBe("echo hello");
  });

  it("passes a payload file path pointer through env vars and redacts echoed payloads", async () => {
    const payload = "TEST PAYLOAD: direct override";
    const payloadFilePath = "/tmp/apex-prompt-library/payloads/direct.txt";
    const library = new StaticPromptInjectionLibrary([
      {
        id: "pi.direct.override",
        name: "Direct Override",
        category: "instruction-hijack",
        description: "Safe metadata for a direct override test.",
        tags: ["baseline"],
        deliveryHints: ["execute-command"],
        expectedObservation: "The system should preserve hierarchy.",
        payload,
        payloadFilePath,
      },
    ]);

    let capturedCommand = "";
    let capturedEnvVars: Record<string, string> | undefined;
    let capturedSandboxFilePath = "";
    let executionCount = 0;
    const sandbox: UnifiedSandbox = {
      type: "linux",
      execute: async (command, opts) => {
        executionCount++;
        // First call writes the payload to a temp file in the sandbox
        if (executionCount === 1) {
          // Extract the temp file path from the write command
          const match = command.match(/> (\/tmp\/apex_payload_\d+\.txt)/);
          if (match) {
            capturedSandboxFilePath = match[1];
          }
          return {
            success: true,
            exitCode: 0,
            stdout: "",
            stderr: "",
          };
        }
        // Second call runs the actual command with env var pointing to sandbox temp file
        capturedCommand = command;
        capturedEnvVars = opts?.envVars;
        return {
          success: true,
          exitCode: 0,
          stdout: `using ${opts?.envVars?.APEX_PROMPT_INJECTION_FILE}: ${payload}`,
          stderr: payload,
        };
      },
    };

    const tool = executeCommand(
      makeCtx({ promptInjectionLibrary: library, sandbox }),
    );
    const command =
      'python3 harness.py --payload-file "$APEX_PROMPT_INJECTION_FILE"';
    const result = (await tool.execute?.(
      {
        command,
        promptInjection: { id: "pi.direct.override" },
        timeout: 5,
        toolCallDescription: "Run a prompt-injection harness",
      },
      { toolCallId: "tc_test", messages: [], abortSignal: undefined },
    )) as ExecuteCommandResult;

    expect(capturedCommand).toBe(command);
    expect(capturedCommand).not.toContain(payloadFilePath);
    // In sandbox mode, env var points to the temp file in the sandbox
    expect(capturedEnvVars).toEqual({
      APEX_PROMPT_INJECTION_FILE: capturedSandboxFilePath,
    });
    expect(capturedSandboxFilePath).toMatch(/^\/tmp\/apex_payload_\d+\.txt$/);
    expect(result.command).toBe(command);
    expect(result.stdout).toContain(capturedSandboxFilePath);
    expect(result.stdout).toContain("[PROMPT_INJECTION:pi.direct.override]");
    expect(result.stdout).not.toContain(payload);
    expect(result.stderr).toBe("[PROMPT_INJECTION:pi.direct.override]");
  });

  it("fails closed when a prompt injection id has no file pointer", async () => {
    const library = new StaticPromptInjectionLibrary([
      {
        id: "pi.memory.only",
        name: "Memory Only",
        category: "instruction-hijack",
        description: "Safe metadata.",
        tags: [],
        deliveryHints: [],
        expectedObservation: "",
        payload: "TEST PAYLOAD",
      },
    ]);

    const tool = executeCommand(makeCtx({ promptInjectionLibrary: library }));
    const result = (await tool.execute?.(
      {
        command: 'cat "$APEX_PROMPT_INJECTION_FILE"',
        promptInjection: { id: "pi.memory.only" },
        toolCallDescription: "Try to use a memory-only payload",
      },
      { toolCallId: "tc_test", messages: [], abortSignal: undefined },
    )) as ExecuteCommandResult;

    expect(result.success).toBe(false);
    expect(result.error).toContain("no payload file path available");
  });

  it("wraps local persistent-shell commands with a runtime file pointer", async () => {
    const payload = "TEST PAYLOAD: shell direct override";
    const payloadFilePath = "/tmp/apex-prompt-library/payloads/shell.txt";
    const library = new StaticPromptInjectionLibrary([
      {
        id: "pi.shell.override",
        name: "Shell Override",
        category: "instruction-hijack",
        description: "Safe metadata for a shell harness test.",
        tags: ["shell"],
        deliveryHints: ["execute-command"],
        expectedObservation: "The system should preserve hierarchy.",
        payload,
        payloadFilePath,
      },
    ]);

    let capturedCommand = "";
    const persistentShell = {
      execute: async (command: string) => {
        capturedCommand = command;
        return {
          exitCode: 0,
          stdout: payload,
          stderr: "",
        };
      },
    } as unknown as ToolContext["persistentShell"];

    const tool = executeCommand(
      makeCtx({ promptInjectionLibrary: library, persistentShell }),
    );
    const command = 'node harness.js "$APEX_PROMPT_INJECTION_FILE"';
    const result = (await tool.execute?.(
      {
        command,
        promptInjection: { id: "pi.shell.override" },
        toolCallDescription: "Run a shell harness with a payload file pointer",
      },
      { toolCallId: "tc_test", messages: [], abortSignal: undefined },
    )) as ExecuteCommandResult;

    expect(capturedCommand).toContain("bash -lc");
    expect(capturedCommand).toContain(payloadFilePath);
    expect(result.command).toBe(command);
    expect(result.command).not.toContain(payloadFilePath);
    expect(result.stdout).toBe("[PROMPT_INJECTION:pi.shell.override]");
  });
});

describe("redactSecretValues", () => {
  it("replaces every occurrence of a known secret", () => {
    expect(
      redactSecretValues("token=s3cr3tvalue s3cr3tvalue", ["s3cr3tvalue"]),
    ).toBe("token=[REDACTED] [REDACTED]");
  });

  it("masks the longer secret first so it isn't left partially exposed", () => {
    // "abcdef" is a substring of "abcdef-longtail"; longest-first must win.
    const out = redactSecretValues("val=abcdef-longtail", [
      "abcdef",
      "abcdef-longtail",
    ]);
    expect(out).toBe("val=[REDACTED]");
    expect(out).not.toContain("longtail");
  });

  it("skips values shorter than 6 chars so they can't corrupt unrelated output", () => {
    expect(redactSecretValues("the cat sat", ["cat"])).toBe("the cat sat");
  });

  it("no-ops when there are no secrets", () => {
    expect(redactSecretValues("nothing to hide", [])).toBe("nothing to hide");
    expect(redactSecretValues("nothing to hide", undefined)).toBe(
      "nothing to hide",
    );
  });
});

// Finite-deadline contract: an omitted timeout must never mean "run until
// completion or abort", and timeout/abort must terminate the real process.
describe("executeCommand deadlines", () => {
  function captureShell() {
    const calls: {
      command: string;
      timeout?: number;
      abortSignal?: AbortSignal;
    }[] = [];
    const persistentShell = {
      execute: async (
        command: string,
        timeout?: number,
        _onData?: (chunk: string) => void,
        abortSignal?: AbortSignal,
      ) => {
        calls.push({ command, timeout, abortSignal });
        return { exitCode: 0, stdout: "ok", stderr: "" };
      },
    } as unknown as ToolContext["persistentShell"];
    return { calls, persistentShell };
  }

  function callTool(
    ctx: ToolContext,
    input: Omit<ExecuteCommandInput, "toolCallDescription"> & {
      command: string;
    },
  ): Promise<unknown> {
    return executeCommand(ctx).execute?.(
      {
        toolCallDescription: "Deadline contract test",
        ...input,
      },
      { toolCallId: "tc_test", messages: [], abortSignal: undefined },
    ) as Promise<unknown>;
  }

  it("applies a finite default timeout when none is provided", async () => {
    const { calls, persistentShell } = captureShell();
    const result = (await callTool(makeCtx({ persistentShell }), {
      command: "echo hello",
    })) as ExecuteCommandResult;

    expect(result.success).toBe(true);
    expect(calls[0]?.timeout).toBe(DEFAULT_COMMAND_TIMEOUT_SECONDS);
  });

  it("clamps an explicit over-max timeout and preserves a valid one", async () => {
    const { calls, persistentShell } = captureShell();
    const ctx = makeCtx({ persistentShell });

    await callTool(ctx, { command: "echo hello", timeout: 700 });
    expect(calls[0]?.timeout).toBe(MAX_COMMAND_TIMEOUT_SECONDS);

    await callTool(ctx, { command: "echo hello", timeout: 30 });
    expect(calls[1]?.timeout).toBe(30);
  });

  it("rejects invalid explicit timeouts instead of running indefinitely", async () => {
    const { calls, persistentShell } = captureShell();
    const ctx = makeCtx({ persistentShell });

    for (const bad of [0, -5]) {
      const result = (await callTool(ctx, {
        command: "echo hello",
        timeout: bad,
      })) as ExecuteCommandResult;
      expect(result.success).toBe(false);
      expect(result.error).toContain("Invalid timeout");
      expect(result.error).toContain(String(bad));
    }
    expect(calls).toHaveLength(0);
  });

  it("terminates real process work on timeout (persistent shell integration)", async () => {
    const shell = new PersistentShell();
    try {
      const result = (await callTool(makeCtx({ persistentShell: shell }), {
        command: "sleep 30",
        timeout: 1,
      })) as ExecuteCommandResult;

      expect(result.success).toBe(false);
      expect(result.error).toBe("Command timed out");
      // The shell survived the kill and is immediately reusable.
      const after = await shell.execute("echo ok", 5);
      expect(after.exitCode).toBe(0);
      expect(after.stdout).toContain("ok");
    } finally {
      shell.dispose();
    }
  }, 8_000);

  it("terminates real process work on caller abort (persistent shell integration)", async () => {
    const shell = new PersistentShell();
    const ac = new AbortController();
    setTimeout(() => ac.abort(), 300);
    try {
      const result = (await callTool(
        makeCtx({ persistentShell: shell, abortSignal: ac.signal }),
        { command: "sleep 30" },
      )) as ExecuteCommandResult;

      expect(result.success).toBe(false);
      expect(result.stderr).toContain("aborted");
      const after = await shell.execute("echo ok", 5);
      expect(after.exitCode).toBe(0);
    } finally {
      shell.dispose();
    }
  }, 8_000);

  it("keeps the payload-file write under its own 30s ceiling for omitted and over-max command timeouts", async () => {
    const library = new StaticPromptInjectionLibrary([
      {
        id: "pi.write.deadline",
        name: "Write Deadline",
        category: "instruction-hijack",
        description: "Safe metadata.",
        tags: [],
        deliveryHints: [],
        expectedObservation: "",
        payload: "TEST PAYLOAD",
        payloadFilePath: "/tmp/apex-prompt-library/payloads/write.txt",
      },
    ]);
    const writeTimeout: (number | undefined)[] = [];
    const commandTimeout: (number | undefined)[] = [];
    const sandbox: UnifiedSandbox = {
      type: "linux",
      execute: async (
        command: string,
        opts?: { timeout?: number; envVars?: Record<string, string> },
      ) => {
        if (command.includes("apex_payload_")) {
          writeTimeout.push(opts?.timeout);
          return { success: true, exitCode: 0, stdout: "", stderr: "" };
        }
        commandTimeout.push(opts?.timeout);
        return { success: true, exitCode: 0, stdout: "ok", stderr: "" };
      },
    };

    const ctx = makeCtx({ promptInjectionLibrary: library, sandbox });

    // Omitted: write gets its own 30s, the command gets the finite default.
    const omitted = (await callTool(ctx, {
      command: 'cat "$APEX_PROMPT_INJECTION_FILE"',
      promptInjection: { id: "pi.write.deadline" },
    })) as ExecuteCommandResult;
    expect(omitted.success).toBe(true);
    expect(writeTimeout).toEqual([30]);
    expect(commandTimeout).toEqual([DEFAULT_COMMAND_TIMEOUT_SECONDS]);

    // Over-max explicit timeout: the command clamps to the hard cap, and the
    // write stays under its 30s ceiling — an explicit value can never loosen it.
    const overmax = (await callTool(ctx, {
      command: 'cat "$APEX_PROMPT_INJECTION_FILE"',
      promptInjection: { id: "pi.write.deadline" },
      timeout: 700,
    })) as ExecuteCommandResult;
    expect(overmax.success).toBe(true);
    expect(writeTimeout).toEqual([30, 30]);
    expect(commandTimeout).toEqual([
      DEFAULT_COMMAND_TIMEOUT_SECONDS,
      MAX_COMMAND_TIMEOUT_SECONDS,
    ]);
  });
});
