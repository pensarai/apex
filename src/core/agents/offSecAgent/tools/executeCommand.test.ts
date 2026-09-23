import { describe, expect, it } from "vitest";
import { StaticPromptInjectionLibrary } from "../../../prompt-injections";
import type { SessionInfo } from "../../../session";
import {
  normalizeExecuteCommandTimeout,
  redactSecretValues,
} from "../../../tools/backends/helpers";
import { ToolPolicyDeniedError } from "../../../tools/backends/policy";
import type {
  CommandEvent,
  RunOpts,
  ToolBackends,
} from "../../../tools/backends/types";
import { inProcessSubagentSpawner } from "../subagentSpawner";
import {
  type ExecuteCommandResult,
  executeCommand,
  normalizePromptInjectionPointer,
} from "./executeCommand";
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

  it("passes a payload file path pointer through env vars against the command backend", async () => {
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
    const persistentShell = {
      execute: async (command: string) => {
        capturedCommand = command;
        return {
          exitCode: 0,
          stdout: `using ${payloadFilePath}: ${payload}`,
          stderr: payload,
        };
      },
    } as unknown as ToolContext["persistentShell"];

    const tool = executeCommand(
      makeCtx({ promptInjectionLibrary: library, persistentShell }),
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

    expect(capturedCommand).toContain("bash -lc");
    expect(capturedCommand).toContain(payloadFilePath);
    expect(result.command).toBe(command);
    expect(result.command).not.toContain(payloadFilePath);
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

describe("executeCommand routes through the injected command backend", () => {
  function fakeBackends(events: CommandEvent[]): {
    backends: ToolBackends;
    calls: Array<{ cmd: string; opts?: RunOpts }>;
  } {
    const calls: Array<{ cmd: string; opts?: RunOpts }> = [];
    const backends = {
      command: {
        async *run(cmd: string, opts?: RunOpts) {
          calls.push({ cmd, opts });
          for (const event of events) yield event;
        },
      },
    } as unknown as ToolBackends;
    return { backends, calls };
  }

  it("calls backends.command.run with the command and timeout, no persistentShell/sandbox reference", async () => {
    const { backends, calls } = fakeBackends([
      { type: "start" },
      { type: "stdout", seq: 0, bytes: "hello from backend" },
      { type: "end", exitCode: 0, timedOut: false },
    ]);

    const tool = executeCommand(makeCtx({ backends }));
    const result = (await tool.execute?.(
      { command: "echo hello", timeout: 5, toolCallDescription: "d" },
      { toolCallId: "tc", messages: [], abortSignal: undefined },
    )) as ExecuteCommandResult;

    expect(calls).toHaveLength(1);
    expect(calls[0].cmd).toBe("echo hello");
    expect(calls[0].opts?.timeoutSeconds).toBe(5);
    expect(result).toEqual({
      success: true,
      error: "",
      stdout: "hello from backend",
      stderr: "",
      command: "echo hello",
      outputFile: undefined,
    });
  });

  it("surfaces a timeout signaled by the backend", async () => {
    const { backends } = fakeBackends([
      { type: "start" },
      { type: "end", exitCode: 124, timedOut: true },
    ]);
    const tool = executeCommand(makeCtx({ backends }));
    const result = (await tool.execute?.(
      { command: "sleep 100", toolCallDescription: "d" },
      { toolCallId: "tc", messages: [], abortSignal: undefined },
    )) as ExecuteCommandResult;

    expect(result.success).toBe(false);
    expect(result.error).toBe("Command timed out");
  });

  it("surfaces a ToolPolicy denial as a failed result", async () => {
    const backends = {
      command: {
        // biome-ignore lint/correctness/useYield: the generator must throw before its first event
        async *run() {
          throw new ToolPolicyDeniedError("command", "run", "out of scope");
        },
      },
    } as unknown as ToolBackends;

    const tool = executeCommand(makeCtx({ backends }));
    const result = (await tool.execute?.(
      { command: "curl http://evil.example.com", toolCallDescription: "d" },
      { toolCallId: "tc", messages: [], abortSignal: undefined },
    )) as ExecuteCommandResult;

    expect(result.success).toBe(false);
    expect(result.error).toBe("out of scope");
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
