import { describe, expect, it } from "vitest";
import { StaticPromptInjectionLibrary } from "../../../prompt-injections";
import type { SessionInfo } from "../../../session";
import {
  type ExecuteCommandResult,
  executeCommand,
  normalizeExecuteCommandTimeout,
} from "./executeCommand";
import type { UnifiedSandbox } from "./sandbox";
import type { ToolContext } from "./types";

function makeCtx(overrides: Partial<ToolContext> = {}): ToolContext {
  return {
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

describe("executeCommand prompt injection pointer", () => {
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
    const sandbox: UnifiedSandbox = {
      type: "linux",
      execute: async (command, opts) => {
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
    const result = (await tool.execute!(
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
    expect(capturedEnvVars).toEqual({
      APEX_PROMPT_INJECTION_FILE: payloadFilePath,
    });
    expect(result.command).toBe(command);
    expect(result.stdout).toContain(payloadFilePath);
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
    const result = (await tool.execute!(
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
    const result = (await tool.execute!(
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
