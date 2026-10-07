import {
  mkdtempSync,
  readFileSync,
  rmSync,
  unlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { asSchema } from "ai";
import { describe, expect, it, vi } from "vitest";
import { StaticPromptInjectionLibrary } from "../../../prompt-injections";
import type { SessionInfo } from "../../../session";
import { LocalBackends } from "../../../tools/backends/local";
import { inProcessSubagentSpawner } from "../subagentSpawner";
import {
  DEFAULT_COMMAND_TIMEOUT_SECONDS,
  type ExecuteCommandInput,
  type ExecuteCommandResult,
  executeCommand,
  MAX_COMMAND_TIMEOUT_SECONDS,
  normalizePromptInjectionPointer,
  redactSecretValues,
  resolveExecuteCommandTimeoutInput,
  validateExecuteCommandTimeout,
} from "./executeCommand";
import { PerCommandShell } from "./perCommandShell";
import type { UnifiedSandbox } from "./sandbox";
import { toolOutputForModel } from "./toolOutput";
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

describe("validateExecuteCommandTimeout", () => {
  it("preserves valid second-based timeouts", () => {
    expect(validateExecuteCommandTimeout(30)).toEqual({
      ok: true,
      seconds: 30,
    });
    expect(validateExecuteCommandTimeout(120)).toEqual({
      ok: true,
      seconds: 120,
    });
    expect(validateExecuteCommandTimeout(MAX_COMMAND_TIMEOUT_SECONDS)).toEqual({
      ok: true,
      seconds: MAX_COMMAND_TIMEOUT_SECONDS,
    });
  });

  it("rejects millisecond-style values as over-max — never reinterpreted", () => {
    const ms = validateExecuteCommandTimeout(30_000);
    expect(ms.ok).toBe(false);
    if (!ms.ok) expect(ms.error).toContain("maximum");
  });

  it("rejects invalid timeout values", () => {
    for (const bad of [
      0,
      -5,
      Number.NaN,
      Number.POSITIVE_INFINITY,
      601,
      30_000,
    ]) {
      const r = validateExecuteCommandTimeout(bad);
      expect(r.ok).toBe(false);
      if (!r.ok) expect(r.error).toContain("Invalid timeout");
    }
  });
});

describe("executeCommand payload pointer via per-invocation env", () => {
  it("passes a runtime payload file pointer as per-invocation env, not a wrapped command", async () => {
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
    let capturedEnv: Record<string, string> | undefined;
    const commandShell = {
      execute: async (
        command: string,
        opts?: { env?: Record<string, string> },
      ) => {
        capturedCommand = command;
        capturedEnv = opts?.env;
        return {
          exitCode: 0,
          stdout: payload,
          stderr: "",
        };
      },
    } as unknown as ToolContext["commandShell"];

    const tool = executeCommand(
      makeCtx({ promptInjectionLibrary: library, commandShell }),
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

    // The command runs verbatim — the pointer rides as per-invocation env.
    expect(capturedCommand).toBe(command);
    expect(capturedCommand).not.toContain(payloadFilePath);
    expect(capturedEnv).toEqual({
      APEX_PROMPT_INJECTION_FILE: payloadFilePath,
    });
    expect(result.command).toBe(command);
    expect(result.stdout).toBe("[PROMPT_INJECTION:pi.shell.override]");
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
    const commandShell = {
      execute: async (command: string) => {
        capturedCommand = command;
        return { exitCode: 0, stdout: "ok", stderr: "" };
      },
    } as unknown as ToolContext["commandShell"];

    const tool = executeCommand(
      makeCtx({ promptInjectionLibrary: library, commandShell }),
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
    const sandbox: UnifiedSandbox = {
      type: "linux",
      execute: async (command, opts) => {
        if (opts?.envVars?.APEX_HIDDEN_PAYLOAD_COUNT) {
          const fileEnv = opts.envVars;
          const encoded = Array.from(
            { length: Number(fileEnv.APEX_HIDDEN_PAYLOAD_COUNT) },
            (_, i) => fileEnv[`APEX_HIDDEN_PAYLOAD_${i}`],
          ).join("");
          expect(Buffer.from(encoded, "base64").toString()).toBe(payload);
          expect(command).not.toContain(payload);
          capturedSandboxFilePath = command.match(
            /\/tmp\/apex_payload_[a-f0-9-]+\.txt/,
          )![0];
          return {
            success: true,
            exitCode: 0,
            stdout: capturedSandboxFilePath,
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
    expect(capturedSandboxFilePath).toMatch(
      /^\/tmp\/apex_payload_[a-f0-9-]+\.txt$/,
    );
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
      opts?: {
        cwd?: string;
        env?: Record<string, string>;
        timeoutSeconds?: number;
        abortSignal?: AbortSignal;
      };
    }[] = [];
    const commandShell = {
      execute: async (command: string, opts?: unknown) => {
        calls.push({ command, opts: opts as never });
        return {
          exitCode: 0,
          stdout: "ok",
          stderr: "",
          timedOut: false,
          stdoutTruncated: false,
          stderrTruncated: false,
          cleanupUnconfirmed: false,
        };
      },
    } as unknown as ToolContext["commandShell"];
    return { calls, commandShell };
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

  it("applies a finite default timeout and the agent cwd when none is provided", async () => {
    const { calls, commandShell } = captureShell();
    const result = (await callTool(
      makeCtx({ commandShell, agentCwd: "/workspace/session" }),
      { command: "echo hello" },
    )) as ExecuteCommandResult;

    expect(result.success).toBe(true);
    expect(calls[0]?.opts?.timeoutSeconds).toBe(
      DEFAULT_COMMAND_TIMEOUT_SECONDS,
    );
    expect(calls[0]?.opts?.cwd).toBe("/workspace/session");
  });

  it("preserves a valid explicit timeout and passes per-invocation env through", async () => {
    const { calls, commandShell } = captureShell();
    const ctx = makeCtx({ commandShell });

    await callTool(ctx, { command: "echo hello", timeout: 30 });
    expect(calls[0]?.opts?.timeoutSeconds).toBe(30);
  });

  it("rejects invalid and over-max explicit timeouts instead of clamping or reinterpreting", async () => {
    const { calls, commandShell } = captureShell();
    const ctx = makeCtx({ commandShell });

    for (const bad of [0, -5, 700, 30_000]) {
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

  it("maps runner outcomes: 124 times out, 130 aborts, truncation is labeled INCOMPLETE", async () => {
    const outcomes: Array<{
      runner: {
        exitCode: number;
        stdout: string;
        stderr: string;
        timedOut: boolean;
        stdoutTruncated: boolean;
        stderrTruncated: boolean;
        cleanupUnconfirmed: boolean;
      };
      expectError: string;
    }> = [
      {
        runner: {
          exitCode: 124,
          stdout: "partial",
          stderr: "",
          timedOut: true,
          stdoutTruncated: false,
          stderrTruncated: false,
          cleanupUnconfirmed: false,
        },
        expectError: "Command timed out",
      },
      {
        runner: {
          exitCode: 130,
          stdout: "partial",
          stderr: "(aborted)",
          timedOut: false,
          stdoutTruncated: false,
          stderrTruncated: false,
          cleanupUnconfirmed: false,
        },
        expectError: "Command aborted",
      },
    ];
    for (const { runner, expectError } of outcomes) {
      const commandShell = {
        execute: async () => runner,
      } as unknown as ToolContext["commandShell"];
      const result = (await callTool(makeCtx({ commandShell }), {
        command: "sleep 30",
        timeout: 1,
      })) as ExecuteCommandResult;
      expect(result.success).toBe(false);
      expect(result.error).toBe(expectError);
    }

    // Capped capture is never labeled full output — inline or spill file.
    const truncatedRunner = {
      execute: async () => ({
        exitCode: 0,
        stdout: "x".repeat(60_000),
        stderr: "y".repeat(60_000),
        timedOut: false,
        stdoutTruncated: true,
        stderrTruncated: true,
        cleanupUnconfirmed: false,
      }),
    } as unknown as ToolContext["commandShell"];
    const truncated = (await callTool(
      makeCtx({ commandShell: truncatedRunner }),
      {
        command: "verbose-tool",
      },
    )) as ExecuteCommandResult;
    expect(truncated.success).toBe(true);
    expect(truncated.stdout).toContain("INCOMPLETE");
    expect(truncated.stdout).not.toContain("full output saved");
    expect(truncated.stderr).toContain("INCOMPLETE");
  });

  it.each([
    true,
    false,
  ])("preserves capture completeness when saving fails (capped: %s)", async (stdoutTruncated) => {
    const logsPath = mkdtempSync(join(tmpdir(), "apex-save-failure-"));
    try {
      // An existing file at the output directory makes the spill write fail.
      writeFileSync(join(logsPath, "tool-output"), "occupied");
      const ctx = makeCtx({
        commandShell: {
          execute: async () => ({
            exitCode: 0,
            stdout: "x".repeat(60_000),
            stderr: "",
            timedOut: false,
            stdoutTruncated,
            stderrTruncated: false,
            cleanupUnconfirmed: false,
          }),
        } as unknown as ToolContext["commandShell"],
      });
      ctx.session.logsPath = logsPath;
      const result = (await callTool(ctx, {
        command: "verbose-tool",
      })) as ExecuteCommandResult;

      expect(result.success).toBe(true);
      expect(result.stdout).toContain("x".repeat(60_000));
      const projected = await toolOutputForModel(ctx, result);
      expect(projected.type).toBe("text");
      const text = String(projected.value);
      expect(text).toContain("Failed to save captured result");
      expect(text).not.toMatch(/tool-output:[0-9a-f-]+/);
      expect(Buffer.byteLength(text)).toBeLessThanOrEqual(50 * 1024);
      expect(text).toContain(
        stdoutTruncated
          ? "capture=INCOMPLETE"
          : "capture=as returned by executor",
      );
    } finally {
      rmSync(logsPath, { recursive: true, force: true });
    }
  });

  it("terminates real process work on timeout (per-command executor integration)", async () => {
    const shell = new PerCommandShell();
    try {
      const result = (await callTool(
        makeCtx({ commandShell: shell, agentCwd: process.cwd() }),
        { command: "sleep 30", timeout: 0.5 },
      )) as ExecuteCommandResult;

      expect(result.success).toBe(false);
      expect(result.error).toBe("Command timed out");
      // The executor survived the kill and is immediately reusable.
      const after = await shell.execute("echo ok", { timeoutSeconds: 5 });
      expect(after.exitCode).toBe(0);
      expect(after.stdout).toContain("ok");
    } finally {
      await shell.dispose();
    }
  }, 8_000);

  it("terminates real process work on caller abort (per-command executor integration)", async () => {
    const shell = new PerCommandShell();
    const ac = new AbortController();
    setTimeout(() => ac.abort(), 300);
    try {
      const result = (await callTool(
        makeCtx({
          commandShell: shell,
          abortSignal: ac.signal,
          agentCwd: process.cwd(),
        }),
        { command: "sleep 30" },
      )) as ExecuteCommandResult;

      expect(result.success).toBe(false);
      expect(result.stderr).toContain("aborted");
      const after = await shell.execute("echo ok", { timeoutSeconds: 5 });
      expect(after.exitCode).toBe(0);
    } finally {
      await shell.dispose();
    }
  }, 10_000);

  it("keeps the payload-file write under its own 30s ceiling", async () => {
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
        _command: string,
        opts?: { timeout?: number; envVars?: Record<string, string> },
      ) => {
        if (opts?.envVars?.APEX_HIDDEN_PAYLOAD_COUNT) {
          expect(opts.timeout).toBeLessThanOrEqual(30);
          writeTimeout.push(opts.timeout);
          return {
            success: true,
            exitCode: 0,
            stdout: "/tmp/apex_payload_test.txt",
            stderr: "",
          };
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

    // Valid explicit timeout: the write is tightened to it.
    const explicit = (await callTool(ctx, {
      command: 'cat "$APEX_PROMPT_INJECTION_FILE"',
      promptInjection: { id: "pi.write.deadline" },
      timeout: 10,
    })) as ExecuteCommandResult;
    expect(explicit.success).toBe(true);
    expect(writeTimeout).toEqual([30, 10]);
    expect(commandTimeout).toEqual([DEFAULT_COMMAND_TIMEOUT_SECONDS, 10]);
  });

  it("sandbox dispatch passes explicit cwd and approved env with per-agent config overriding the workspace blob", async () => {
    process.env.PENSAR_AGENT_ENV_VARS = JSON.stringify({
      WORKSPACE_VAR: "workspace-value",
      SHARED_VAR: "workspace-shared",
    });
    const calls: Array<{
      command: string;
      opts?: {
        cwd?: string;
        envVars?: Record<string, string>;
        timeout?: number;
      };
    }> = [];
    const sandbox: UnifiedSandbox = {
      type: "linux",
      execute: async (
        command: string,
        opts?: {
          cwd?: string;
          envVars?: Record<string, string>;
          timeout?: number;
        },
      ) => {
        calls.push({ command, opts });
        return { success: true, exitCode: 0, stdout: "ok", stderr: "" };
      },
    };
    try {
      const ctx = makeCtx({
        sandbox,
        agentCwd: "/workspace/session",
        environmentVariables: {
          AGENT_VAR: "agent-value",
          SHARED_VAR: "agent-shared",
        },
      });
      const result = (await callTool(ctx, {
        command: "echo hello",
      })) as ExecuteCommandResult;

      expect(result.success).toBe(true);
      expect(calls[0]?.opts?.cwd).toBe("/workspace/session");
      expect(calls[0]?.opts?.timeout).toBe(DEFAULT_COMMAND_TIMEOUT_SECONDS);
      expect(calls[0]?.opts?.envVars).toEqual({
        WORKSPACE_VAR: "workspace-value",
        AGENT_VAR: "agent-value",
        // Per-agent configured env overrides the workspace blob.
        SHARED_VAR: "agent-shared",
      });
    } finally {
      delete process.env.PENSAR_AGENT_ENV_VARS;
    }
  });
});

it.skipIf(process.platform === "win32")(
  "stages injected payloads outside readable files and redacts harness output",
  async () => {
    const root = mkdtempSync(join(tmpdir(), "apex-hidden-payload-"));
    const payload = "INERT SECRET PAYLOAD FOR RETRIEVAL TEST";
    const library = new StaticPromptInjectionLibrary([
      {
        id: "pi.hidden",
        name: "Hidden",
        category: "instruction-hijack",
        description: "test",
        tags: [],
        deliveryHints: [],
        expectedObservation: "",
        payload,
      },
    ]);
    const ctx = makeCtx({
      agentCwd: root,
      fileWorkspaceRoot: root,
      promptInjectionLibrary: library,
    });
    const local = LocalBackends(ctx);
    const run = local.command.run;
    let stagedPath = "";
    const write = vi.fn(async () => {
      throw new Error("payload must not enter readable filesystem backend");
    });
    ctx.backends = {
      ...local,
      sandboxed: true,
      fs: { ...local.fs, write },
      command: {
        ...local.command,
        async *run(command, options) {
          stagedPath =
            options?.envVars?.APEX_PROMPT_INJECTION_FILE ?? stagedPath;
          yield* run(command, options);
        },
      },
    };
    try {
      const result = await executeCommand(ctx).execute?.(
        {
          command: 'cat "$APEX_PROMPT_INJECTION_FILE"',
          promptInjection: { id: "pi.hidden" },
          toolCallDescription: "Verify hidden payload routing",
        },
        { toolCallId: "hidden", messages: [] },
      );
      expect(result).toMatchObject({
        success: true,
        stdout: "[PROMPT_INJECTION:pi.hidden]",
      });
      expect(stagedPath).toMatch(/^\/tmp\/apex_payload_[a-f0-9-]+\.txt$/);
      expect(readFileSync(stagedPath, "utf8")).toBe(payload);
      await expect(ctx.backends.fs.read(stagedPath)).resolves.toMatchObject({
        success: false,
      });
      expect(write).not.toHaveBeenCalled();
    } finally {
      if (stagedPath) unlinkSync(stagedPath);
      rmSync(root, { recursive: true, force: true });
    }
  },
);

describe("resolveExecuteCommandTimeoutInput", () => {
  it("resolves canonical, legacy, and null-inactive inputs before the default", () => {
    expect(resolveExecuteCommandTimeoutInput({ timeoutSeconds: 30 })).toEqual({
      ok: true,
      seconds: 30,
    });
    expect(resolveExecuteCommandTimeoutInput({ timeout: 45 })).toEqual({
      ok: true,
      seconds: 45,
    });
    // Null is an inactive spelling, not a value that fights the other alias.
    expect(
      resolveExecuteCommandTimeoutInput({ timeoutSeconds: null, timeout: 60 }),
    ).toEqual({ ok: true, seconds: 60 });
    expect(
      resolveExecuteCommandTimeoutInput({ timeoutSeconds: 75, timeout: null }),
    ).toEqual({ ok: true, seconds: 75 });
    // Equal aliases agree on one deadline — accepted, not treated as a conflict.
    expect(
      resolveExecuteCommandTimeoutInput({ timeoutSeconds: 90, timeout: 90 }),
    ).toEqual({ ok: true, seconds: 90 });
    expect(resolveExecuteCommandTimeoutInput({})).toEqual({
      ok: true,
      seconds: undefined,
    });
    expect(
      resolveExecuteCommandTimeoutInput({
        timeoutSeconds: null,
        timeout: null,
      }),
    ).toEqual({ ok: true, seconds: undefined });
  });

  it("rejects disagreeing aliases instead of guessing which one was meant", () => {
    const r = resolveExecuteCommandTimeoutInput({
      timeoutSeconds: 30,
      timeout: 60,
    });
    expect(r.ok).toBe(false);
    if (!r.ok) {
      expect(r.error).toContain("timeoutSeconds=30");
      expect(r.error).toContain("timeout=60");
      expect(r.error).toContain("seconds");
    }
  });
});

// Canonical-field contract: the wire schema the model sees, and the deadline
// the executor enforces, must stay in lockstep across every alias spelling.
describe("execute_command timeout fields (canonical timeoutSeconds)", () => {
  function wireSchema() {
    const t = executeCommand(makeCtx());
    return asSchema(t.inputSchema);
  }

  it("serializes both spellings as nullable optional seconds in the wire schema", () => {
    const json = wireSchema().jsonSchema as {
      properties: Record<
        string,
        { anyOf?: { type: string }[]; description?: string } | undefined
      >;
      required?: string[];
      additionalProperties?: boolean;
    };
    for (const field of ["timeoutSeconds", "timeout"]) {
      expect(json.properties[field]?.anyOf?.map((t) => t.type)).toEqual([
        "number",
        "null",
      ]);
    }
    expect(json.required ?? []).not.toContain("timeoutSeconds");
    expect(json.required ?? []).not.toContain("timeout");
    // Strict wire schema: no third spelling can sneak in.
    expect(json.additionalProperties).toBe(false);
    expect(json.properties.timeoutSeconds?.description).toContain("seconds");
    expect(json.properties.timeout?.description).toContain("alias");
  });

  it("keeps null as an accepted inactive value on the SDK validation path", async () => {
    const schema = wireSchema();
    const nulled = await schema.validate?.({
      toolCallDescription: "Probe null handling",
      command: "echo ok",
      timeoutSeconds: null,
      timeout: null,
    });
    expect(nulled?.success).toBe(true);
    if (nulled?.success) {
      expect(nulled.value.timeoutSeconds).toBeNull();
      expect(nulled.value.timeout).toBeNull();
      // Unknown spellings are stripped by the strict schema — never a third alias.
      expect(
        (nulled.value as Record<string, unknown>).timeout_seconds,
      ).toBeUndefined();
    }
    const wrongType = await schema.validate?.({
      toolCallDescription: "Probe type handling",
      command: "echo ok",
      timeoutSeconds: "30",
    });
    expect(wrongType?.success).toBe(false);
  });

  function captureShell() {
    const calls: {
      opts?: { timeoutSeconds?: number } | undefined;
    }[] = [];
    const commandShell = {
      execute: async (_command: string, opts?: unknown) => {
        calls.push({ opts: opts as { timeoutSeconds?: number } | undefined });
        return {
          exitCode: 0,
          stdout: "ok",
          stderr: "",
          timedOut: false,
          stdoutTruncated: false,
          stderrTruncated: false,
          cleanupUnconfirmed: false,
        };
      },
    } as unknown as ToolContext["commandShell"];
    return { calls, commandShell };
  }

  function callTool(
    ctx: ToolContext,
    input: Omit<ExecuteCommandInput, "toolCallDescription"> & {
      command: string;
    },
  ): Promise<unknown> {
    return executeCommand(ctx).execute?.(
      {
        toolCallDescription: "Timeout alias dispatch test",
        ...input,
      },
      { toolCallId: "tc_alias", messages: [], abortSignal: undefined },
    ) as Promise<unknown>;
  }

  it("dispatches the resolved seconds for every accepted alias shape", async () => {
    const { calls, commandShell } = captureShell();
    const ctx = makeCtx({ commandShell });

    await callTool(ctx, { command: "echo a", timeoutSeconds: 30 });
    await callTool(ctx, { command: "echo b", timeout: 45 });
    await callTool(ctx, {
      command: "echo c",
      timeoutSeconds: null,
      timeout: 60,
    });
    await callTool(ctx, {
      command: "echo d",
      timeoutSeconds: 75,
      timeout: 75,
    });
    await callTool(ctx, {
      command: "echo e",
      timeoutSeconds: null,
      timeout: null,
    });
    await callTool(ctx, { command: "echo f" });

    expect(calls.map((c) => c.opts?.timeoutSeconds)).toEqual([
      30,
      45,
      60,
      75,
      DEFAULT_COMMAND_TIMEOUT_SECONDS,
      DEFAULT_COMMAND_TIMEOUT_SECONDS,
    ]);
  });

  it("rejects conflicting aliases before any command is dispatched", async () => {
    const { calls, commandShell } = captureShell();
    const ctx = makeCtx({ commandShell });

    const result = (await callTool(ctx, {
      command: "echo hello",
      timeoutSeconds: 30,
      timeout: 60,
    })) as ExecuteCommandResult;

    expect(result.success).toBe(false);
    expect(result.error).toContain("Conflicting timeout values");
    expect(result.error).toContain("timeoutSeconds=30");
    expect(result.error).toContain("timeout=60");
    expect(result.stderr).toContain("Conflicting timeout values");
    expect(calls).toHaveLength(0);
  });

  it("validates the canonical field literally — over-max and non-positive values are rejected, not clamped", async () => {
    const { calls, commandShell } = captureShell();
    const ctx = makeCtx({ commandShell });

    for (const bad of [0, -5, 700, 30_000]) {
      const result = (await callTool(ctx, {
        command: "echo hello",
        timeoutSeconds: bad,
      })) as ExecuteCommandResult;
      expect(result.success).toBe(false);
      expect(result.error).toContain("Invalid timeout");
      expect(result.error).toContain(String(bad));
    }
    expect(calls).toHaveLength(0);
  });

  it.skipIf(process.platform === "win32")(
    "terminates real process work on the canonical timeoutSeconds deadline",
    async () => {
      const shell = new PerCommandShell();
      try {
        const result = (await callTool(
          makeCtx({ commandShell: shell, agentCwd: process.cwd() }),
          { command: "sleep 30", timeoutSeconds: 0.5 },
        )) as ExecuteCommandResult;

        expect(result.success).toBe(false);
        expect(result.error).toBe("Command timed out");
        // The executor survived the kill and is immediately reusable.
        const after = await shell.execute("echo ok", { timeoutSeconds: 5 });
        expect(after.exitCode).toBe(0);
        expect(after.stdout).toContain("ok");
      } finally {
        await shell.dispose();
      }
    },
    8_000,
  );

  it("an already-aborted caller wins over any timeout alias", async () => {
    const { calls, commandShell } = captureShell();
    const ac = new AbortController();
    ac.abort();

    const result = (await callTool(
      makeCtx({ commandShell, abortSignal: ac.signal }),
      { command: "echo hello", timeoutSeconds: 5 },
    )) as ExecuteCommandResult;

    expect(result.success).toBe(false);
    expect(result.error).toBe("Command aborted by user");
    expect(calls).toHaveLength(0);
  });
});

describe("required-header policy on redirected shell commands", () => {
  function makeHeaderCtx(backends?: ToolContext["backends"]): ToolContext {
    const ctx = makeCtx({
      target: "https://example.com",
      ...(backends ? { backends } : {}),
    });
    ctx.session = {
      ...ctx.session,
      targets: ["https://example.com"],
      config: { headers: { "X-API-Key": "abc" } },
    } as typeof ctx.session;
    return ctx;
  }

  it("executes single-host curl with literal 2>&1 and injected headers", async () => {
    // Regression: the `&` in a literal `2>&1` was classified as command
    // chaining, so the capture pattern the tool guidance recommends was
    // fail-closed whenever session headers were configured. The backend
    // declares the POSIX contract explicitly — no host-OS dependence.
    let captured = "";
    const posixBackends = {
      command: {
        platform: "posix" as const,
        async *run(cmd: string) {
          captured = cmd;
          yield { type: "end" as const, exitCode: 0, timedOut: false };
        },
      },
    } as unknown as ToolContext["backends"];

    const result = (await executeCommand(
      makeHeaderCtx(posixBackends),
    ).execute?.(
      {
        command: "curl -s https://example.com/api 2>&1",
        toolCallDescription: "Fetch with stderr merged onto stdout",
      },
      { toolCallId: "tc_test", messages: [], abortSignal: undefined },
    )) as ExecuteCommandResult;

    expect(result.success).toBe(true);
    expect(captured).toContain(`-H "X-API-Key: abc"`);
    // Everything except the injected flags must survive byte-for-byte.
    expect(captured.endsWith("-s https://example.com/api 2>&1")).toBe(true);
  });

  it("rejection message offers the supported literal 2>&1 form", async () => {
    const result = (await executeCommand(makeHeaderCtx()).execute?.(
      {
        command: "curl -s https://example.com/api 2>&1 | tee scratchpad/o.txt",
        toolCallDescription: "Pipeline is still rejected",
      },
      { toolCallId: "tc_test", messages: [], abortSignal: undefined },
    )) as ExecuteCommandResult;

    expect(result.success).toBe(false);
    expect(result.error).toContain("2>&1");
    expect(result.error).toContain("single target host");
  });

  it("rejects 2>&1 on Windows command backends without dispatching", async () => {
    // Windows cmd expands `%VAR%` and parses metacharacters differently,
    // so the POSIX `2>&1` proof does not transfer — the command must be
    // fail-closed before any dispatch to the Windows shell.
    let dispatched = false;
    const windowsBackends = {
      command: {
        platform: "windows" as const,
        async *run() {
          dispatched = true;
          yield { type: "end" as const, exitCode: 0, timedOut: false };
        },
      },
    } as unknown as ToolContext["backends"];

    const result = (await executeCommand(
      makeHeaderCtx(windowsBackends),
    ).execute?.(
      {
        command: "curl -s https://example.com/api 2>&1",
        toolCallDescription:
          "Windows shell must not carry injected headers here",
      },
      { toolCallId: "tc_test", messages: [], abortSignal: undefined },
    )) as ExecuteCommandResult;

    expect(result.success).toBe(false);
    expect(dispatched).toBe(false);
    expect(result.error).toContain("Windows");
    expect(result.error).toContain("2>&1");
  });
});
