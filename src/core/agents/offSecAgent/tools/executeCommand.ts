import { existsSync, mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { tool } from "ai";
import { z } from "zod";
import { applyHeadersToShellCommand } from "../../../http/targetHeaders";
import {
  getPromptInjectionLibrary,
  type PromptInjectionLibrary,
  redactPromptInjectionPayloads,
} from "../../../prompt-injections";
import { agentLogsDir } from "./agentScratch";
import {
  assertCommandActionAllowed,
  DestructiveActionError,
} from "./destructiveGuard";
import { readSandboxAgentEnv } from "./perCommandShell";
import {
  assertCommandInScope,
  extractHostsFromCommand,
  resolverSessionFromCtx,
  ScopeViolationError,
} from "./scopeGuard";
import type { ToolContext } from "./types";

const MAX_INLINE = 50_000;
const DEFAULT_PROMPT_INJECTION_FILE_ENV = "APEX_PROMPT_INJECTION_FILE";

/** Deadline applied when the model omits `timeout`. */
export const DEFAULT_COMMAND_TIMEOUT_SECONDS = 120;
export const MAX_COMMAND_TIMEOUT_SECONDS = 600;

export type ExecuteCommandTimeoutValidation =
  | { ok: true; seconds: number }
  | { ok: false; error: string };

/**
 * Explicit timeouts are seconds, taken literally: nonfinite, nonpositive, and
 * over-max values are rejected — never silently clamped or reinterpreted
 * (millisecond-style values like 30000 fail as over-max, by design).
 */
export function validateExecuteCommandTimeout(
  timeout: number,
): ExecuteCommandTimeoutValidation {
  if (!Number.isFinite(timeout)) {
    return {
      ok: false,
      error: `Invalid timeout: must be a finite number of seconds (got ${timeout})`,
    };
  }
  if (timeout <= 0) {
    return {
      ok: false,
      error: `Invalid timeout: must be a positive number of seconds (got ${timeout})`,
    };
  }
  if (timeout > MAX_COMMAND_TIMEOUT_SECONDS) {
    return {
      ok: false,
      error: `Invalid timeout: ${timeout} exceeds the ${MAX_COMMAND_TIMEOUT_SECONDS}-second maximum — pass seconds, not milliseconds`,
    };
  }
  return { ok: true, seconds: timeout };
}

/**
 * Placeholder ids models emit for the optional promptInjection pointer when
 * they mean "no payload" but fill the field anyway instead of omitting it.
 * These are non-empty strings, so they pass schema validation and would
 * otherwise fail as "Unknown prompt injection id". Compared lowercase.
 */
const OMITTED_PROMPT_INJECTION_IDS = new Set([
  "null",
  "undefined",
  "none",
  "__omit__",
]);

const promptInjectionPointerSchema = z.object({
  id: z
    .string()
    .min(1)
    .nullable()
    .optional()
    .describe(
      'Stable prompt-injection id returned by list_prompt_injections. Leave unset/null unless you are intentionally running a prompt-injection harness. Do NOT pass placeholder values like "__omit__", "none", or "null" — just omit the field.',
    ),
  envVar: z
    .string()
    .regex(/^[A-Za-z_][A-Za-z0-9_]*$/)
    .optional()
    .describe(
      `Environment variable that will contain the payload file path at runtime. Defaults to ${DEFAULT_PROMPT_INJECTION_FILE_ENV}.`,
    ),
});

const executeCommandInputSchema = z.object({
  // not actually sure if placing this above the other keys/zod values ensures that the model generates it first...
  toolCallDescription: z
    .string()
    .describe(
      "A concise, human-readable description of what this tool call is doing (e.g., 'Scanning for open ports on target')",
    ),
  command: z.string().describe("The shell command to execute"),
  promptInjection: promptInjectionPointerSchema
    .optional()
    .describe(
      "Optional runtime prompt-injection file pointer. Omit this entirely unless you are running a prompt-injection harness with a payload id from list_prompt_injections. When set, the tool resolves the id to a local payload file path and exposes that path through envVar. The raw payload text is never inserted into the command.",
    ),
  timeout: z
    .number()
    .optional()
    .describe(
      `Timeout in seconds (maximum ${MAX_COMMAND_TIMEOUT_SECONDS}; over-max and non-positive values are rejected, not clamped). If omitted, defaults to ${DEFAULT_COMMAND_TIMEOUT_SECONDS} seconds.`,
    ),
  allow_unprotected: z
    .boolean()
    .optional()
    .describe(
      "Acknowledge that this command will run WITHOUT the session's configured custom HTTP headers because the tool is unrecognized or the command is pipelined. Defaults to false (fail-closed). Use only when you understand the headers will not be applied.",
    ),
});

export type ExecuteCommandInput = z.infer<typeof executeCommandInputSchema>;

/**
 * Models sometimes fill the optional promptInjection pointer with placeholder
 * sentinels ("__omit__", "null", "none", empty) instead of leaving it out.
 * Normalize those to undefined so the command runs without a payload pointer
 * rather than failing with "Unknown prompt injection id".
 */
export function normalizePromptInjectionPointer(
  promptInjection: ExecuteCommandInput["promptInjection"],
): { id: string; envVar?: string } | undefined {
  if (!promptInjection) return undefined;
  const id =
    typeof promptInjection.id === "string" ? promptInjection.id.trim() : "";
  if (id === "" || OMITTED_PROMPT_INJECTION_IDS.has(id.toLowerCase())) {
    return undefined;
  }
  return { ...promptInjection, id };
}

export type ExecuteCommandResult = {
  success: boolean;
  error: string;
  stdout: string;
  stderr: string;
  command: string;
  outputFile?: string;
};

/**
 * If `raw` exceeds the inline limit, save the full text to a file under this
 * agent's log dir (`cmd-output/`) and return truncated text + file path.
 * Otherwise return the text as-is with no file. An `incompleteNote` marks a
 * capture that hit the byte cap — the saved artifact is the bounded capture
 * and is never labeled as the full output. Scoped per-subagent via
 * {@link agentLogsDir} so a host can reclaim a finished subagent's command
 * dumps mid-scan.
 */
function maybeSaveFullOutput(
  raw: string,
  ctx: ToolContext,
  opts?: { incompleteNote?: string },
): { text: string; file?: string } {
  const incompleteNote = opts?.incompleteNote;
  if (raw.length <= MAX_INLINE) {
    return {
      text: incompleteNote
        ? `${raw || "(no output)"}\n\n(INCOMPLETE — ${incompleteNote})`
        : raw || "(no output)",
    };
  }

  const outputDir = join(agentLogsDir(ctx), "cmd-output");
  if (!existsSync(outputDir)) {
    mkdirSync(outputDir, { recursive: true });
  }

  const ts = new Date().toISOString().replace(/[:.]/g, "-");
  const filename = `output-${ts}.txt`;
  const filePath = join(outputDir, filename);

  try {
    writeFileSync(filePath, raw);
  } catch {
    const failedNote = incompleteNote
      ? `INCOMPLETE capture (${incompleteNote}); failed to save bounded capture to file`
      : "failed to save full output to file";
    return {
      text: `${raw.substring(0, MAX_INLINE)}...\n\n(truncated — ${failedNote})`,
    };
  }

  const truncated = raw.substring(0, MAX_INLINE);
  const savedNote = incompleteNote
    ? `INCOMPLETE capture (${incompleteNote}); saved output truncated at the byte limit to ${filePath}`
    : `full output saved to ${filePath}`;
  return {
    text: `${truncated}...\n\n(truncated — ${savedNote}). Use read_file or grep to analyze.`,
    file: filePath,
  };
}

/**
 * Redact known secret values from command output. Longest-first to avoid
 * partial masking; skip values under 6 chars so they can't corrupt output.
 */
export function redactSecretValues(text: string, secrets?: string[]): string {
  if (!secrets?.length) return text;
  let out = text;
  for (const s of [...secrets]
    .filter((v) => v && v.length >= 6)
    .sort((a, b) => b.length - a.length)) {
    out = out.split(s).join("[REDACTED]");
  }
  return out;
}

async function resolvePromptInjectionEnv(
  promptInjection: ExecuteCommandInput["promptInjection"],
  ctx: ToolContext,
): Promise<
  | {
      envVars?: Record<string, string>;
      library?: PromptInjectionLibrary;
      payloadContent?: string;
      error?: undefined;
    }
  | {
      envVars?: undefined;
      library?: PromptInjectionLibrary;
      payloadContent?: undefined;
      error: string;
    }
> {
  const normalized = normalizePromptInjectionPointer(promptInjection);
  if (!normalized) return {};

  const library = await getPromptInjectionLibrary({
    library: ctx.promptInjectionLibrary,
    source: ctx.promptInjectionLibrarySource,
  });

  const payloadContent = library.getPayload(normalized.id);
  if (payloadContent === undefined) {
    return {
      library,
      error: `Unknown prompt injection id: ${normalized.id}`,
    };
  }

  const payloadFilePath = library.getPayloadFilePath(normalized.id);
  if (!payloadFilePath) {
    return {
      library,
      error:
        `Unknown prompt injection id or no payload file path available: ` +
        normalized.id,
    };
  }

  return {
    library,
    payloadContent,
    envVars: {
      [normalized.envVar ?? DEFAULT_PROMPT_INJECTION_FILE_ENV]: payloadFilePath,
    },
  };
}

export function executeCommand(ctx: ToolContext) {
  return tool({
    description: `Execute a shell command for penetration testing activities.

Each call runs in a FRESH shell in your working directory: cd, export,
aliases, and background jobs do NOT persist between calls. Chain related
steps in one command (cd dir && ./run) or use absolute paths. Environment
activation (virtualenv, exports) must happen in the SAME command that uses
it, or come from the session's configured environment.

LOCAL SERVICES: to start a long-running service, background it WITH
redirected stdio so the call returns immediately and the service survives as
a plain process:
  nohup python server.py > scratchpad/server.log 2>&1 & echo $! > scratchpad/server.pid
Check later with cat scratchpad/server.log; stop with kill $(cat
scratchpad/server.pid). There is no shell job table across calls — recorded
PIDs/files plus explicit lifecycle are how you manage services. Note: a
command that FAILS (nonzero exit) takes its background children down with it;
only a successful launcher leaves its redirected service running.

COMMON COMMANDS FOR BLACK BOX TESTING:

RECONNAISSANCE:
- nmap -sV -sC <target>              # Service version detection + default scripts
- nmap -p- <target>                  # Scan all ports
- dig <domain>                       # DNS lookup
- whois <domain>                     # Domain registration info

WEB APPLICATION TESTING:
- curl -i <url>                      # HTTP request with headers
- curl -X POST -d "data" <url>       # POST request
- nikto -h <host>                    # Web server scanner
- gobuster dir -u <url> -w <wordlist> # Directory enumeration
- ffuf -u <url>/FUZZ -w <wordlist>   # Web fuzzer

SSL/TLS TESTING:
- openssl s_client -connect <host>:<port>
- nmap --script ssl-enum-ciphers -p 443 <host>

OUTPUT HANDLING:
- Use 2>&1 to capture stderr
- Use timeout command for long-running scans
- The tool's timeout parameter is in SECONDS (default ${DEFAULT_COMMAND_TIMEOUT_SECONDS}, maximum ${MAX_COMMAND_TIMEOUT_SECONDS})
- Good timeout examples: 30, 60, 120
- Values over ${MAX_COMMAND_TIMEOUT_SECONDS} (including millisecond-style values like 30000) are REJECTED, not reinterpreted
- Each stream captures up to 1 MiB in memory; a verbose process is never
  killed for output volume — capture keeps draining and reports truncation
  honestly (capped output is labeled INCOMPLETE). For large evidence, redirect
  the command's output directly to a file (e.g. \`... > scratchpad/scan.txt 2>&1\`)
  and read targeted windows of it: with read_file/grep locally, or — when the
  command ran in the sandbox, where those files live inside the sandbox — via
  bounded execute_command reads like \`sed -n '1,200p' scratchpad/scan.txt\`.
- If the tool's timeout is hit, the partial stdout the command had already
  produced is still returned (with exit code 124). It is safe to set a
  conservative timeout: you will not lose the bytes a fuzzer printed
  before the kill.

LONG-RUNNING FUZZERS AND SCANNERS:

Wordlist fuzzers (ffuf, gobuster, dirb, wfuzz, dirsearch) and large nmap
scans against slow targets routinely take longer than a single tool call
should. ALWAYS bound them with their OWN internal time budget, set BELOW
the tool's timeout, so the tool exits cleanly with full output and you
don't have to rely on signal-based truncation.

General rule: set the inner tool's runtime cap at least 5s below the
execute_command timeout, so the tool exits gracefully and flushes its
results to disk before any signal arrives.

- ffuf: pair with -maxtime <seconds> and a sane -rate.
  Example: ffuf -u <url>/FUZZ -w <wordlist> -maxtime 55 -rate 50
  with the tool's timeout=60.
- gobuster: has no -maxtime flag. Wrap with the \`timeout\` coreutils
  command and tune --timeout / --threads.
  Example: timeout 55 gobuster dir -u <url> -w <wordlist> --timeout 5s --threads 20
  with the tool's timeout=60.
- nmap: prefer --host-timeout, --max-rtt-timeout, and -T4 / --min-rate
  to bound total runtime against slow networks.

PROMPT-INJECTION PAYLOADS:
- Do not put raw prompt-injection payload text in the command.
- To run a local harness with a payload, set promptInjection.id to an id from
  list_prompt_injections and reference "$APEX_PROMPT_INJECTION_FILE" in the
  command. The tool resolves that variable to the local payload file path only
  at runtime.

IMPORTANT: Always analyze results and adjust your approach based on findings.`,
    inputSchema: executeCommandInputSchema,
    execute: async ({
      command,
      promptInjection,
      timeout,
      allow_unprotected,
    }): Promise<ExecuteCommandResult> => {
      if (ctx.abortSignal?.aborted) {
        return {
          success: false,
          error: "Command aborted by user",
          stdout: "",
          stderr: "",
          command,
        };
      }

      // Fail loud on invalid explicit timeouts — silently dropping or
      // clamping them would reinterpret the caller's deadline.
      let effectiveTimeout = DEFAULT_COMMAND_TIMEOUT_SECONDS;
      if (timeout !== undefined) {
        const validated = validateExecuteCommandTimeout(timeout);
        if (!validated.ok) {
          return {
            success: false,
            error: validated.error,
            stdout: "",
            stderr: validated.error,
            command,
          };
        }
        effectiveTimeout = validated.seconds;
      }

      try {
        assertCommandInScope(command, ctx);
      } catch (e) {
        if (e instanceof ScopeViolationError) {
          return {
            success: false,
            error: e.message,
            stdout: "",
            stderr: e.message,
            command,
          };
        }
        throw e;
      }

      // Inject session headers into the shell command. Fail closed for
      // unknown tools / pipelines so configured headers aren't silently
      // dropped — agent can opt out with `allow_unprotected`.
      const cmdHosts = extractHostsFromCommand(command);
      const inject = applyHeadersToShellCommand(
        command,
        resolverSessionFromCtx(ctx),
        cmdHosts,
      );
      if (inject.status === "unknown-tool" && !allow_unprotected) {
        const msg =
          "Command rejected: configured custom HTTP headers cannot be injected because the tool is unrecognized or the command is pipelined. " +
          "Supported HTTP tools: curl, wget, nuclei, ffuf, gobuster, httpx, feroxbuster, dirb, wfuzz, wpscan, sqlmap, nikto. " +
          "Either (a) rewrite the command using one of those tools, (b) use the http_request tool, or (c) pass allow_unprotected: true to acknowledge headers will NOT be sent.";
        return {
          success: false,
          error: msg,
          stdout: "",
          stderr: msg,
          command,
        };
      }
      const commandWithHeaders =
        inject.status === "injected" ? inject.command : command;

      // Enforce the destructive-action guard on the header-injected command so
      // a method-override header (e.g. `X-HTTP-Method-Override: DELETE`) added
      // by the session/credential layer is classified, not just agent-authored
      // flags. (Prompt-injection payloads are written to a temp file and
      // referenced by env var below — never inlined into the command string —
      // so their content is out of scope for this string classifier.)
      try {
        assertCommandActionAllowed(commandWithHeaders, ctx);
      } catch (e) {
        if (e instanceof DestructiveActionError) {
          return {
            success: false,
            error: e.message,
            stdout: "",
            stderr: e.message,
            command,
          };
        }
        throw e;
      }

      let promptInjectionLibrary: PromptInjectionLibrary | undefined;
      let promptInjectionEnvVars: Record<string, string> | undefined;
      let promptInjectionPayloadContent: string | undefined;
      try {
        const resolved = await resolvePromptInjectionEnv(promptInjection, ctx);
        if (resolved.error) {
          return {
            success: false,
            error: resolved.error,
            stdout: "",
            stderr: resolved.error,
            command,
          };
        }
        promptInjectionLibrary = resolved.library;
        promptInjectionEnvVars = resolved.envVars;
        promptInjectionPayloadContent = resolved.payloadContent;
      } catch (error: unknown) {
        const msg = error instanceof Error ? error.message : String(error);
        return {
          success: false,
          error: msg,
          stdout: "",
          stderr: msg,
          command,
        };
      }

      const redact = (value: string) => {
        const stripped = promptInjectionLibrary
          ? redactPromptInjectionPayloads(value, promptInjectionLibrary)
          : value;
        return redactSecretValues(stripped, ctx.secretValues);
      };

      // Sandbox mode: route execution through the sandbox
      if (ctx.sandbox) {
        try {
          // Explicit default cwd + approved configured agent env every
          // invocation, via the existing sandbox interface. Per-agent
          // configured env overrides the workspace blob; the injection env
          // (payload pointer) overrides both. Process ownership/termination
          // parity is the adapter's, not claimed here.
          const ssmOpts: {
            timeout: number;
            cwd?: string;
            envVars?: Record<string, string>;
          } = {
            timeout: effectiveTimeout,
            cwd: ctx.agentCwd,
            envVars: {
              ...readSandboxAgentEnv(),
              ...ctx.environmentVariables,
            },
          };

          // If we have a prompt injection payload for sandbox mode, we need to write
          // it to a temp file in the sandbox first, since the host file path won't
          // be accessible from inside the sandbox.
          if (promptInjectionPayloadContent && promptInjection) {
            const envVarName =
              promptInjection.envVar ?? DEFAULT_PROMPT_INJECTION_FILE_ENV;
            const sandboxTempFile = `/tmp/apex_payload_${Date.now()}.txt`;

            // Write the payload to a temp file in the sandbox
            const escapedPayload = promptInjectionPayloadContent
              .replace(/\\/g, "\\\\")
              .replace(/'/g, "'\\''");
            const writeCommand = `printf '%s' '${escapedPayload}' > ${sandboxTempFile}`;

            // The payload-file write keeps its own 30s ceiling: 30s when the
            // command timeout is omitted, and an explicit timeout can only
            // tighten it — a printf must never outlive a 600s command cap.
            const writeResult = await ctx.sandbox.execute(writeCommand, {
              timeout: Math.min(effectiveTimeout, 30),
            });

            if (!writeResult.success) {
              const errorMsg = `Failed to write prompt injection payload to sandbox: ${writeResult.stderr || "unknown error"}`;
              return {
                success: false,
                error: errorMsg,
                stdout: writeResult.stdout,
                stderr: writeResult.stderr || errorMsg,
                command,
              };
            }

            // Update env vars to point to the sandbox temp file
            ssmOpts.envVars = {
              ...ssmOpts.envVars,
              [envVarName]: sandboxTempFile,
            };
          } else if (promptInjectionEnvVars) {
            ssmOpts.envVars = { ...ssmOpts.envVars, ...promptInjectionEnvVars };
          }

          const result = await ctx.sandbox.execute(commandWithHeaders, ssmOpts);
          const { text: stdout, file: outputFile } = maybeSaveFullOutput(
            redact(result.stdout),
            ctx,
          );
          const stderr = redact(result.stderr || "");
          return {
            success: result.success,
            error: !result.success ? stderr || "Command failed" : "",
            stdout,
            stderr,
            command,
            outputFile,
          };
        } catch (error: unknown) {
          const msg = error instanceof Error ? error.message : String(error);
          return {
            success: false,
            error: msg,
            stdout: "",
            stderr: msg,
            command,
          };
        }
      }

      // Local mode: per-command executor (fresh shell each invocation)
      if (ctx.commandShell) {
        try {
          const onData = ctx.eventBus
            ? (data: string) =>
                ctx.eventBus?.emit("command-output", { data: redact(data) })
            : undefined;
          const result = await ctx.commandShell.execute(commandWithHeaders, {
            cwd: ctx.agentCwd,
            env: promptInjectionEnvVars,
            timeoutSeconds: effectiveTimeout,
            abortSignal: ctx.abortSignal,
            onData,
          });
          const stdoutNote = result.stdoutTruncated
            ? "stdout capture truncated at the byte limit"
            : undefined;
          const stderrNote = result.stderrTruncated
            ? "stderr capture truncated at the byte limit"
            : undefined;
          const { text: stdout, file: outputFile } = maybeSaveFullOutput(
            redact(result.stdout),
            ctx,
            { incompleteNote: stdoutNote },
          );
          const stderr =
            redact(result.stderr) +
            (stderrNote ? `\n\n(INCOMPLETE — ${stderrNote})` : "");
          return {
            success: result.exitCode === 0,
            error:
              result.exitCode === 124
                ? "Command timed out"
                : result.exitCode === 130
                  ? "Command aborted"
                  : result.exitCode !== 0
                    ? `Exit code: ${result.exitCode}`
                    : "",
            stdout,
            stderr,
            command,
            outputFile,
          };
        } catch (error: unknown) {
          const msg = error instanceof Error ? error.message : String(error);
          return {
            success: false,
            error: msg,
            stdout: "",
            stderr: msg,
            command,
          };
        }
      }

      return {
        success: false,
        error: "No shell or sandbox available",
        stdout: "",
        stderr: "",
        command,
      };
    },
  });
}
