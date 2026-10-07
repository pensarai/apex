import { randomUUID } from "node:crypto";
import { tool } from "ai";
import { z } from "zod";
import { applyHeadersToShellCommand } from "../../../http/targetHeaders";
import {
  getPromptInjectionLibrary,
  type PromptInjectionLibrary,
  redactPromptInjectionPayloads,
} from "../../../prompt-injections";
import { collectCommand } from "../../../tools/backends/collectCommand";
import { resolveBackends } from "../../../tools/backends/resolve";
import {
  assertCommandActionAllowed,
  DestructiveActionError,
} from "./destructiveGuard";
import {
  assertCommandInScope,
  extractHostsFromCommand,
  resolverSessionFromCtx,
  ScopeViolationError,
} from "./scopeGuard";
import { toolOutputForModel } from "./toolOutput";
import type { ToolContext } from "./types";

const DEFAULT_PROMPT_INJECTION_FILE_ENV = "APEX_PROMPT_INJECTION_FILE";

/** Deadline applied when the model omits every timeout spelling. */
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

export type ExecuteCommandTimeoutInputResolution =
  | { ok: true; seconds: number | undefined }
  | { ok: false; error: string };

/**
 * `timeoutSeconds` (canonical) and `timeout` (legacy) are one seconds field.
 * Null is inactive — strict-mode models emit it for unset fields — and the
 * default applies only after alias resolution. Equal aliases pass; a
 * disagreement is rejected, never guessed or clamped.
 */
export function resolveExecuteCommandTimeoutInput(input: {
  timeoutSeconds?: number | null;
  timeout?: number | null;
}): ExecuteCommandTimeoutInputResolution {
  const canonical =
    typeof input.timeoutSeconds === "number" ? input.timeoutSeconds : undefined;
  const legacy = typeof input.timeout === "number" ? input.timeout : undefined;
  if (
    canonical !== undefined &&
    legacy !== undefined &&
    !Object.is(canonical, legacy)
  ) {
    return {
      ok: false,
      error: `Conflicting timeout values: timeoutSeconds=${canonical} and timeout=${legacy} — both are seconds; pass matching values or a single field`,
    };
  }
  return { ok: true, seconds: canonical ?? legacy };
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
  timeoutSeconds: z
    .number()
    .nullable()
    .optional()
    .describe(
      `Timeout in seconds (maximum ${MAX_COMMAND_TIMEOUT_SECONDS}; over-max and non-positive values are rejected, not clamped). Defaults to ${DEFAULT_COMMAND_TIMEOUT_SECONDS} seconds when unset or null.`,
    ),
  timeout: z
    .number()
    .nullable()
    .optional()
    .describe(
      "Legacy alias for timeoutSeconds — same seconds value. Prefer timeoutSeconds; if both are set they must match.",
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
  exitCode?: number;
  stdoutTruncated?: boolean;
  stderrTruncated?: boolean;
};

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
  timeoutSeconds: number,
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

  const backends = resolveBackends(ctx);
  if (backends.sandboxed) {
    const encoded = Buffer.from(payloadContent).toString("base64");
    const envVars: Record<string, string> = {
      APEX_HIDDEN_PAYLOAD_COUNT: String(Math.ceil(encoded.length / 6000)),
    };
    for (let offset = 0; offset < encoded.length; offset += 6000)
      envVars[`APEX_HIDDEN_PAYLOAD_${offset / 6000}`] = encoded.slice(
        offset,
        offset + 6000,
      );
    const filename = `apex_payload_${randomUUID()}.txt`;
    let writeCommand: string;
    if (backends.command.platform === "windows") {
      const script = `$ErrorActionPreference='Stop';$data='';for($i=0;$i -lt [int]$env:APEX_HIDDEN_PAYLOAD_COUNT;$i++){$data += [Environment]::GetEnvironmentVariable('APEX_HIDDEN_PAYLOAD_'+$i)};$path=[IO.Path]::Combine([IO.Path]::GetTempPath(),'${filename}');[IO.File]::WriteAllBytes($path,[Convert]::FromBase64String($data));[Console]::Write($path)`;
      writeCommand = `powershell.exe -NoProfile -NonInteractive -EncodedCommand ${Buffer.from(script, "utf16le").toString("base64")}`;
    } else {
      writeCommand = `umask 077; (i=0; while [ "$i" -lt "$APEX_HIDDEN_PAYLOAD_COUNT" ]; do printenv "APEX_HIDDEN_PAYLOAD_$i"; i=$((i+1)); done) | base64 -d > '/tmp/${filename}' && printf '%s' '/tmp/${filename}'`;
    }
    const written = await collectCommand(
      backends.command.run(writeCommand, {
        envVars,
        timeoutSeconds: Math.min(timeoutSeconds, 30),
        abortSignal: ctx.abortSignal,
      }),
    );
    if (written.exitCode !== 0 || written.timedOut || written.stdoutTruncated) {
      return {
        library,
        error: `Failed to materialize prompt injection payload in sandbox: ${written.stderr || "write failed"}`,
      };
    }
    const path = written.stdout.trim();
    if (!path) throw new Error("Payload materialization returned no path");
    return {
      library,
      envVars: {
        [normalized.envVar ?? DEFAULT_PROMPT_INJECTION_FILE_ENV]: path,
      },
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
- The tool's timeoutSeconds parameter is in SECONDS (default ${DEFAULT_COMMAND_TIMEOUT_SECONDS}, maximum ${MAX_COMMAND_TIMEOUT_SECONDS}); the legacy timeout field takes the same value
- Good timeoutSeconds examples: 30, 60, 120
- Values over ${MAX_COMMAND_TIMEOUT_SECONDS} (including millisecond-style values like 30000) are REJECTED, not reinterpreted
- Each stream captures up to 1 MiB in memory; a verbose process is never
  killed for output volume — capture keeps draining and reports truncation
  honestly (capped output is labeled INCOMPLETE). For large evidence, redirect
  the command's output directly to a file (e.g. \`... > scratchpad/scan.txt 2>&1\`)
  and read targeted windows of it: with read_file/grep locally, or — when the
  command ran in the sandbox, where those files live inside the sandbox — via
  bounded execute_command reads like \`sed -n '1,200p' scratchpad/scan.txt\`.
- If timeoutSeconds is hit, the partial stdout the command had already
  produced is still returned (with exit code 124). It is safe to set a
  conservative timeoutSeconds: you will not lose the bytes a fuzzer printed
  before the kill.

LONG-RUNNING FUZZERS AND SCANNERS:

Wordlist fuzzers (ffuf, gobuster, dirb, wfuzz, dirsearch) and large nmap
scans against slow targets routinely take longer than a single tool call
should. ALWAYS bound them with their OWN internal time budget, set BELOW
the tool's timeoutSeconds, so the tool exits cleanly with full output and
you don't have to rely on signal-based truncation.

General rule: set the inner tool's runtime cap at least 5s below the
execute_command timeoutSeconds, so the tool exits gracefully and flushes
its results to disk before any signal arrives.

- ffuf: pair with -maxtime <seconds> and a sane -rate.
  Example: ffuf -u <url>/FUZZ -w <wordlist> -maxtime 55 -rate 50
  with the tool's timeoutSeconds=60.
- gobuster: has no -maxtime flag. Wrap with the \`timeout\` coreutils
  command and tune --timeout / --threads.
  Example: timeout 55 gobuster dir -u <url> -w <wordlist> --timeout 5s --threads 20
  with the tool's timeoutSeconds=60.
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
    toModelOutput: ({ output }) =>
      toolOutputForModel(ctx, output as ExecuteCommandResult),
    execute: async ({
      command,
      promptInjection,
      timeoutSeconds,
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

      // Fail loud on alias conflicts and invalid explicit timeouts — silently
      // dropping, guessing, or clamping them would reinterpret the caller's
      // deadline. Aliases resolve before the default applies.
      let effectiveTimeout = DEFAULT_COMMAND_TIMEOUT_SECONDS;
      const resolvedInput = resolveExecuteCommandTimeoutInput({
        timeoutSeconds,
        timeout,
      });
      if (!resolvedInput.ok) {
        return {
          success: false,
          error: resolvedInput.error,
          stdout: "",
          stderr: resolvedInput.error,
          command,
        };
      }
      if (resolvedInput.seconds !== undefined) {
        const validated = validateExecuteCommandTimeout(resolvedInput.seconds);
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
      // dropped — agent can opt out with `allow_unprotected`. The literal
      // `2>&1` recognition is POSIX-shell-only, so the selected backend's
      // declared platform decides whether it applies.
      const backends = resolveBackends(ctx);
      const cmdHosts = extractHostsFromCommand(command);
      const inject = applyHeadersToShellCommand(
        command,
        resolverSessionFromCtx(ctx),
        cmdHosts,
        backends.command.platform,
      );
      if (inject.status === "unknown-tool" && !allow_unprotected) {
        const redirectGuidance =
          backends.command.platform === "windows"
            ? "on Windows command shells `2>&1` redirection is not supported for header injection — drop the redirect; "
            : "literal `2>&1` is allowed, but pipelines, substitutions, and multiple hosts are not; ";
        const msg =
          "Command rejected: configured custom HTTP headers cannot be injected because the tool is unrecognized or the command is pipelined or chained. " +
          "Run a supported HTTP tool (curl, wget, nuclei, ffuf, gobuster, httpx, feroxbuster, dirb, wfuzz, wpscan, sqlmap, nikto) on a single target host; " +
          redirectGuidance +
          "otherwise use the http_request tool, or pass allow_unprotected: true to acknowledge headers will NOT be sent.";
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
      try {
        const resolved = await resolvePromptInjectionEnv(
          promptInjection,
          ctx,
          effectiveTimeout,
        );
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

      {
        let captured: Awaited<ReturnType<typeof collectCommand>>;
        try {
          captured = await collectCommand(
            backends.command.run(commandWithHeaders, {
              timeoutSeconds: effectiveTimeout,
              envVars: promptInjectionEnvVars,
              abortSignal: ctx.abortSignal,
            }),
            (chunk) =>
              ctx.eventBus?.emit("command-output", { data: redact(chunk) }),
          );
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
        const {
          stdout,
          stderr,
          exitCode,
          timedOut,
          stdoutTruncated,
          stderrTruncated,
        } = captured;
        return {
          success: exitCode === 0,
          error:
            timedOut || exitCode === 124
              ? "Command timed out"
              : exitCode === 130
                ? "Command aborted"
                : exitCode !== 0
                  ? `Exit code: ${exitCode}`
                  : "",
          stdout:
            (redact(stdout) || "(no output)") +
            (stdoutTruncated
              ? "\n\n(INCOMPLETE — stdout capture truncated at the byte limit)"
              : ""),
          stderr:
            redact(stderr) +
            (stderrTruncated
              ? "\n\n(INCOMPLETE — stderr capture truncated at the byte limit)"
              : ""),
          command: redact(command),
          exitCode,
          stdoutTruncated,
          stderrTruncated,
        };
      }
    },
  });
}
