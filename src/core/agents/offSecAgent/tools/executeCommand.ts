import { tool } from "ai";
import { z } from "zod";
import { join } from "path";
import { writeFileSync, mkdirSync, existsSync } from "fs";
import type { ToolContext } from "./types";
import { assertCommandInScope, ScopeViolationError } from "./scopeGuard";

const MAX_INLINE = 50_000;
const MS_TIMEOUT_THRESHOLD = 10_000;

export const executeCommandInputSchema = z.object({
  // not actually sure if placing this above the other keys/zod values ensures that the model generates it first...
  toolCallDescription: z
    .string()
    .describe(
      "A concise, human-readable description of what this tool call is doing (e.g., 'Scanning for open ports on target')",
    ),
  command: z.string().describe("The shell command to execute"),
  timeout: z
    .number()
    .optional()
    .describe(
      "Timeout in seconds. If omitted, the command runs until completion or abort.",
    ),
});

export type ExecuteCommandInput = z.infer<typeof executeCommandInputSchema>;

export type ExecuteCommandResult = {
  success: boolean;
  error: string;
  stdout: string;
  stderr: string;
  command: string;
  outputFile?: string;
};

/**
 * Defensively normalize obviously-millisecond timeout values into seconds.
 *
 * The tool contract is seconds, but models sometimes emit JavaScript-style
 * millisecond values like 30000 or 120000. Without normalization, those become
 * multi-hour hangs instead of 30s / 120s command limits.
 */
export function normalizeExecuteCommandTimeout(
  timeout?: number,
): number | undefined {
  if (timeout == null || !Number.isFinite(timeout) || timeout <= 0) {
    return undefined;
  }

  if (timeout >= MS_TIMEOUT_THRESHOLD) {
    return Math.max(1, Math.ceil(timeout / 1_000));
  }

  return timeout;
}

/**
 * If `raw` exceeds the inline limit, save the full text to a file under
 * `{session.logsPath}/cmd-output/` and return truncated text + file path.
 * Otherwise return the text as-is with no file.
 */
function maybeSaveFullOutput(
  raw: string,
  ctx: ToolContext,
): { text: string; file?: string } {
  if (raw.length <= MAX_INLINE) {
    return { text: raw || "(no output)" };
  }

  const outputDir = join(ctx.session.logsPath, "cmd-output");
  if (!existsSync(outputDir)) {
    mkdirSync(outputDir, { recursive: true });
  }

  const ts = new Date().toISOString().replace(/[:.]/g, "-");
  const filename = `output-${ts}.txt`;
  const filePath = join(outputDir, filename);

  try {
    writeFileSync(filePath, raw);
  } catch {
    return {
      text: `${raw.substring(0, MAX_INLINE)}...\n\n(truncated — failed to save full output to file)`,
    };
  }

  const truncated = raw.substring(0, MAX_INLINE);
  return {
    text: `${truncated}...\n\n(truncated — full output saved to ${filePath}). Use read_file or grep to analyze.`,
    file: filePath,
  };
}

export function executeCommand(ctx: ToolContext) {
  return tool({
    description: `Execute a shell command for penetration testing activities.

The shell is persistent — environment variables, working directory (cd), and
background processes survive across calls. You do NOT need nohup/& tricks to
keep processes alive between calls; just background them normally with &.

COMMON COMMANDS FOR BLACK BOX TESTING:

RECONNAISSANCE:
- dig <domain>                       # DNS lookup
- whois <domain>                     # Domain registration info

NMAP PORT SCANNING STRATEGY — FAST TARGETED SCANS FIRST:
Always start with a fast, lightweight scan on specific ports. Do NOT begin
with -sV -sC or --top-ports — those are slow. Get open ports first, then
probe only the ports that are actually open.

Step 1 — Fast port discovery (no version detection, no scripts):
  nmap -T4 --open -p 21,22,80,443,2121,8080,8443,3000,3306,4000,5000,5432,6379,8000,9000,27017 <target> 2>&1
  This finishes in seconds and tells you which ports are open.

Step 2 — Version/script scan ONLY on the open ports found in Step 1:
  nmap -sV -sC -p <open-ports-from-step-1> <target> 2>&1
  e.g. nmap -sV -sC -p 22,80,443 <target> 2>&1

Step 3 — Only if Steps 1-2 find nothing interesting, broaden:
  nmap -T4 --open --top-ports 1000 <target> 2>&1   # Wider discovery
  nmap -p- <target> 2>&1                            # Full port scan (last resort, very slow)

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
- The tool's timeout parameter is in SECONDS, not milliseconds
- Good timeout examples: 30, 60, 120
- Do NOT pass millisecond values like 30000 or 120000

TIMEOUTS — MATCH TO SCAN TYPE:
- Fast nmap discovery (Step 1, no -sV/-sC): 60–120s is plenty.
- Version/script scans (-sV -sC on known open ports): 300s (5 min).
- Full-port or heavy script scans (-p-, --script): 600+s.
  A premature timeout wastes all the work done so far.
- For other network tools (nikto, gobuster, masscan), default to a longer
  timeout rather than a short one.
- Quick commands (curl, dig, whois) are fine with 30–60s.

IMPORTANT: Always analyze results and adjust your approach based on findings.`,
    inputSchema: executeCommandInputSchema,
    execute: async ({ command, timeout }): Promise<ExecuteCommandResult> => {
      if (ctx.abortSignal?.aborted) {
        return {
          success: false,
          error: "Command aborted by user",
          stdout: "",
          stderr: "",
          command,
        };
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

      // Sandbox mode: route execution through the sandbox
      if (ctx.sandbox) {
        try {
          const ssmOpts: { timeout?: number } = {};
          const normalizedTimeout = normalizeExecuteCommandTimeout(timeout);
          if (normalizedTimeout != null) {
            ssmOpts.timeout = normalizedTimeout;
          }
          const result = await ctx.sandbox.execute(command, ssmOpts);
          const { text: stdout, file: outputFile } = maybeSaveFullOutput(
            result.stdout,
            ctx,
          );
          return {
            success: result.success,
            error: !result.success ? result.stderr || "Command failed" : "",
            stdout,
            stderr: result.stderr || "",
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

      // Local mode: use the persistent shell
      if (ctx.persistentShell) {
        try {
          const normalizedTimeout = normalizeExecuteCommandTimeout(timeout);
          const onData = ctx.eventBus
            ? (data: string) => ctx.eventBus!.emit("command-output", { data })
            : undefined;
          const result = await ctx.persistentShell.execute(
            command,
            normalizedTimeout,
            onData,
            ctx.abortSignal,
          );
          const { text: stdout, file: outputFile } = maybeSaveFullOutput(
            result.stdout,
            ctx,
          );
          return {
            success: result.exitCode === 0,
            error:
              result.exitCode === 124
                ? "Command timed out"
                : result.exitCode !== 0
                  ? `Exit code: ${result.exitCode}`
                  : "",
            stdout,
            stderr: result.stderr,
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
