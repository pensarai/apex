import { tool } from "ai";
import { z } from "zod";
import { spawn } from "child_process";
import type { ToolContext } from "./types";

export const executeCommandInputSchema = z.object({
  command: z.string().describe("The shell command to execute"),
  timeout: z
    .number()
    .optional()
    .describe(
      "Timeout in seconds. In foreground mode the process is killed after this duration. " +
        "In background mode this controls how long to collect initial output before returning (default: 2s). " +
        "If omitted in foreground mode the command runs until completion or abort.",
    ),
  background: z
    .boolean()
    .optional()
    .describe(
      "Run the command as a background process. Returns immediately with initial output and the process PID. " +
        "Use for long-running processes like servers, listeners, or watchers.",
    ),
  toolCallDescription: z
    .string()
    .describe(
      "A concise, human-readable description of what this tool call is doing (e.g., 'Scanning for open ports on target')",
    ),
});

export type ExecuteCommandInput = z.infer<typeof executeCommandInputSchema>;

export type ExecuteCommandResult = {
  success: boolean;
  error: string;
  stdout: string;
  stderr: string;
  command: string;
  pid?: number;
  isBackgroundProcess?: boolean;
};

const MAX_OUTPUT = 50_000;

function truncateOutput(output: string): string {
  if (output.length <= MAX_OUTPUT) return output;
  return `${output.substring(0, MAX_OUTPUT)}...\n\n(truncated) call the command again with grep / tail to paginate`;
}

export function executeCommand(ctx: ToolContext) {
  return tool({
    description: `Execute a shell command for penetration testing activities.

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

BACKGROUND MODE:
Set background=true for long-running processes (servers, listeners, watchers).
The command starts in the background and the tool returns initial output with the process PID.

IMPORTANT: Always analyze results and adjust your approach based on findings.`,
    inputSchema: executeCommandInputSchema,
    execute: async ({
      command,
      timeout,
      background,
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

      // --- Sandbox mode ---
      if (ctx.sandbox) {
        if (background) {
          return sandboxBackground(ctx, command);
        }
        return sandboxForeground(ctx, command, timeout);
      }

      // --- Local mode ---
      return new Promise((resolve) => {
        const shellCmd = process.platform === "win32" ? "cmd" : "bash";
        const shellArgs =
          process.platform === "win32" ? ["/c", command] : ["-lc", command];

        const child = spawn(shellCmd, shellArgs, {
          stdio: ["ignore", "pipe", "pipe"],
          detached: process.platform !== "win32",
        });

        let stdout = "";
        let stderr = "";
        let killed = false;
        let resolved = false;

        const safeResolve = (result: ExecuteCommandResult) => {
          if (!resolved) {
            resolved = true;
            resolve(result);
          }
        };

        const killProcess = () => {
          if (killed) return;
          killed = true;

          try {
            if (child.pid && process.platform !== "win32") {
              process.kill(-child.pid, "SIGTERM");
            } else {
              child.kill("SIGTERM");
            }
          } catch {
            // Process may have already exited
          }

          // SIGKILL fallback after 5 s
          setTimeout(() => {
            try {
              if (child.pid && process.platform !== "win32") {
                process.kill(-child.pid, "SIGKILL");
              } else {
                child.kill("SIGKILL");
              }
            } catch {
              // Process may have already exited
            }

            safeResolve({
              success: false,
              stdout: truncateOutput(stdout) || "(no output)",
              stderr: stderr || "",
              command,
              error: "Command killed (did not exit after SIGTERM)",
            });
          }, 5_000);
        };

        child.stdout.on("data", (data: Buffer) => {
          stdout += data.toString();
        });

        child.stderr.on("data", (data: Buffer) => {
          stderr += data.toString();
        });

        if (background) {
          // Background: collect initial output for a settle period, then detach
          let exited = false;
          let exitCode: number | null = null;

          child.on("close", (code) => {
            exited = true;
            exitCode = code;
          });

          child.on("error", (err) => {
            exited = true;
            safeResolve({
              success: false,
              error: err.message,
              stdout,
              stderr,
              command,
            });
          });

          const settleMs = timeout != null ? timeout * 1_000 : 2_000;
          setTimeout(() => {
            if (exited) {
              // Process already exited during the settle period
              safeResolve({
                success: exitCode === 0,
                stdout: truncateOutput(stdout) || "(no output)",
                stderr: stderr || "",
                command,
                error:
                  exitCode !== 0
                    ? `Process exited during startup (code ${exitCode})`
                    : "",
              });
            } else {
              // Still running — detach so Node doesn't wait on it
              child.stdout.removeAllListeners("data");
              child.stderr.removeAllListeners("data");
              child.stdout.resume();
              child.stderr.resume();
              child.removeAllListeners("close");
              child.removeAllListeners("error");
              child.unref();

              safeResolve({
                success: true,
                stdout:
                  truncateOutput(stdout) ||
                  "(process running, no output yet)",
                stderr: stderr || "",
                command,
                error: "",
                pid: child.pid,
                isBackgroundProcess: true,
              });
            }
          }, settleMs);
        } else {
          // Foreground: wait for completion or timeout
          const timeoutTimer =
            timeout != null
              ? setTimeout(killProcess, timeout * 1_000)
              : undefined;

          child.on("close", (code) => {
            if (timeoutTimer) clearTimeout(timeoutTimer);
            safeResolve({
              success: code === 0 && !killed,
              stdout: truncateOutput(stdout) || "(no output)",
              stderr: stderr || "",
              command,
              error: killed
                ? "Command timed out"
                : code !== 0
                  ? `Exit code: ${code}`
                  : "",
            });
          });

          child.on("error", (err) => {
            if (timeoutTimer) clearTimeout(timeoutTimer);
            safeResolve({
              success: false,
              error: err.message,
              stdout,
              stderr,
              command,
            });
          });
        }

        // Abort signal: kill the process (foreground or background) when the
        // agent is cancelled by the user.
        if (ctx.abortSignal) {
          const abortHandler = () => killProcess();
          ctx.abortSignal.addEventListener("abort", abortHandler, {
            once: true,
          });
          child.on("close", () => {
            ctx.abortSignal!.removeEventListener("abort", abortHandler);
          });
        }
      });
    },
  });
}

// ---------------------------------------------------------------------------
// Sandbox helpers
// ---------------------------------------------------------------------------

async function sandboxBackground(
  ctx: ToolContext,
  command: string,
): Promise<ExecuteCommandResult> {
  try {
    const escaped = command.replace(/'/g, "'\\''");
    const logFile = `/tmp/bg_${Date.now()}.log`;
    const result = await ctx.sandbox!.execute(
      `nohup bash -c '${escaped}' > ${logFile} 2>&1 & echo $!`,
      { timeout: 10 },
    );
    const bgPid = parseInt(result.stdout.trim(), 10);
    return {
      success: true,
      error: "",
      stdout: `Background process started (PID: ${isNaN(bgPid) ? "unknown" : bgPid}). Output: ${logFile}`,
      stderr: "",
      command,
      pid: isNaN(bgPid) ? undefined : bgPid,
      isBackgroundProcess: true,
    };
  } catch (error: unknown) {
    const msg = error instanceof Error ? error.message : String(error);
    return { success: false, error: msg, stdout: "", stderr: msg, command };
  }
}

async function sandboxForeground(
  ctx: ToolContext,
  command: string,
  timeout?: number,
): Promise<ExecuteCommandResult> {
  try {
    const ssmOpts: { timeout?: number } = {};
    if (timeout != null) {
      ssmOpts.timeout = timeout;
    }
    const result = await ctx.sandbox!.execute(command, ssmOpts);
    return {
      success: result.success,
      error: !result.success ? result.stderr || "Command failed" : "",
      stdout: truncateOutput(result.stdout) || "(no output)",
      stderr: result.stderr || "",
      command,
    };
  } catch (error: unknown) {
    const msg = error instanceof Error ? error.message : String(error);
    return { success: false, error: msg, stdout: "", stderr: msg, command };
  }
}
