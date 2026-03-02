import { tool } from "ai";
import { z } from "zod";
import { spawn } from "child_process";
import type { ToolContext } from "./types";
import {
  persistCommandOutput,
  shouldPersistOutput,
  OUTPUT_SIZE_THRESHOLD,
} from "./outputPersistence";

export const executeCommandInputSchema = z.object({
  command: z.string().describe("The shell command to execute"),
  timeout: z
    .number()
    .optional()
    .describe("Timeout in milliseconds (default: 30000)"),
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
  /** Path to persisted output file when output exceeds threshold */
  outputPath?: string;
};

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
- Use timeout command for long-running scans

IMPORTANT: Always analyze results and adjust your approach based on findings.`,
    inputSchema: executeCommandInputSchema,
    execute: async ({
      command,
      timeout = 30000,
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

      // Sandbox mode: route execution through the sandbox
      if (ctx.sandbox) {
        try {
          const ssmTimeout = Math.max(Math.ceil(timeout / 1000), 30);
          const result = await ctx.sandbox.execute(command, {
            timeout: ssmTimeout,
          });

          const rawStdout = result.stdout || "(no output)";
          const rawStderr = result.stderr || "";

          // Persist large outputs to file and return path
          if (shouldPersistOutput(rawStdout, rawStderr)) {
            const persisted = persistCommandOutput(
              ctx.session,
              command,
              rawStdout,
              rawStderr,
              result.success ? 0 : 1,
            );
            return {
              success: result.success,
              error: !result.success ? rawStderr || "Command failed" : "",
              stdout: `Output saved to: ${persisted.relativePath}\n\nPreview (first ${OUTPUT_SIZE_THRESHOLD} chars):\n${rawStdout.substring(0, OUTPUT_SIZE_THRESHOLD)}...`,
              stderr: rawStderr.length > 1000 ? rawStderr.substring(0, 1000) + "..." : rawStderr,
              command,
              outputPath: persisted.relativePath,
            };
          }

          return {
            success: result.success,
            error: !result.success ? rawStderr || "Command failed" : "",
            stdout: rawStdout,
            stderr: rawStderr,
            command,
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

      // Local mode: spawn a child process
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

        // Helper to resolve with output persistence logic
        const resolveWithPersistence = (
          success: boolean,
          rawStdout: string,
          rawStderr: string,
          error: string,
          exitCode?: number,
        ) => {
          const finalStdout = rawStdout || "(no output)";
          const finalStderr = rawStderr || "";

          if (shouldPersistOutput(finalStdout, finalStderr)) {
            const persisted = persistCommandOutput(
              ctx.session,
              command,
              finalStdout,
              finalStderr,
              exitCode,
            );
            safeResolve({
              success,
              stdout: `Output saved to: ${persisted.relativePath}\n\nPreview (first ${OUTPUT_SIZE_THRESHOLD} chars):\n${finalStdout.substring(0, OUTPUT_SIZE_THRESHOLD)}...`,
              stderr: finalStderr.length > 1000 ? finalStderr.substring(0, 1000) + "..." : finalStderr,
              command,
              error,
              outputPath: persisted.relativePath,
            });
          } else {
            safeResolve({
              success,
              stdout: finalStdout,
              stderr: finalStderr,
              command,
              error,
            });
          }
        };

        const killProcess = () => {
          if (killed) return;
          killed = true;

          try {
            // Kill the entire process group (negative PID) so subprocesses
            // spawned by bash (nmap, gobuster, etc.) are also terminated.
            if (child.pid && process.platform !== "win32") {
              process.kill(-child.pid, "SIGTERM");
            } else {
              child.kill("SIGTERM");
            }
          } catch {
            // Process may have already exited
          }

          // SIGKILL fallback: if SIGTERM doesn't work after 5 seconds,
          // force-kill and resolve the promise so the agent doesn't hang.
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

            resolveWithPersistence(
              false,
              stdout,
              stderr,
              "Command killed (did not exit after SIGTERM)",
              1,
            );
          }, 5000);
        };

        const timeoutTimer = setTimeout(killProcess, timeout);

        child.stdout.on("data", (data) => {
          stdout += data.toString();
        });

        child.stderr.on("data", (data) => {
          stderr += data.toString();
        });

        child.on("close", (code) => {
          clearTimeout(timeoutTimer);
          resolveWithPersistence(
            code === 0 && !killed,
            stdout,
            stderr,
            killed
              ? "Command timed out"
              : code !== 0
                ? `Exit code: ${code}`
                : "",
            code ?? 1,
          );
        });

        child.on("error", (err) => {
          clearTimeout(timeoutTimer);
          resolveWithPersistence(false, stdout, stderr, err.message, 1);
        });

        // Wire up abort signal
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
