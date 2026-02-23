import { tool } from "ai";
import { z } from "zod";
import { spawn } from "child_process";
import type { ToolContext } from "./types";

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
          return {
            success: result.success,
            error: !result.success ? result.stderr || "Command failed" : "",
            stdout:
              result.stdout.length > 50000
                ? `${result.stdout.substring(0, 50000)}...\n\n(truncated) call the command again with grep / tail to paginate`
                : result.stdout || "(no output)",
            stderr: result.stderr || "",
            command,
          };
        } catch (error: unknown) {
          const msg = error instanceof Error ? error.message : String(error);
          return { success: false, error: msg, stdout: "", stderr: msg, command };
        }
      }

      // Local mode: spawn a child process
      return new Promise((resolve) => {
        const shellCmd = process.platform === "win32" ? "cmd" : "bash";
        const shellArgs =
          process.platform === "win32" ? ["/c", command] : ["-lc", command];

        const child = spawn(shellCmd, shellArgs, {
          stdio: ["ignore", "pipe", "pipe"],
        });

        let stdout = "";
        let stderr = "";
        let killed = false;

        const timeoutTimer = setTimeout(() => {
          killed = true;
          child.kill("SIGTERM");
        }, timeout);

        child.stdout.on("data", (data) => {
          stdout += data.toString();
        });

        child.stderr.on("data", (data) => {
          stderr += data.toString();
        });

        child.on("close", (code) => {
          clearTimeout(timeoutTimer);
          resolve({
            success: code === 0 && !killed,
            stdout:
              stdout.length > 50000
                ? `${stdout.substring(0, 50000)}...\n\n(truncated) call the command again with grep / tail to paginate`
                : stdout || "(no output)",
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
          clearTimeout(timeoutTimer);
          resolve({
            success: false,
            error: err.message,
            stdout,
            stderr,
            command,
          });
        });

        if (ctx.abortSignal) {
          const abortHandler = () => {
            killed = true;
            child.kill("SIGTERM");
          };
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
