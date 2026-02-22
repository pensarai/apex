import { tool } from "ai";
import { z } from "zod";
import { spawn } from "child_process";
import type { ToolContext } from "./types";
import {
  writeToolOutput,
  createOutputReference,
  OUTPUT_THRESHOLDS,
} from "./outputWriter";

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
  outputFilePath?: string;
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
- Large outputs are automatically saved to files for detailed analysis

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

      const rawResult = await new Promise<{
        success: boolean;
        stdout: string;
        stderr: string;
        error: string;
      }>((resolve) => {
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
            stdout: stdout || "(no output)",
            stderr: stderr || "",
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

      const threshold = OUTPUT_THRESHOLDS.EXECUTE_COMMAND;
      if (rawResult.stdout.length > threshold) {
        const fullOutput = `Command: ${command}\n\n--- STDOUT ---\n${rawResult.stdout}\n\n--- STDERR ---\n${rawResult.stderr}`;

        try {
          const { outputFilePath } = await writeToolOutput(
            ctx.session,
            "execute_command",
            fullOutput,
          );

          return {
            success: rawResult.success,
            stdout: createOutputReference(
              outputFilePath,
              rawResult.stdout.substring(0, 2000),
              rawResult.stdout.length,
            ),
            stderr: rawResult.stderr,
            command,
            error: rawResult.error,
            outputFilePath,
          };
        } catch {
          return {
            success: rawResult.success,
            stdout:
              rawResult.stdout.substring(0, threshold) +
              `...\n\n(truncated, ${rawResult.stdout.length} bytes total) call the command again with grep / tail to paginate`,
            stderr: rawResult.stderr,
            command,
            error: rawResult.error,
          };
        }
      }

      return {
        success: rawResult.success,
        stdout: rawResult.stdout,
        stderr: rawResult.stderr,
        command,
        error: rawResult.error,
      };
    },
  });
}
