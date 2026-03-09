import { tool } from "ai";
import { z } from "zod";
import { join } from "path";
import { writeFileSync, mkdirSync, existsSync } from "fs";
import type { ToolContext } from "./types";

const MAX_INLINE = 4_500;

const DEFAULT_TIMEOUT_SECONDS = 30;

export const executeCommandInputSchema = z.object({
  command: z.string().describe("The shell command to execute"),
  timeout: z
    .number()
    .optional()
    .describe(
      `Timeout in seconds (default: ${DEFAULT_TIMEOUT_SECONDS}). For long-running scans, set a higher value.`,
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
  outputFile?: string;
};

/**
 * Strip HTML `<style>` and `<script>` blocks from text that looks like HTML.
 * Reduces noise from web server responses captured in command output.
 */
function stripHtmlNoise(text: string): string {
  if (!/<(?:style|script|html|head|body)\b/i.test(text)) return text;
  return text
    .replace(/<style[^>]*>[\s\S]*?<\/style>/gi, "")
    .replace(/<script[^>]*>[\s\S]*?<\/script>/gi, "");
}

/**
 * If `raw` exceeds the inline limit, save the full text to a file under
 * `{session.logsPath}/cmd-output/` and return truncated text + file path.
 * Otherwise return the text as-is with no file.
 *
 * Uses head+tail truncation (first 3,000 + last 1,500 chars) to preserve
 * both the beginning (headers, initial output) and end (final results,
 * error messages) of long outputs.
 */
function maybeSaveFullOutput(
  raw: string,
  ctx: ToolContext,
): { text: string; file?: string } {
  // Strip noisy HTML blocks before size check
  const cleaned = stripHtmlNoise(raw);

  if (cleaned.length <= MAX_INLINE) {
    return { text: cleaned || "(no output)" };
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
    const head = cleaned.substring(0, 3_000);
    return {
      text: `${head}...\n\n(truncated — failed to save full output to file)`,
    };
  }

  // Head + tail truncation: first 3,000 chars + last 1,500 chars
  const HEAD = 3_000;
  const TAIL = 1_500;
  const head = cleaned.substring(0, HEAD);
  const tail = cleaned.substring(cleaned.length - TAIL);
  const truncated = `${head}\n\n... [${cleaned.length - HEAD - TAIL} chars trimmed] ...\n\n${tail}`;

  return {
    text: `${truncated}\n\n(truncated — full output saved to ${filePath}). Run the command again with grep/tail/head to extract specific data.`,
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
      timeout = DEFAULT_TIMEOUT_SECONDS,
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
          const ssmOpts: { timeout?: number } = {};
          if (timeout != null) {
            ssmOpts.timeout = timeout;
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
          const result = await ctx.persistentShell.execute(
            command,
            timeout,
            ctx.onCommandOutput,
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
