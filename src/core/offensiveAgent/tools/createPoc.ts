import { tool } from "ai";
import { z } from "zod";
import { join } from "path";
import { spawn } from "child_process";
import { existsSync, writeFileSync, chmodSync, unlinkSync, mkdirSync } from "fs";
import type { ToolContext } from "./types";

const MAX_POC_ATTEMPTS = 3;

function sanitizeFilename(str: string): string {
  return str
    .toLowerCase()
    .replace(/[^a-z0-9_-]/g, "_")
    .replace(/_+/g, "_")
    .replace(/^_|_$/g, "")
    .substring(0, 50);
}

export const createPocInputSchema = z.object({
  pocName: z.string().describe("Short descriptive name for the POC"),
  pocType: z
    .enum(["bash", "python", "javascript"])
    .describe("Script language"),
  pocContent: z.string().describe("The full POC script content"),
  description: z.string().describe("What this POC demonstrates"),
  toolCallDescription: z
    .string()
    .describe(
      "A concise, human-readable description of what this tool call is doing"
    ),
});

export type CreatePocInput = z.infer<typeof createPocInputSchema>;

export type CreatePocResult = {
  success: boolean;
  pocPath?: string;
  stdout?: string;
  stderr?: string;
  exitCode?: number;
  error?: string;
  attemptsRemaining?: number;
};

export function createPoc(ctx: ToolContext) {
  const pocAttempts = new Map<string, number>();

  return tool({
    description: `Create and test a Proof-of-Concept script.

Supported languages:
- **Bash** (.sh) - Preferred for simple HTTP/curl-based POCs
- **Python** (.py) - For complex scenarios with requests library
- **JavaScript** (.js) - For Node.js-based exploitation

This tool:
1. Creates the POC file in the pocs/ directory
2. Makes executable and runs it
3. Returns execution output for analysis
4. Deletes the file if execution fails

POC requirements:
- Exit 0 on success (vuln confirmed), 1 on failure
- Print clear evidence of exploitation
- Include rate limiting (sleep between requests)

Max ${MAX_POC_ATTEMPTS} attempts per approach before pivoting.`,
    inputSchema: createPocInputSchema,
    execute: async (poc: CreatePocInput): Promise<CreatePocResult> => {
      const approachKey = `${poc.pocName}_${poc.description.substring(0, 30)}`;
      const currentAttempts = (pocAttempts.get(approachKey) || 0) + 1;
      pocAttempts.set(approachKey, currentAttempts);

      if (currentAttempts > MAX_POC_ATTEMPTS) {
        return {
          success: false,
          error: `Max attempts (${MAX_POC_ATTEMPTS}) reached for this approach. Pivot to a different technique.`,
          attemptsRemaining: 0,
        };
      }

      try {
        const pocsPath = ctx.session.pocsPath;
        if (!existsSync(pocsPath)) {
          mkdirSync(pocsPath, { recursive: true });
        }

        const extension =
          poc.pocType === "bash"
            ? ".sh"
            : poc.pocType === "python"
            ? ".py"
            : ".js";
        const sanitizedName = sanitizeFilename(poc.pocName);
        const filename = `poc_${sanitizedName}${extension}`;
        const pocPath = join(pocsPath, filename);

        let pocContent = poc.pocContent.trim();

        // Add shebang if missing
        if (!pocContent.startsWith("#!")) {
          const shebangs: Record<string, string> = {
            bash: "#!/bin/bash\nset -e\n\n",
            python: "#!/usr/bin/env python3\n\n",
            javascript: "#!/usr/bin/env node\n\n",
          };
          pocContent = shebangs[poc.pocType] + pocContent;
        }

        // Add header comment
        const commentChar = poc.pocType === "javascript" ? "//" : "#";
        const header = `${commentChar} POC: ${poc.description}\n${commentChar} Created: ${new Date().toISOString()}\n${commentChar} Attempt: ${currentAttempts}/${MAX_POC_ATTEMPTS}\n\n`;
        const afterShebang = pocContent.replace(/^#!.*\n/, (match) => match + header);
        pocContent = afterShebang;

        writeFileSync(pocPath, pocContent);
        chmodSync(pocPath, 0o755);

        // Execute the POC
        const runner =
          poc.pocType === "bash"
            ? "bash"
            : poc.pocType === "python"
            ? "python3"
            : "node";

        const { stdout, stderr, exitCode } = await runScript(
          runner,
          pocPath,
          60000,
          ctx.abortSignal
        );

        // Delete on failure
        if (exitCode !== 0) {
          try {
            unlinkSync(pocPath);
          } catch {
            // ignore cleanup errors
          }
        }

        return {
          success: exitCode === 0,
          pocPath: exitCode === 0 ? `pocs/${filename}` : undefined,
          stdout,
          stderr,
          exitCode,
          attemptsRemaining: MAX_POC_ATTEMPTS - currentAttempts,
          error:
            exitCode !== 0
              ? `POC exited with code ${exitCode}. ${MAX_POC_ATTEMPTS - currentAttempts} attempts remaining.`
              : undefined,
        };
      } catch (error: unknown) {
        const errorMsg = error instanceof Error ? error.message : String(error);
        return {
          success: false,
          error: errorMsg,
          attemptsRemaining: MAX_POC_ATTEMPTS - currentAttempts,
        };
      }
    },
  });
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function runScript(
  runner: string,
  scriptPath: string,
  timeout: number,
  abortSignal?: AbortSignal
): Promise<{ stdout: string; stderr: string; exitCode: number }> {
  return new Promise((resolve) => {
    const child = spawn(runner, [scriptPath], {
      stdio: ["ignore", "pipe", "pipe"],
      timeout,
    });

    let stdout = "";
    let stderr = "";

    child.stdout.on("data", (data) => {
      stdout += data.toString();
    });
    child.stderr.on("data", (data) => {
      stderr += data.toString();
    });

    child.on("close", (code) => {
      resolve({ stdout, stderr, exitCode: code ?? 1 });
    });

    child.on("error", (err) => {
      resolve({ stdout, stderr, exitCode: 1 });
    });

    if (abortSignal) {
      const handler = () => child.kill("SIGTERM");
      abortSignal.addEventListener("abort", handler, { once: true });
      child.on("close", () =>
        abortSignal.removeEventListener("abort", handler)
      );
    }
  });
}
