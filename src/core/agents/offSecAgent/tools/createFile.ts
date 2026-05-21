import { tool } from "ai";
import { existsSync } from "fs";
import { mkdir, writeFile } from "fs/promises";
import { dirname, isAbsolute, resolve } from "path";
import { z } from "zod";
import type { ToolContext } from "./types";

const createFileInputSchema = z.object({
  path: z.string().describe("Absolute or relative path for the new file"),
  content: z.string().describe("Content to write to the file"),
  overwrite: z
    .boolean()
    .optional()
    .describe(
      "If true, overwrite the file if it already exists (default: false)",
    ),
  toolCallDescription: z
    .string()
    .describe(
      "A concise, human-readable description of what this tool call is doing (e.g., 'Creating security middleware file')",
    ),
});

type CreateFileInput = z.infer<typeof createFileInputSchema>;

export type CreateFileResult = {
  success: boolean;
  error: string;
  path: string;
};

export function createFile(ctx: ToolContext) {
  return tool({
    description: `Create a new file with the given content.

By default, refuses to overwrite an existing file. Set overwrite=true to replace
an existing file's content entirely.

Parent directories are created automatically if they don't exist.`,
    inputSchema: createFileInputSchema,
    execute: async ({
      path: filePath,
      content,
      overwrite = false,
    }): Promise<CreateFileResult> => {
      const resolved = isAbsolute(filePath)
        ? filePath
        : resolve(ctx.agentCwd, filePath);
      if (ctx.sandbox) {
        return executeSandboxCreate(ctx, resolved, content, overwrite);
      }
      return executeLocalCreate(resolved, content, overwrite);
    },
  });
}

async function executeLocalCreate(
  filePath: string,
  content: string,
  overwrite: boolean,
): Promise<CreateFileResult> {
  try {
    if (!overwrite && existsSync(filePath)) {
      return {
        success: false,
        error: `File already exists: ${filePath}. Set overwrite=true to replace it.`,
        path: filePath,
      };
    }

    const dir = dirname(filePath);
    await mkdir(dir, { recursive: true });
    await writeFile(filePath, content, "utf-8");

    return {
      success: true,
      error: "",
      path: filePath,
    };
  } catch (err: unknown) {
    return {
      success: false,
      error: err instanceof Error ? err.message : String(err),
      path: filePath,
    };
  }
}

async function executeSandboxCreate(
  ctx: ToolContext,
  filePath: string,
  content: string,
  overwrite: boolean,
): Promise<CreateFileResult> {
  try {
    if (!overwrite) {
      const checkResult = await ctx.sandbox!.execute(`test -e "${filePath}"`);
      if (checkResult.exitCode === 0) {
        return {
          success: false,
          error: `File already exists: ${filePath}. Set overwrite=true to replace it.`,
          path: filePath,
        };
      }
    }

    const dirPath = dirname(filePath);
    await ctx.sandbox!.execute(`mkdir -p "${dirPath}"`);

    const base64Content = Buffer.from(content).toString("base64");
    const writeResult = await ctx.sandbox!.execute(
      `echo "${base64Content}" | base64 -d > "${filePath}"`,
    );

    if (!writeResult.success) {
      return {
        success: false,
        error: writeResult.stderr || "Failed to write file in sandbox",
        path: filePath,
      };
    }

    return {
      success: true,
      error: "",
      path: filePath,
    };
  } catch (err: unknown) {
    return {
      success: false,
      error: err instanceof Error ? err.message : String(err),
      path: filePath,
    };
  }
}
