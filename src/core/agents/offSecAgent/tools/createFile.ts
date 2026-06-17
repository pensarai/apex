import { tool } from "ai";
import { existsSync } from "node:fs";
import { mkdir, writeFile } from "node:fs/promises";
import { dirname, isAbsolute, resolve } from "node:path";
import { z } from "zod";
import { createLogger } from "../../../logger/structured";
import { scopedLogger } from "../../../util/lazyLogger";
import type { ToolContext } from "./types";

const log = scopedLogger(() => createLogger("create_file"));

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
      log.debug(
        `enter: path=${filePath}, contentLen=${content.length}, overwrite=${overwrite}, sandbox=${!!ctx.sandbox}`,
      );
      const resolved = isAbsolute(filePath)
        ? filePath
        : resolve(ctx.agentCwd, filePath);
      log.debug(`resolved: ${resolved}`);
      if (ctx.sandbox) {
        return executeSandboxCreate(ctx, resolved, content, overwrite);
      }
      const result = await executeLocalCreate(resolved, content, overwrite);
      log.debug(
        `done: success=${result.success}, error=${result.error || "(none)"}`,
      );
      return result;
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
      log.debug(`local: file already exists: ${filePath}`);
      return {
        success: false,
        error: `File already exists: ${filePath}. Set overwrite=true to replace it.`,
        path: filePath,
      };
    }

    const dir = dirname(filePath);
    log.debug(`local: mkdir ${dir}`);
    await mkdir(dir, { recursive: true });
    log.debug(`local: mkdir done, writing ${content.length} bytes`);
    await writeFile(filePath, content, "utf-8");
    log.debug("local: writeFile done");

    return {
      success: true,
      error: "",
      path: filePath,
    };
  } catch (err: unknown) {
    log.error("local: write failed", err instanceof Error ? err : undefined, {
      error: String(err),
    });
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
      const checkResult = await ctx.sandbox?.execute(`test -e "${filePath}"`);
      if (checkResult.exitCode === 0) {
        return {
          success: false,
          error: `File already exists: ${filePath}. Set overwrite=true to replace it.`,
          path: filePath,
        };
      }
    }

    const dirPath = dirname(filePath);
    await ctx.sandbox?.execute(`mkdir -p "${dirPath}"`);

    const base64Content = Buffer.from(content).toString("base64");
    const writeResult = await ctx.sandbox?.execute(
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
