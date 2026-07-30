import { existsSync, mkdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { tool } from "ai";
import { z } from "zod";
import { screenshotCommand } from "../../../../desktop";
import type { ToolContext } from "../types";
import { localExec, resolveDesktopOs } from "./runtime";

interface ScreenshotResult {
  success: boolean;
  message: string;
  filePath?: string;
  imageBase64?: string;
}

/**
 * Capture the current screen. Returns the PNG as base64 (surfaced to the model
 * as an image via `toModelOutput`) and persists a copy under the session
 * evidence dir, mirroring the browser screenshot tool.
 */
export function computerScreenshot(ctx: ToolContext) {
  return tool({
    description: `Take a screenshot of the current desktop screen.

Returns the screenshot as an image so you can visually inspect the current state
of the desktop and the application under test. The PNG is also saved to the
session evidence directory for later reference.

Always take a screenshot before interacting so you know what is on screen and
where UI elements are, and again after an action to verify its effect.`,
    inputSchema: z.object({
      toolCallDescription: z
        .string()
        .describe("Why you are taking this screenshot"),
    }),
    execute: async (): Promise<ScreenshotResult> => {
      try {
        const os = resolveDesktopOs();
        const evidenceDir = join(
          ctx.session.rootPath,
          "evidence",
          "screenshots",
        );
        if (!existsSync(evidenceDir)) {
          mkdirSync(evidenceDir, { recursive: true });
        }
        const ts = new Date().toISOString().replace(/[:.]/g, "-");
        const filePath = join(evidenceDir, `screenshot-${ts}.png`);

        const result = await localExec(screenshotCommand(os, filePath));
        if (!result.success || !existsSync(filePath)) {
          const detail = (result.stderr || result.stdout).trim();
          return {
            success: false,
            message: `Failed to take screenshot${detail ? `: ${detail}` : ""}`,
          };
        }

        const imageBase64 = readFileSync(filePath).toString("base64");
        return {
          success: true,
          message: `Screenshot saved to ${filePath}`,
          filePath,
          imageBase64,
        };
      } catch (error) {
        const msg = error instanceof Error ? error.message : String(error);
        return { success: false, message: `Failed to take screenshot: ${msg}` };
      }
    },
    toModelOutput: ({ output }) => {
      const result = output as ScreenshotResult;
      if (result.success && result.imageBase64) {
        return {
          type: "content",
          value: [
            { type: "text", text: result.message },
            {
              type: "media",
              data: result.imageBase64,
              mediaType: "image/png",
            },
          ],
        };
      }
      return {
        type: "content",
        value: [{ type: "text", text: result.message }],
      };
    },
  });
}
