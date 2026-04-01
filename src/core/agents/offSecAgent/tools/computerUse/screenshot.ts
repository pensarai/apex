import { tool } from "ai";
import { z } from "zod";
import { join } from "path";
import { mkdirSync, existsSync, readFileSync } from "fs";
import type { ToolContext } from "../types";
import { getDesktopBackend } from "./platform";

export function computerScreenshot(ctx: ToolContext) {
  return tool({
    description: `Take a screenshot of the current screen.

Returns the screenshot as a base64-encoded PNG image that can be analyzed visually.
Use this to observe the current state of the desktop, verify UI changes, or capture
evidence during penetration testing.

The screenshot is also saved to the session's evidence directory for later reference.`,
    inputSchema: z.object({
      toolCallDescription: z
        .string()
        .describe("Why you are taking this screenshot"),
    }),
    execute: async (): Promise<{
      success: boolean;
      message: string;
      filePath?: string;
      imageBase64?: string;
    }> => {
      try {
        const backend = getDesktopBackend();

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

        backend.screenshot(filePath);

        const imageBuffer = readFileSync(filePath);
        const imageBase64 = imageBuffer.toString("base64");

        return {
          success: true,
          message: `Screenshot saved to ${filePath}`,
          filePath,
          imageBase64,
        };
      } catch (error) {
        const msg = error instanceof Error ? error.message : String(error);
        return {
          success: false,
          message: `Failed to take screenshot: ${msg}`,
        };
      }
    },
  });
}
