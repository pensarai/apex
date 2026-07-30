import { tool } from "ai";
import { z } from "zod";
import { screenInfoCommand } from "../../../../desktop";
import type { ToolContext } from "../types";
import { localExec, resolveDesktopOs } from "./runtime";

interface ScreenInfoResult {
  success: boolean;
  message: string;
  width?: number;
  height?: number;
  mouseX?: number;
  mouseY?: number;
  activeWindowTitle?: string;
}

// Parse a `KEY=VALUE` line (SIZE=W,H / POS=X,Y / TITLE=…) from the builder's
// stdout contract.
function parseScreenInfo(stdout: string): Omit<ScreenInfoResult, "message"> {
  const out: Omit<ScreenInfoResult, "message"> = { success: true };
  for (const line of stdout.split(/\r?\n/)) {
    const eq = line.indexOf("=");
    if (eq === -1) continue;
    const key = line.slice(0, eq).trim().toUpperCase();
    const value = line.slice(eq + 1).trim();
    if (key === "SIZE") {
      const [w, h] = value.split(",").map((n) => Number.parseInt(n, 10));
      if (Number.isFinite(w)) out.width = w;
      if (Number.isFinite(h)) out.height = h;
    } else if (key === "POS") {
      const [x, y] = value.split(",").map((n) => Number.parseInt(n, 10));
      if (Number.isFinite(x)) out.mouseX = x;
      if (Number.isFinite(y)) out.mouseY = y;
    } else if (key === "TITLE") {
      out.activeWindowTitle = value;
    }
  }
  return out;
}

/** Report screen size, cursor position, and the active window title. */
export function computerScreenInfo(_ctx: ToolContext) {
  return tool({
    description: `Get information about the desktop: screen dimensions, current
mouse position, and the title of the active window.

Use this to learn the coordinate bounds before clicking, to confirm the cursor
location, or to check which window currently has focus.`,
    inputSchema: z.object({
      toolCallDescription: z
        .string()
        .describe("Why you are querying screen info"),
    }),
    execute: async (): Promise<ScreenInfoResult> => {
      const os = resolveDesktopOs();
      const result = await localExec(screenInfoCommand(os));
      if (!result.success) {
        const detail = (result.stderr || result.stdout).trim();
        return {
          success: false,
          message: `Failed to read screen info${detail ? `: ${detail}` : ""}`,
        };
      }
      const parsed = parseScreenInfo(result.stdout);
      const size =
        parsed.width != null && parsed.height != null
          ? `${parsed.width}x${parsed.height}`
          : "unknown";
      const pos =
        parsed.mouseX != null && parsed.mouseY != null
          ? `(${parsed.mouseX}, ${parsed.mouseY})`
          : "unknown";
      return {
        ...parsed,
        message: `Screen ${size}, mouse ${pos}, active window: ${
          parsed.activeWindowTitle || "unknown"
        }`,
      };
    },
  });
}
