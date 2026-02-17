/**
 * Browser tool wrappers for the general agent harness.
 *
 * Delegates to the existing {@link createBrowserTools} factory from
 * `browserTools/playwrightMcp.ts`, which provisions 8 Playwright MCP
 * tools. The mode is set to `"operator"` (generic reconnaissance) by
 * default — the descriptions are broad enough for recon, auth flows,
 * and pentest use-cases alike.
 *
 * Individual agents don't need to worry about Playwright initialisation
 * or MCP plumbing — they just list the browser tool names they want
 * in their `activeTools` array.
 */

import { join } from "path";
import { createBrowserTools } from "./playwrightMcp";
import type { ToolContext } from "./types";

/**
 * All browser tool names that get registered in the harness.
 */
export const BROWSER_TOOL_NAMES = [
  "browser_navigate",
  "browser_snapshot",
  "browser_screenshot",
  "browser_click",
  "browser_fill",
  "browser_evaluate",
  "browser_console",
  "browser_get_cookies",
] as const;

export type BrowserToolName = (typeof BROWSER_TOOL_NAMES)[number];

/**
 * Create the full set of browser automation tools from a {@link ToolContext}.
 *
 * Uses `"operator"` mode by default for the most general-purpose descriptions.
 * The evidence directory is derived from `session.rootPath + "/evidence"`.
 */
export function createBrowserToolset(ctx: ToolContext) {
  const evidenceDir = join(ctx.session.rootPath, "evidence");
  const targetUrl = ctx.target ?? "";

  return createBrowserTools(
    targetUrl,
    evidenceDir,
    "operator", // generic mode — works for recon, auth, and pentest
    undefined, // no Logger (tools use console)
    ctx.abortSignal,
  );
}
