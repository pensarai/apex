import { tool } from "ai";
import { z } from "zod";
import { extractJavascriptEndpoints } from "../../agents/attackSurface/jsExtraction";

/**
 * Factory for the `extract_js_endpoints` tool.
 *
 * Thin wrapper around the existing jsExtraction helper.
 * No ToolContext needed — the helper is stateless.
 */
export function extractJsEndpoints(_ctx: unknown) {
  return tool({
    description: `Extract endpoint URLs from JavaScript code in a page using pattern matching.

Uses regex patterns to find:
- AJAX calls ($.ajax, $.get, $.post)
- Fetch API calls
- Axios requests
- XMLHttpRequest calls
- URL assignments

Returns all discovered endpoint patterns.`,
    inputSchema: z.object({
      url: z.string().describe("URL of the page to analyze"),
      sessionCookie: z
        .string()
        .optional()
        .describe("Session cookie for authenticated pages"),
      includeExternalJS: z
        .boolean()
        .default(true)
        .describe("Whether to download and analyze external JS files"),
      toolCallDescription: z
        .string()
        .describe(
          "A concise, human-readable description of what this tool call is doing",
        ),
    }),
    execute: async (params) => {
      return extractJavascriptEndpoints(params);
    },
  });
}
