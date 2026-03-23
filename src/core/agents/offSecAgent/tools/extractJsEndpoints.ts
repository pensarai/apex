import { tool } from "ai";
import { z } from "zod";
import { extractJavascriptEndpoints } from "../../specialized/attackSurface/jsExtraction";

/**
 * Factory for the `extract_js_endpoints` tool.
 *
 * Thin wrapper around the existing jsExtraction helper.
 * No ToolContext needed — the helper is stateless.
 */
export function extractJsEndpoints(_ctx: unknown) {
  return tool({
    description:
      "Extract endpoint URLs from JavaScript sources in a page via regex (fetch, axios, AJAX, URL patterns). Returns discovered endpoint paths.",
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
    }),
    execute: async (params) => {
      return extractJavascriptEndpoints(params);
    },
  });
}
