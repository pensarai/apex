import { tool } from "ai";
import { z } from "zod";
import { resolveBackends } from "../../../tools/backends";
import type { ToolContext } from "./types";

const getPageInputSchema = z.object({
  url: z
    .string()
    .url()
    .describe("The URL of the page to fetch and extract content from."),
  toolCallDescription: z
    .string()
    .describe(
      "A concise, human-readable description of what this tool call is doing (e.g., 'Fetching CVE details from NVD')",
    ),
});

export interface GetPageResponse {
  success: boolean;
  url: string;
  title?: string;
  content?: string;
  error?: string;
}

/**
 * `get_page` — a thin alias over `http_request` with `extract: 'readability'`
 * (design §5.4, Appendix L: the one safe tool-name merge). Kept as its own
 * model-facing name because prompts and `activeTools` lists across the agent
 * definitions still reference it by name; the fetch/extraction logic itself
 * lives once in `LocalBackends.http` (`src/core/tools/backends/local.ts`).
 */
export function getPage(ctx: ToolContext) {
  return tool({
    description: `Fetch and extract readable content from a web page. Returns the page title and main text content.

USAGE GUIDANCE:
- Use this tool to read full content from URLs found via web_search
- Fetch CVE details, security advisories, and vulnerability write-ups
- Read documentation, API references, and technical guides
- Extract exploit code, payloads, and proof-of-concept details from security blogs

BEST PRACTICES:
- First use web_search to find relevant URLs, then use get_page to read the full content
- Prefer authoritative sources (NVD, vendor advisories, security researcher blogs)
- For large pages, focus on the most relevant sections
- If content is truncated, the important information is usually near the beginning`,
    inputSchema: getPageInputSchema,
    execute: async ({ url }): Promise<GetPageResponse> => {
      const response = await resolveBackends(ctx).http.request(
        { url, extract: "readability" },
        { abortSignal: ctx.abortSignal },
      );
      if (!response.success) {
        return { success: false, url, error: response.error };
      }
      return {
        success: true,
        url: response.url,
        title: response.title,
        content: response.body,
      };
    },
  });
}
