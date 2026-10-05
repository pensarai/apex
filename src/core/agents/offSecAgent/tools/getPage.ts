import { tool } from "ai";
import { z } from "zod";
import { resolveBackends } from "../../../tools/backends/resolve";
import type { ToolContext } from "./types";

const REQUEST_TIMEOUT = 30_000;

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

type GetPageInput = z.infer<typeof getPageInputSchema>;

export interface GetPageResponse {
  success: boolean;
  url: string;
  title?: string;
  content?: string;
  error?: string;
  /** True when the returned content is not the complete page text. */
  contentTruncated?: boolean;
  /** Why the content stopped: preview limit, capture cap, or a failed read. */
  stopReason?: "content-limit" | "byte-cap" | "timeout" | "aborted" | "error";
}

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
      {
        const response = await resolveBackends(ctx).http.request(
          { url, extract: "readability" },
          { abortSignal: ctx.abortSignal, timeoutMs: REQUEST_TIMEOUT },
        );
        return {
          success: response.success,
          url: response.url,
          title: response.title,
          content: response.body,
          error: response.error,
          contentTruncated: response.contentTruncated,
          stopReason: response.stopReason,
        };
      }
    },
  });
}
