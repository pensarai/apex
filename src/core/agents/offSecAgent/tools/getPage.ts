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
      "A concise, human-readable description of what this tool call is doing (e.g., 'Reading the target login page')",
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
    description: `Fetch and extract readable content from an in-scope target page. Returns the page title and main text content.

USAGE GUIDANCE:
- Use this tool only for pages already present in the immutable run scope
- Use web_search for external security research; do not fetch those URLs directly
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
