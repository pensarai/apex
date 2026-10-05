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
  fetchToken: z
    .string()
    .optional()
    .describe(
      "Broker token returned with this exact URL by web_search. Required for external research URLs; omit for in-scope target pages.",
    ),
  toolCallDescription: z
    .string()
    .describe(
      "A concise, human-readable description of what this tool call is doing (e.g., 'Reading the target login page')",
    ),
});

export interface GetPageResponse {
  success: boolean;
  url: string;
  title?: string;
  content?: string;
  error?: string;
  contentTruncated?: boolean;
  stopReason?: "content-limit" | "byte-cap" | "timeout" | "aborted" | "error";
}

export function getPage(ctx: ToolContext) {
  return tool({
    description: `Fetch and extract readable content from an in-scope target page or a web_search result carrying a broker token. Returns the page title and main text content.

USAGE GUIDANCE:
- Use this tool directly for pages already present in the immutable run scope
- For external security research, first use web_search and pass the result's fetchToken
- A discovered URL without a broker token does not widen this run's scope`,
    inputSchema: getPageInputSchema,
    execute: async ({ url, fetchToken }): Promise<GetPageResponse> => {
      try {
        const response = await resolveBackends(ctx).http.request(
          { url, extract: "readability", fetchToken },
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
      } catch (error) {
        const message = error instanceof Error ? error.message : String(error);
        return {
          success: false,
          url,
          error:
            !fetchToken && message.includes("Scope violation")
              ? "External documents require the fetchToken returned by web_search and the Console research broker."
              : message,
        };
      }
    },
  });
}
