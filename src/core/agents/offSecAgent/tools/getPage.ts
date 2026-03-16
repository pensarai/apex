import { tool } from "ai";
import { z } from "zod";
import { config } from "../../../config";
import { ensureValidToken } from "../../../api/tokenRefresh";
import { getPensarApiUrl } from "../../../api/constants";
import type { ToolContext } from "./types";

const MAX_CONTENT_LENGTH = 50_000;

export const getPageInputSchema = z.object({
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

export type GetPageInput = z.infer<typeof getPageInputSchema>;

export interface GetPageResponse {
  success: boolean;
  url: string;
  title?: string;
  content?: string;
  error?: string;
}

export function getPage(_ctx: ToolContext) {
  return tool({
    description: `Fetch and extract readable content from a web page. Returns the page title and main text content.

USAGE GUIDANCE:
- Use this tool to read full content from URLs found via web_search
- Fetch CVE details, security advisories, and vulnerability write-ups
- Read documentation, API references, and technical guides
- Extract exploit code, payloads, and proof-of-concept details from security blogs

IMPORTANT: This tool requires a Pensar account. If you're not signed in, you'll receive an error message with instructions to sign in.

BEST PRACTICES:
- First use web_search to find relevant URLs, then use get_page to read the full content
- Prefer authoritative sources (NVD, vendor advisories, security researcher blogs)
- For large pages, focus on the most relevant sections
- If content is truncated, the important information is usually near the beginning`,
    inputSchema: getPageInputSchema,
    execute: async ({ url }): Promise<GetPageResponse> => {
      try {
        const cfg = await config.get();

        const tokenResult = await ensureValidToken({
          accessToken: cfg.accessToken,
          refreshToken: cfg.refreshToken,
          pensarAPIKey: cfg.pensarAPIKey,
        });

        if (!tokenResult) {
          return {
            success: false,
            url,
            error:
              "Page fetching requires a Pensar account. Please sign in to your Pensar account to use this feature. You can sign in via the TUI settings or by running 'pensar auth login'.",
          };
        }

        const apiUrl = getPensarApiUrl();
        const response = await fetch(`${apiUrl}/api/agents/get_page`, {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            Authorization: `Bearer ${tokenResult.token}`,
          },
          body: JSON.stringify({ url }),
        });

        if (!response.ok) {
          if (response.status === 401) {
            return {
              success: false,
              url,
              error:
                "Authentication failed. Please sign in again to your Pensar account.",
            };
          }

          if (response.status === 429) {
            return {
              success: false,
              url,
              error:
                "Rate limit exceeded. Please wait a moment before fetching pages again.",
            };
          }

          const errorText = await response.text().catch(() => "Unknown error");
          return {
            success: false,
            url,
            error: `Failed to fetch page: ${response.status} ${response.statusText}. ${errorText}`,
          };
        }

        const data = (await response.json()) as {
          title?: string;
          content?: string;
          error?: string;
        };

        if (data.error) {
          return {
            success: false,
            url,
            error: data.error,
          };
        }

        let content = data.content || "";
        if (content.length > MAX_CONTENT_LENGTH) {
          content =
            content.substring(0, MAX_CONTENT_LENGTH) +
            "\n\n... (content truncated — page exceeded maximum length)";
        }

        return {
          success: true,
          url,
          title: data.title,
          content,
        };
      } catch (error: unknown) {
        const errorMsg = error instanceof Error ? error.message : String(error);
        return {
          success: false,
          url,
          error: `Failed to fetch page: ${errorMsg}`,
        };
      }
    },
  });
}
