import { tool } from "ai";
import { z } from "zod";
import { targetFetch } from "../../../http/targetHeaders";
import type { ToolContext } from "./types";

const MAX_CONTENT_LENGTH = 50_000;
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
}

function extractTitle(html: string): string | undefined {
  const titleMatch = html.match(/<title[^>]*>([^<]+)<\/title>/i);
  return titleMatch?.[1]?.trim();
}

function extractTextContent(html: string): string {
  let text = html;

  // Remove script and style tags with their content
  text = text.replace(/<script[^>]*>[\s\S]*?<\/script>/gi, "");
  text = text.replace(/<style[^>]*>[\s\S]*?<\/style>/gi, "");
  text = text.replace(/<noscript[^>]*>[\s\S]*?<\/noscript>/gi, "");

  // Remove HTML comments
  text = text.replace(/<!--[\s\S]*?-->/g, "");

  // Remove all HTML tags
  text = text.replace(/<[^>]+>/g, " ");

  // Decode common HTML entities
  text = text
    .replace(/&nbsp;/g, " ")
    .replace(/&amp;/g, "&")
    .replace(/&lt;/g, "<")
    .replace(/&gt;/g, ">")
    .replace(/&quot;/g, '"')
    .replace(/&#39;/g, "'")
    .replace(/&apos;/g, "'");

  // Normalize whitespace
  text = text.replace(/\s+/g, " ").trim();

  // Split into lines and remove empty ones
  const lines = text
    .split(/[.\n]/)
    .map((line) => line.trim())
    .filter((line) => line.length > 0);

  return lines.join("\n");
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
      try {
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), REQUEST_TIMEOUT);

        const combinedSignal = ctx.abortSignal
          ? AbortSignal.any([ctx.abortSignal, controller.signal])
          : controller.signal;

        // Identification headers are deliberately omitted here — the
        // resolver supplies the session/global User-Agent for in-scope
        // target URLs (INV-single-source). For external/research URLs
        // (CVE writeups, vendor docs) the resolver returns empty and
        // the runtime's default UA is used.
        const response = await targetFetch(ctx.session, url, {
          method: "GET",
          headers: {
            Accept:
              "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
          },
          signal: combinedSignal,
          redirect: "follow",
        });

        clearTimeout(timeoutId);

        if (!response.ok) {
          return {
            success: false,
            url,
            error: `Failed to fetch page: ${response.status} ${response.statusText}`,
          };
        }

        const contentType = response.headers.get("content-type") || "";
        if (
          !contentType.includes("text/html") &&
          !contentType.includes("text/plain") &&
          !contentType.includes("application/xhtml")
        ) {
          return {
            success: false,
            url,
            error: `Unsupported content type: ${contentType}. This tool only supports HTML and text pages.`,
          };
        }

        const html = await response.text();
        const title = extractTitle(html);
        let content = extractTextContent(html);

        if (content.length > MAX_CONTENT_LENGTH) {
          content =
            content.substring(0, MAX_CONTENT_LENGTH) +
            "\n\n... (content truncated — page exceeded maximum length)";
        }

        return {
          success: true,
          url,
          title,
          content,
        };
      } catch (error: unknown) {
        if (error instanceof Error && error.name === "AbortError") {
          return {
            success: false,
            url,
            error: ctx.abortSignal?.aborted
              ? "Request aborted by user"
              : `Request timeout after ${REQUEST_TIMEOUT / 1000}s`,
          };
        }

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
