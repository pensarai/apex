import { tool } from "ai";
import { z } from "zod";
import { config } from "../../../config";
import { ensureValidToken } from "../../../api/tokenRefresh";
import { getPensarApiUrl } from "../../../api/constants";
import type { ToolContext } from "./types";

export const webSearchInputSchema = z.object({
  query: z
    .string()
    .describe(
      "The search query to look up. Be specific and include relevant keywords for better results.",
    ),
  toolCallDescription: z
    .string()
    .describe(
      "A concise, human-readable description of what this tool call is doing (e.g., 'Searching for CVE-2024-1234 details')",
    ),
});

export type WebSearchInput = z.infer<typeof webSearchInputSchema>;

export interface WebSearchResult {
  title: string;
  url: string;
  snippet: string;
}

export interface WebSearchResponse {
  success: boolean;
  results: WebSearchResult[];
  error?: string;
}

export function webSearch(_ctx: ToolContext) {
  return tool({
    description: `Search the web for real-time information about any topic. Returns summarized information from search results.

USAGE GUIDANCE:
- Use this tool to look up CVEs, security advisories, and vulnerability details
- Search for exploit techniques, payloads, and bypass methods
- Research target technologies, frameworks, and their known vulnerabilities
- Find documentation for tools, APIs, and security testing techniques
- Look up default credentials, common misconfigurations, and hardening guides

IMPORTANT: This tool requires a Pensar account. If you're not signed in, you'll receive an error message with instructions to sign in.

COMMON SEARCH PATTERNS:
- "CVE-2024-XXXX exploit" — Find details about specific CVEs
- "Apache Struts RCE vulnerability" — Research known vulnerabilities in specific software
- "SSRF bypass techniques" — Find security testing techniques
- "Spring Boot actuator default credentials" — Look up default credentials
- "JWT token security vulnerabilities" — Research vulnerability classes`,
    inputSchema: webSearchInputSchema,
    execute: async ({ query }): Promise<WebSearchResponse> => {
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
            results: [],
            error:
              "Web search requires a Pensar account. Please sign in to your Pensar account to use this feature. You can sign in via the TUI settings or by running 'pensar auth login'.",
          };
        }

        const apiUrl = getPensarApiUrl();
        const response = await fetch(`${apiUrl}/api/agents/web_search`, {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            Authorization: `Bearer ${tokenResult.token}`,
          },
          body: JSON.stringify({ query }),
        });

        if (!response.ok) {
          if (response.status === 401) {
            return {
              success: false,
              results: [],
              error:
                "Authentication failed. Please sign in again to your Pensar account.",
            };
          }

          if (response.status === 429) {
            return {
              success: false,
              results: [],
              error:
                "Rate limit exceeded. Please wait a moment before searching again.",
            };
          }

          const errorText = await response.text().catch(() => "Unknown error");
          return {
            success: false,
            results: [],
            error: `Web search failed: ${response.status} ${response.statusText}. ${errorText}`,
          };
        }

        const data = (await response.json()) as {
          results?: WebSearchResult[];
          error?: string;
        };

        if (data.error) {
          return {
            success: false,
            results: [],
            error: data.error,
          };
        }

        return {
          success: true,
          results: data.results || [],
        };
      } catch (error: unknown) {
        const errorMsg = error instanceof Error ? error.message : String(error);
        return {
          success: false,
          results: [],
          error: `Web search failed: ${errorMsg}`,
        };
      }
    },
  });
}
