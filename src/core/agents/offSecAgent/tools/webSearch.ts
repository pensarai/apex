import { tool } from "ai";
import { z } from "zod";
import { config } from "../../../config";
import { ensureValidToken, signGatewayRequest } from "../../../auth";
import { getPensarApiUrl } from "../../../api/constants";
import type { ToolContext } from "./types";

export const webSearchInputSchema = z.object({
  query: z
    .string()
    .describe(
      "The search query to look up. Be specific and include relevant keywords for better results.",
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
    description:
      "Search the web for real-time information. Returns titles, URLs, and snippets. Requires Pensar account.",
    inputSchema: webSearchInputSchema,
    execute: async ({ query }): Promise<WebSearchResponse> => {
      try {
        const cfg = await config.get();
        const apiUrl = getPensarApiUrl();
        const body = JSON.stringify({ query });

        // API key mode: authenticate directly without token exchange or signing
        if (cfg.pensarAPIKey && !cfg.accessToken) {
          const response = await fetch(`${apiUrl}/agents/web_search`, {
            method: "POST",
            headers: {
              "Content-Type": "application/json",
              "x-api-key": cfg.pensarAPIKey,
            },
            body,
          });

          return handleSearchResponse(response);
        }

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

        if (!cfg.workspaceId) {
          return {
            success: false,
            results: [],
            error:
              "Web search requires a workspace. Please sign in to your Pensar account.",
          };
        }

        if (!cfg.gatewaySigningKey) {
          return {
            success: false,
            results: [],
            error:
              "Web search requires authentication. Please sign in again to your Pensar account.",
          };
        }

        const { signature, timestamp, nonce } = signGatewayRequest(
          cfg.gatewaySigningKey,
          "web_search",
          body,
        );

        const response = await fetch(`${apiUrl}/agents/web_search`, {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            Authorization: `Bearer ${tokenResult.token}`,
            "X-Workspace-Id": cfg.workspaceId,
            "X-Pensar-Timestamp": timestamp,
            "X-Pensar-Nonce": nonce,
            "X-Pensar-Signature": signature,
          },
          body,
        });

        return handleSearchResponse(response);
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

async function handleSearchResponse(
  response: Response,
): Promise<WebSearchResponse> {
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
}
