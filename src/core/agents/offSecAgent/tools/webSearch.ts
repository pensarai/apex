import { tool } from "ai";
import { z } from "zod";
// Importing through the api barrel would create a circular module load:
// api → offesecAgent → offSecAgent/tools → webSearch → api. Use the leaf
// constants module directly.
import { getPensarApiUrl } from "../../../api/constants";
import { ensureValidToken, signGatewayRequest } from "../../../auth";
import { config } from "../../../config";
import type { ToolContext } from "./types";

const webSearchInputSchema = z.object({
  query: z
    .string()
    .describe(
      "The search query to look up. Be specific and include relevant keywords for better results.",
    ),
  toolCallDescription: z
    .string()
    .optional()
    .describe(
      "A concise, human-readable description of what this tool call is doing (e.g., 'Searching for CVE-2024-1234 details')",
    ),
});

type WebSearchInput = z.infer<typeof webSearchInputSchema>;

interface WebSearchResult {
  title: string;
  url: string;
  snippet: string;
}

export interface WebSearchResponse {
  success: boolean;
  results: WebSearchResult[];
  error?: string;
}

const BRAVE_SEARCH_URL = "https://api.search.brave.com/res/v1/web/search";

async function braveSearch(
  query: string,
  apiKey: string,
): Promise<WebSearchResponse> {
  const url = new URL(BRAVE_SEARCH_URL);
  url.searchParams.set("q", query);
  url.searchParams.set("count", "10");

  // biome-ignore lint/style/noRestrictedGlobals: Brave Search API is infrastructure (not the pentest target); must not pass through targetFetch.
  const response = await fetch(url.toString(), {
    method: "GET",
    headers: {
      Accept: "application/json",
      "Accept-Encoding": "gzip",
      "X-Subscription-Token": apiKey,
    },
  });

  if (!response.ok) {
    if (response.status === 401 || response.status === 403) {
      return {
        success: false,
        results: [],
        error:
          "Brave API authentication failed. Check that your brave_api_key is valid.",
      };
    }

    if (response.status === 429) {
      return {
        success: false,
        results: [],
        error:
          "Brave API rate limit exceeded. Please wait a moment before searching again.",
      };
    }

    const errorText = await response.text().catch(() => "Unknown error");
    return {
      success: false,
      results: [],
      error: `Brave search failed: ${response.status} ${response.statusText}. ${errorText}`,
    };
  }

  const data = (await response.json()) as {
    web?: {
      results?: Array<{
        title?: string;
        url?: string;
        description?: string;
      }>;
    };
  };

  const results: WebSearchResult[] =
    data.web?.results?.map((r) => ({
      title: r.title ?? "",
      url: r.url ?? "",
      snippet: r.description ?? "",
    })) ?? [];

  return { success: true, results };
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

IMPORTANT: This tool requires either a Pensar account or a Brave API key. If neither is configured, you'll receive an error message with instructions.

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

        // Brave API direct mode: bypass Pensar API entirely
        if (cfg.braveAPIKey) {
          return braveSearch(query, cfg.braveAPIKey);
        }

        const apiUrl = getPensarApiUrl();
        const body = JSON.stringify({ query });

        // API key mode: authenticate directly without token exchange or signing
        if (cfg.pensarAPIKey && !cfg.accessToken) {
          // biome-ignore lint/style/noRestrictedGlobals: Pensar Console (not the pentest target); must not pass through targetFetch.
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
              "Web search requires a Pensar account or a Brave API key. Please sign in to your Pensar account or configure a Brave API key (set BRAVE_API_KEY or brave_api_key in config).",
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

        // biome-ignore lint/style/noRestrictedGlobals: Pensar Console (not the pentest target); must not pass through targetFetch.
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
