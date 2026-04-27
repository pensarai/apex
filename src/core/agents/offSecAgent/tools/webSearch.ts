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

USE THIS TOOL LIBERALLY. It is one of your most powerful advantages over static
scanners — you can look things up in real time. Whenever you discover a technology,
version, header, or behavior you're not 100% sure about, search for it. The cost
of a search is near-zero; the cost of missing a known vulnerability is high.

WHEN TO SEARCH (non-exhaustive — err on the side of searching):
- You identify a technology or version (e.g., Apache 2.4.49, Next.js 13.2, OpenSSH 8.9)
  → search for known CVEs and exploits against that exact version
- You find an unusual header, cookie name, endpoint, or error message
  → search to identify the framework/product and its known weaknesses
- You want exploit techniques, payloads, or bypass methods for a vulnerability class
- You need default credentials, common misconfigurations, or hardening gaps
- You want to discover novel attack paths — search for "<technology> pentest",
  "<technology> bug bounty writeups", or "<technology> security research"
- You're stuck or making no progress → search for writeups on similar targets

IMPORTANT: This tool requires a Pensar account. If you're not signed in, you'll receive an error message with instructions to sign in.

COMMON SEARCH PATTERNS:
- "CVE-2024-XXXX exploit" — Find details about specific CVEs
- "Apache 2.4.49 CVE" — Find CVEs for an exact version you discovered
- "Apache Struts RCE vulnerability" — Research known vulnerabilities in specific software
- "SSRF bypass techniques 2024" — Find current security testing techniques
- "Spring Boot actuator default credentials" — Look up default credentials
- "JWT token security vulnerabilities" — Research vulnerability classes
- "nginx 1.25 known vulnerabilities" — Version-specific vulnerability lookup
- "<product name> bug bounty writeup" — Find real-world attack paths others have found`,
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
              "Web search requires a Pensar account. Please sign in to your Pensar account to use this feature. You can sign in via the TUI settings or by running 'pensar login'.",
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
