import { tool } from "ai";
import { z } from "zod";
import { targetFetch } from "../../../http/targetHeaders";
import { createLogger } from "../../../logger/structured";
import { scopedLogger } from "../../../util/lazyLogger";
import {
  type EndpointInfo,
  extractJavascriptEndpoints,
} from "../../specialized/attackSurface/jsExtraction";
import {
  assertUrlInScope,
  resolverSessionFromCtx,
  ScopeViolationError,
} from "./scopeGuard";
import type { ToolContext } from "./types";

const log = scopedLogger(() => createLogger("crawl-authenticated"));

/**
 * Factory for the `crawl_authenticated_area` tool.
 *
 * Recursively crawls web pages starting from a URL, following links,
 * extracting forms, and running JS endpoint extraction on each page.
 */
export function crawlAuthenticated(ctx: ToolContext) {
  return tool({
    description: `Recursively crawl web pages starting from a URL to discover links, forms, and JavaScript endpoints.

- Follows links to discover connected pages
- Extracts form actions
- Calls extract_js_endpoints on each discovered page
- Returns comprehensive map of discovered pages and endpoints`,
    inputSchema: z.object({
      startUrl: z.string().describe("Starting URL (e.g., /dashboard)"),
      sessionCookie: z
        .string()
        .describe("Session cookie from delegate_to_auth_subagent"),
      maxDepth: z.number().default(3).describe("Maximum crawl depth"),
      maxPages: z.number().default(50).describe("Maximum pages to visit"),
      toolCallDescription: z
        .string()
        .describe(
          "A concise, human-readable description of what this tool call is doing",
        ),
    }),
    execute: async (params) => {
      try {
        assertUrlInScope(params.startUrl, ctx);
      } catch (e) {
        if (e instanceof ScopeViolationError) {
          return { success: false, message: e.message };
        }
        throw e;
      }

      try {
        const { startUrl, sessionCookie, maxDepth, maxPages } = params;

        const visited = new Set<string>();
        const toVisit: Array<{ url: string; depth: number }> = [
          { url: startUrl, depth: 0 },
        ];
        const pages: Array<{
          url: string;
          status: number;
          links: string[];
          forms: string[];
          jsEndpoints: unknown[];
        }> = [];
        const allEndpoints = new Set<string>();

        while (toVisit.length > 0 && visited.size < maxPages) {
          const { url, depth } = toVisit.shift()!;

          if (visited.has(url) || depth > maxDepth) continue;
          visited.add(url);

          try {
            const pageResult = await targetFetch(
              resolverSessionFromCtx(ctx),
              url,
              {
                method: "GET",
                headers: { cookie: sessionCookie },
              },
            );

            if (pageResult.status >= 200 && pageResult.status < 400) {
              const html = await pageResult.text();

              // Extract links
              const linkRegex = /<a[^>]+href=['"]([^'"]+)['"]/gi;
              const links: string[] = [];
              for (
                let linkMatch = linkRegex.exec(html);
                linkMatch !== null;
                linkMatch = linkRegex.exec(html)
              ) {
                const link = linkMatch[1];
                if (link.startsWith("/") && !link.startsWith("//")) {
                  links.push(link);
                  if (!visited.has(link)) {
                    toVisit.push({ url: link, depth: depth + 1 });
                  }
                }
              }

              // Extract forms
              const formRegex = /<form[^>]+action=['"]([^'"]+)['"]/gi;
              const forms: string[] = [];
              for (
                let formMatch = formRegex.exec(html);
                formMatch !== null;
                formMatch = formRegex.exec(html)
              ) {
                forms.push(formMatch[1]);
              }

              // Extract JavaScript endpoints
              const jsEndpoints = await extractJavascriptEndpoints({
                url,
                sessionCookie,
                includeExternalJS: false,
              });

              if (jsEndpoints.endpoints) {
                jsEndpoints.endpoints.forEach((ep: EndpointInfo) => {
                  allEndpoints.add(ep.endpoint);
                });
              }

              pages.push({
                url,
                status: pageResult.status,
                links,
                forms,
                jsEndpoints: jsEndpoints.endpoints || [],
              });
            }
          } catch (error) {
            log.error(
              `Error crawling ${url}`,
              error instanceof Error ? error : undefined,
              { error: String(error) },
            );
          }
        }

        return {
          success: true,
          startUrl,
          pagesVisited: visited.size,
          totalPages: pages.length,
          pages,
          allDiscoveredEndpoints: Array.from(allEndpoints),
          message: `Crawled ${visited.size} pages. Discovered ${allEndpoints.size} unique endpoints from JavaScript.`,
        };
      } catch (error: unknown) {
        const errorMsg = error instanceof Error ? error.message : String(error);
        return {
          success: false,
          message: `Crawl error: ${errorMsg}`,
        };
      }
    },
  });
}
