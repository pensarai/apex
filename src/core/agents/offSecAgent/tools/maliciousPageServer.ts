import { tool } from "ai";
import { z } from "zod";
import type { ToolContext } from "./types";
import type { InfrastructureManager } from "./infrastructure";

/**
 * Tool for serving attacker-controlled web pages.
 * Critical for testing AI agent security, XSS, CSRF, clickjacking, etc.
 */
export function serveMaliciousPage(
  ctx: ToolContext & { infraManager?: InfrastructureManager },
) {
  return tool({
    description: `Serve an attacker-controlled web page on a local or public URL.

Use cases:
- AI agent prompt injection: serve a page with hidden instructions that an AI agent processes when browsing
- XSS payload hosting: serve pages that trigger stored/reflected XSS in the target
- CSRF attack pages: serve pages with auto-submitting forms targeting the application
- Clickjacking frames: serve framing pages to test X-Frame-Options / CSP frame-ancestors
- OAuth redirect exploitation: serve pages that capture OAuth tokens from redirect flows
- postMessage exploitation: serve pages that send malicious messages to target iframes

The page is served with the specified HTML content and optional custom headers.
When expose=true (default), a public URL is created via cloudflared tunnel.`,
    inputSchema: z.object({
      html: z
        .string()
        .describe("The HTML content to serve on the page"),
      path: z
        .string()
        .optional()
        .default("/")
        .describe("URL path to serve on (default: /)"),
      headers: z
        .record(z.string(), z.string())
        .optional()
        .describe(
          "Custom response headers, e.g. {\"Content-Security-Policy\": \"none\"}",
        ),
      port: z
        .number()
        .optional()
        .describe("Port to listen on (auto-assigned if omitted)"),
      expose: z
        .boolean()
        .optional()
        .default(true)
        .describe("Expose via cloudflared tunnel (default: true)"),
      toolCallDescription: z
        .string()
        .describe(
          "A concise description (e.g., 'Hosting CSRF exploit page targeting admin endpoint')",
        ),
    }),
    execute: async ({ html, path, headers: customHeaders, port, expose }) => {
      const mgr = ctx.infraManager;
      if (!mgr) {
        return {
          success: false,
          error: "Infrastructure manager not available.",
        };
      }

      try {
        const servePath = path || "/";

        const server = await mgr.startHttpServer({
          port,
          expose,
          handler: (req, _interactions) => {
            // Serve the HTML on the configured path, 404 everything else
            if (req.url === servePath || req.url?.startsWith(servePath + "?")) {
              return {
                status: 200,
                headers: {
                  "Content-Type": "text/html; charset=utf-8",
                  ...customHeaders,
                },
                body: html,
              };
            }
            return {
              status: 404,
              headers: { "Content-Type": "text/plain" },
              body: "Not Found",
            };
          },
        });

        return {
          success: true,
          id: server.id,
          localUrl: `${server.localUrl}${servePath}`,
          publicUrl: server.publicUrl
            ? `${server.publicUrl}${servePath}`
            : null,
          port: server.port,
          message: server.publicUrl
            ? `Malicious page served at: ${server.publicUrl}${servePath}`
            : `Malicious page served at: http://localhost:${server.port}${servePath}`,
        };
      } catch (error: unknown) {
        const msg = error instanceof Error ? error.message : String(error);
        return { success: false, error: msg };
      }
    },
  });
}
