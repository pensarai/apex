import { tool } from "ai";
import { z } from "zod";
import type { ToolContext } from "./types";
import type { InfrastructureManager } from "./infrastructure";

/**
 * Tool for hosting arbitrary payloads (DTDs, polyglot files, serialized objects, etc.)
 */
export function hostPayload(
  ctx: ToolContext & { infraManager?: InfrastructureManager },
) {
  return tool({
    description: `Host an arbitrary file/payload on a local or public URL.

Use cases:
- XXE: host external DTD files for parameter entity attacks
- File upload bypass: host polyglot files for download and re-upload
- Deserialization: host serialized payloads for remote class loading
- SSRF chain: host redirect pages that bounce internal requests
- JavaScript payloads: host .js files for XSS exploitation
- CSS injection: host stylesheets for data exfiltration

The payload is served with the specified content type and filename.
When expose=true (default), a public URL is created via cloudflared tunnel.`,
    inputSchema: z.object({
      content: z
        .string()
        .describe("The payload content (text or base64-encoded binary)"),
      filename: z
        .string()
        .describe("Filename to serve at, e.g. evil.dtd, payload.js"),
      contentType: z
        .string()
        .describe(
          "MIME content type, e.g. application/xml-dtd, application/javascript, text/html",
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
          "A concise description (e.g., 'Hosting external DTD for XXE attack')",
        ),
    }),
    execute: async ({ content, filename, contentType, port, expose }) => {
      const mgr = ctx.infraManager;
      if (!mgr) {
        return {
          success: false,
          error: "Infrastructure manager not available.",
        };
      }

      try {
        const servePath = `/${filename}`;

        const server = await mgr.startHttpServer({
          port,
          expose,
          handler: (req, _interactions): { status: number; headers: Record<string, string>; body: string } => {
            if (
              req.url === servePath ||
              req.url?.startsWith(servePath + "?")
            ) {
              return {
                status: 200,
                headers: {
                  "Content-Type": contentType,
                  "Content-Disposition": `inline; filename="${filename}"`,
                  "Access-Control-Allow-Origin": "*",
                },
                body: content,
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
            ? `Payload hosted at: ${server.publicUrl}${servePath}`
            : `Payload hosted at: http://localhost:${server.port}${servePath}`,
        };
      } catch (error: unknown) {
        const msg = error instanceof Error ? error.message : String(error);
        return { success: false, error: msg };
      }
    },
  });
}
