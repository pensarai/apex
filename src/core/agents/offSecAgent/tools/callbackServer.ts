import { tool } from "ai";
import { z } from "zod";
import type { ToolContext } from "./types";
import type { InfrastructureManager } from "./infrastructure";

/**
 * Creates the callback server tools: start, check, and stop.
 *
 * The InfrastructureManager must be passed via extended ToolContext.
 */
export function startCallbackServer(
  ctx: ToolContext & { infraManager?: InfrastructureManager },
) {
  return tool({
    description: `Start a lightweight HTTP or DNS callback listener to detect out-of-band (OOB) interactions.

Essential for:
- Blind SSRF detection: did the server reach your callback?
- Blind XXE detection: did the XML parser fetch your external DTD?
- Blind SQL injection confirmation via DNS exfiltration
- CSP bypass testing and DNS rebinding attacks
- Any scenario where you need to know if a target server makes a request to you

The server records all incoming requests with timestamps, headers, body, and source IP.
When expose=true (default), a public URL is created via cloudflared tunnel.`,
    inputSchema: z.object({
      type: z
        .enum(["http", "dns"])
        .describe("Server type: http for web callbacks, dns for DNS queries"),
      port: z
        .number()
        .optional()
        .describe("Port to listen on (auto-assigned if omitted)"),
      timeout: z
        .number()
        .optional()
        .describe("Auto-shutdown after N seconds (omit for persistent)"),
      expose: z
        .boolean()
        .optional()
        .default(true)
        .describe(
          "Expose via cloudflared tunnel for a public URL (default: true)",
        ),
      toolCallDescription: z
        .string()
        .describe(
          "A concise description of what this callback is for (e.g., 'Starting OOB callback for blind SSRF test')",
        ),
    }),
    execute: async ({ type, port, timeout, expose }) => {
      const mgr = ctx.infraManager;
      if (!mgr) {
        return {
          success: false,
          error:
            "Infrastructure manager not available. Callback servers require the pentest workflow context.",
        };
      }

      try {
        if (type === "http") {
          const server = await mgr.startHttpServer({
            port,
            timeout,
            expose,
          });
          return {
            success: true,
            id: server.id,
            localUrl: server.localUrl,
            publicUrl: server.publicUrl ?? null,
            port: server.port,
            message: server.publicUrl
              ? `HTTP callback server started. Public URL: ${server.publicUrl}`
              : `HTTP callback server started on localhost:${server.port} (no public tunnel)`,
          };
        } else {
          const server = await mgr.startDnsServer({ port, timeout });
          return {
            success: true,
            id: server.id,
            localUrl: server.localUrl,
            port: server.port,
            message: `DNS callback server started on port ${server.port}`,
          };
        }
      } catch (error: unknown) {
        const msg = error instanceof Error ? error.message : String(error);
        return { success: false, error: msg };
      }
    },
  });
}

export function checkCallbackServer(
  ctx: ToolContext & { infraManager?: InfrastructureManager },
) {
  return tool({
    description: `Check for interactions received by a callback server.

After starting a callback server and triggering a potential OOB interaction (e.g., sending an SSRF payload), use this tool to check if the target made a request to your server. Returns all recorded interactions with timestamps, source IPs, request details.`,
    inputSchema: z.object({
      id: z.string().describe("The callback server ID returned by start_callback_server"),
      toolCallDescription: z
        .string()
        .describe(
          "A concise description (e.g., 'Checking if SSRF payload triggered OOB callback')",
        ),
    }),
    execute: async ({ id }) => {
      const mgr = ctx.infraManager;
      if (!mgr) {
        return { success: false, error: "Infrastructure manager not available." };
      }

      const server = mgr.getServer(id);
      if (!server) {
        return {
          success: false,
          error: `No server found with ID '${id}'. It may have been stopped or timed out.`,
        };
      }

      const interactions = mgr.getInteractions(id);

      return {
        success: true,
        id,
        interactionCount: interactions.length,
        interactions: interactions.map((i) => ({
          timestamp: new Date(i.timestamp).toISOString(),
          type: i.type,
          sourceIp: i.sourceIp,
          method: i.method,
          path: i.path,
          headers: i.headers,
          body: i.body?.substring(0, 2000),
          query: i.query,
        })),
        message:
          interactions.length > 0
            ? `${interactions.length} interaction(s) received! The target made contact.`
            : "No interactions received yet.",
      };
    },
  });
}

export function stopCallbackServer(
  ctx: ToolContext & { infraManager?: InfrastructureManager },
) {
  return tool({
    description: `Stop a running callback server and free its port.`,
    inputSchema: z.object({
      id: z.string().describe("The callback server ID to stop"),
      toolCallDescription: z
        .string()
        .describe("A concise description (e.g., 'Stopping callback server')"),
    }),
    execute: async ({ id }) => {
      const mgr = ctx.infraManager;
      if (!mgr) {
        return { success: false, error: "Infrastructure manager not available." };
      }

      const stopped = mgr.stopServer(id);
      return {
        success: stopped,
        message: stopped
          ? `Server ${id} stopped successfully.`
          : `No server found with ID '${id}'.`,
      };
    },
  });
}
