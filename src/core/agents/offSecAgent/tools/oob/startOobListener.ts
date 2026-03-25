import { tool } from "ai";
import { z } from "zod";
import { InteractshClient } from "../../../../../lib/interactsh";
import type { ToolContext } from "../types";

export function oobStartListener(ctx: ToolContext) {
  return tool({
    description: `Start an out-of-band (OOB) interaction listener for blind vulnerability detection.

Registers with an interactsh server and returns a unique callback URL. Embed this URL in payloads to detect blind SSRF, blind SQLi, blind RCE, XXE, stored XSS, LDAP injection, and other vulnerabilities where the server response does not reveal exploitation success.

After starting, inject payloads containing the interaction URL via http_request or execute_command, then use oob_poll_interactions to check for callbacks.`,
    inputSchema: z.object({
      serverUrl: z
        .string()
        .optional()
        .describe(
          "Custom interactsh server URL (default: https://oast.pro). Use for self-hosted deployments.",
        ),
      authToken: z
        .string()
        .optional()
        .describe("Auth token for self-hosted interactsh servers."),
      toolCallDescription: z
        .string()
        .describe(
          "A concise, human-readable description of what this tool call is doing",
        ),
    }),
    execute: async ({ serverUrl, authToken }) => {
      if (!ctx.oobClientHolder) {
        return {
          success: false,
          error: "OOB interaction detection is not available in this context",
        };
      }

      if (ctx.oobClientHolder.client?.isRegistered) {
        return {
          success: false,
          error:
            "An OOB listener is already active. Use oob_poll_interactions to check for callbacks, or oob_stop_listener to stop it first.",
          interactionUrl: ctx.oobClientHolder.client.interactionUrl,
        };
      }

      try {
        const client = new InteractshClient({
          serverUrl: serverUrl || undefined,
          authToken: authToken || undefined,
        });

        const { interactionUrl, correlationId } = await client.register(
          ctx.abortSignal,
        );

        ctx.oobClientHolder.client = client;

        return {
          success: true,
          interactionUrl,
          correlationId,
          usage: [
            `Your OOB listener is active. The base interaction URL is: ${interactionUrl}`,
            "",
            "To detect blind vulnerabilities, embed this URL in your payloads:",
            "",
            "  DNS/HTTP callback:  http://{label}." + interactionUrl,
            "  DNS-only callback:  {label}." + interactionUrl,
            "",
            "Replace {label} with a unique tag per injection point (e.g., ssrf1, sqli-param-id)",
            "so you can attribute which payload triggered the callback when polling.",
            "",
            "After injecting payloads, wait 5-15 seconds, then call oob_poll_interactions.",
            "When finished, call oob_stop_listener to clean up.",
          ].join("\n"),
        };
      } catch (error: unknown) {
        const msg = error instanceof Error ? error.message : String(error);
        return { success: false, error: `Failed to start OOB listener: ${msg}` };
      }
    },
  });
}
