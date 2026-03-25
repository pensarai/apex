import { tool } from "ai";
import { z } from "zod";
import type { ToolContext } from "../types";

export function oobPollInteractions(ctx: ToolContext) {
  return tool({
    description: `Poll the interactsh server for OOB interactions received on the callback URL.

Returns details about each interaction including protocol (DNS, HTTP, SMTP, LDAP), source address, timestamp, and raw request data. Call this after injecting payloads to check if the target made outbound connections to your callback URL.

Requires an active OOB listener (start one with oob_start_listener first).`,
    inputSchema: z.object({
      toolCallDescription: z
        .string()
        .describe(
          "A concise, human-readable description of what this tool call is doing",
        ),
    }),
    execute: async () => {
      if (!ctx.oobClientHolder) {
        return {
          success: false,
          error: "OOB interaction detection is not available in this context",
        };
      }

      const client = ctx.oobClientHolder.client;
      if (!client?.isRegistered) {
        return {
          success: false,
          error:
            "No active OOB listener. Call oob_start_listener first to register a callback URL.",
        };
      }

      try {
        const interactions = await client.poll(ctx.abortSignal);

        if (interactions.length === 0) {
          return {
            success: true,
            count: 0,
            interactions: [],
            note: "No interactions received yet. The target may not have made an outbound connection, or the payload may not have been processed yet. Try waiting longer and polling again.",
          };
        }

        // Format interactions for agent consumption
        const formatted = interactions.map((i) => ({
          protocol: i.protocol,
          uniqueId: i["unique-id"],
          fullId: i["full-id"],
          remoteAddress: i["remote-address"],
          timestamp: i.timestamp,
          rawRequest:
            i["raw-request"].length > 2000
              ? i["raw-request"].substring(0, 2000) + "...(truncated)"
              : i["raw-request"],
          rawResponse:
            i["raw-response"].length > 1000
              ? i["raw-response"].substring(0, 1000) + "...(truncated)"
              : i["raw-response"],
          qType: i["q-type"],
        }));

        return {
          success: true,
          count: interactions.length,
          interactions: formatted,
        };
      } catch (error: unknown) {
        const msg = error instanceof Error ? error.message : String(error);
        return { success: false, error: `Failed to poll interactions: ${msg}` };
      }
    },
  });
}
