import { tool } from "ai";
import { z } from "zod";
import type { ToolContext } from "../types";

export function oobStopListener(ctx: ToolContext) {
  return tool({
    description: `Stop the OOB interaction listener and deregister from the interactsh server.

Always call this when finished with OOB detection testing to release server resources. Any pending interactions will no longer be captured after stopping.`,
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
          error: "No active OOB listener to stop.",
        };
      }

      try {
        await client.deregister();
        ctx.oobClientHolder.client = null;

        return {
          success: true,
          message: "OOB listener stopped and deregistered successfully.",
        };
      } catch (error: unknown) {
        // Even on error, clear the reference since we can't use it anymore
        ctx.oobClientHolder.client = null;
        const msg = error instanceof Error ? error.message : String(error);
        return {
          success: true,
          message: `OOB listener stopped (deregistration warning: ${msg}).`,
        };
      }
    },
  });
}
