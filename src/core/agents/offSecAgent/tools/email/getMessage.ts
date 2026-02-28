import { tool } from "ai";
import { z } from "zod";
import type { ToolContext } from "../types";
import { createEmailAdapter } from "./adapters";

/**
 * Tool: email_get_message
 *
 * Retrieves the full content of a single email message by its ID.
 */
export function emailGetMessage(ctx: ToolContext) {
  return tool({
    description: `Get the full content of an email message.

Returns the complete message including body text, headers, CC, and
attachment metadata. Use email_list_messages or email_search_messages
first to find the message ID.`,
    inputSchema: z.object({
      inboxId: z.string().describe("The inbox ID from email_list_inboxes"),
      messageId: z.string().describe("The message ID to retrieve"),
      toolCallDescription: z
        .string()
        .describe(
          "A concise, human-readable description of what this tool call is doing",
        ),
    }),
    execute: async ({ inboxId, messageId }) => {
      const inboxes = ctx.session.config?.emailIntegration?.inboxes ?? [];
      const inbox = inboxes.find((i) => i.id === inboxId);
      if (!inbox) {
        return { success: false, error: `Inbox ${inboxId} not found` };
      }

      try {
        const adapter = createEmailAdapter(inbox);
        const message = await adapter.getMessage(messageId);
        return { success: true, message };
      } catch (error: unknown) {
        return {
          success: false,
          error: error instanceof Error ? error.message : String(error),
        };
      }
    },
  });
}
