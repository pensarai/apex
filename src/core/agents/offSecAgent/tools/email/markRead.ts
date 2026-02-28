import { tool } from "ai";
import { z } from "zod";
import type { ToolContext } from "../types";
import { createEmailAdapter } from "./adapters";

/**
 * Tool: email_mark_read
 *
 * Marks a message as read in the connected inbox.
 */
export function emailMarkRead(ctx: ToolContext) {
  return tool({
    description: `Mark an email message as read.

Sets the read/seen flag on a message so it no longer appears as unread.`,
    inputSchema: z.object({
      inboxId: z.string().describe("The inbox ID from email_list_inboxes"),
      messageId: z.string().describe("The message ID to mark as read"),
      folder: z
        .string()
        .optional()
        .describe(
          "Mailbox folder the message lives in (default INBOX). Must match the folder used when listing.",
        ),
      toolCallDescription: z
        .string()
        .describe(
          "A concise, human-readable description of what this tool call is doing",
        ),
    }),
    execute: async ({ inboxId, messageId, folder }) => {
      const inboxes = ctx.session.config?.emailIntegration?.inboxes ?? [];
      const inbox = inboxes.find((i) => i.id === inboxId);
      if (!inbox) {
        return { success: false, error: `Inbox ${inboxId} not found` };
      }

      try {
        const adapter = createEmailAdapter(inbox);
        await adapter.markAsRead(messageId, folder);
        return {
          success: true,
          message: `Message ${messageId} marked as read`,
        };
      } catch (error: unknown) {
        return {
          success: false,
          error: error instanceof Error ? error.message : String(error),
        };
      }
    },
  });
}
