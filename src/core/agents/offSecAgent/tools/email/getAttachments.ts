import { tool } from "ai";
import { z } from "zod";
import type { ToolContext } from "../types";
import { createEmailAdapter } from "./adapters";

/**
 * Tool: email_get_attachments
 *
 * Lists attachments on a message, or downloads a specific attachment's
 * content as base64.
 */
export function emailGetAttachments(ctx: ToolContext) {
  return tool({
    description: `List or download attachments from an email message.

When called without attachmentId, returns metadata for all attachments
(filename, mimeType, size). When called with an attachmentId, returns
the attachment content as base64.`,
    inputSchema: z.object({
      inboxId: z.string().describe("The inbox ID from email_list_inboxes"),
      messageId: z.string().describe("The message ID containing attachments"),
      attachmentId: z
        .string()
        .optional()
        .describe(
          "If provided, download this specific attachment. Otherwise list all.",
        ),
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
    execute: async ({ inboxId, messageId, attachmentId, folder }) => {
      const inboxes = ctx.session.config?.emailIntegration?.inboxes ?? [];
      const inbox = inboxes.find((i) => i.id === inboxId);
      if (!inbox) {
        return { success: false, error: `Inbox ${inboxId} not found` };
      }

      try {
        const adapter = createEmailAdapter(inbox);

        if (attachmentId) {
          const content = await adapter.getAttachmentContent(
            messageId,
            attachmentId,
            folder,
          );
          return { success: true, attachment: content };
        }

        const attachments = await adapter.getAttachments(messageId, folder);
        return { success: true, attachments };
      } catch (error: unknown) {
        return {
          success: false,
          error: error instanceof Error ? error.message : String(error),
        };
      }
    },
  });
}
