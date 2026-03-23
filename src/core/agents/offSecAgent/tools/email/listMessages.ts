import { tool } from "ai";
import { z } from "zod";
import type { ToolContext } from "../types";
import { createEmailAdapter } from "./adapters";

/**
 * Tool: email_list_messages
 *
 * Lists messages in an inbox with optional folder selection and pagination.
 */
export function emailListMessages(ctx: ToolContext) {
  return tool({
    description: `List email messages in a connected inbox.

Returns message summaries (from, to, subject, date, snippet) for an inbox.
Supports folder selection and pagination. Use email_list_inboxes first to
get the inbox ID, then pass it here.`,
    inputSchema: z.object({
      inboxId: z.string().describe("The inbox ID from email_list_inboxes"),
      folder: z
        .string()
        .optional()
        .describe(
          "Folder/label to list (e.g. 'inbox', 'sent', 'drafts', 'spam', 'trash'). Defaults to inbox.",
        ),
      maxResults: z
        .number()
        .optional()
        .describe("Maximum messages to return (default 20, max 50)"),
      pageToken: z
        .string()
        .optional()
        .describe("Pagination token from a previous call"),
    }),
    execute: async ({ inboxId, folder, maxResults, pageToken }) => {
      const inboxes = ctx.session.config?.emailIntegration?.inboxes ?? [];
      const inbox = inboxes.find((i) => i.id === inboxId);
      if (!inbox) {
        return { success: false, error: `Inbox ${inboxId} not found` };
      }

      try {
        const adapter = createEmailAdapter(inbox);
        const result = await adapter.listMessages({
          folder,
          maxResults: Math.min(maxResults ?? 20, 50),
          pageToken,
        });
        return { success: true, ...result };
      } catch (error: unknown) {
        return {
          success: false,
          error: error instanceof Error ? error.message : String(error),
        };
      }
    },
  });
}
