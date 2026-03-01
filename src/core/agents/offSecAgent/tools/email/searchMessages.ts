import { tool } from "ai";
import { z } from "zod";
import type { ToolContext } from "../types";
import { createEmailAdapter } from "./adapters";

/**
 * Tool: email_search_messages
 *
 * Searches email messages by a query string. Supports provider-native
 * search syntax (Gmail search operators, Microsoft KQL, IMAP TEXT search).
 */
export function emailSearchMessages(ctx: ToolContext) {
  return tool({
    description: `Search email messages in a connected inbox.

Performs a full-text search across messages. The query syntax depends on
the provider:
- Gmail: supports operators like from:, to:, subject:, has:attachment,
  before:, after:, label:, is:unread, etc.
- Outlook: supports KQL like from:user@example.com, subject:"hello",
  hasAttachment:true, received>=2024-01-01, etc.
- IMAP: plain text search across message bodies.

Returns message summaries matching the query.`,
    inputSchema: z.object({
      inboxId: z.string().describe("The inbox ID from email_list_inboxes"),
      query: z.string().describe("Search query (syntax depends on provider)"),
      folder: z
        .string()
        .optional()
        .describe(
          "Mailbox folder to search within (default INBOX). For IMAP, restricts the search to this folder.",
        ),
      maxResults: z
        .number()
        .optional()
        .describe("Maximum messages to return (default 20, max 50)"),
      pageToken: z
        .string()
        .optional()
        .describe("Pagination token from a previous call"),
      toolCallDescription: z
        .string()
        .describe(
          "A concise, human-readable description of what this tool call is doing",
        ),
    }),
    execute: async ({ inboxId, query, folder, maxResults, pageToken }) => {
      const inboxes = ctx.session.config?.emailIntegration?.inboxes ?? [];
      const inbox = inboxes.find((i) => i.id === inboxId);
      if (!inbox) {
        return { success: false, error: `Inbox ${inboxId} not found` };
      }

      try {
        const adapter = createEmailAdapter(inbox);
        const result = await adapter.searchMessages({
          query,
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
