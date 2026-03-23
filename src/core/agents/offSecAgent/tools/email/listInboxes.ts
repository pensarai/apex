import { tool } from "ai";
import { z } from "zod";
import type { ToolContext } from "../types";

/**
 * Tool: email_list_inboxes
 *
 * Lists all email inboxes configured for the current session so the agent
 * knows which inboxes are available before querying them.
 */
export function emailListInboxes(ctx: ToolContext) {
  return tool({
    description: `List all email inboxes available in this session.

Returns the configured email inboxes (Gmail, Outlook, or IMAP) that have
been connected at the workspace level. Use this first to discover which
inboxes are available, then reference them by ID in other email tools.`,
    inputSchema: z.object({}),
    execute: async () => {
      const inboxes = ctx.session.config?.emailIntegration?.inboxes ?? [];

      if (inboxes.length === 0) {
        return {
          success: false,
          error: "No email inboxes configured for this session.",
          inboxes: [],
        };
      }

      return {
        success: true,
        inboxes: inboxes.map((inbox) => ({
          id: inbox.id,
          provider: inbox.provider,
          name: inbox.name,
          emailAddress: inbox.emailAddress,
        })),
      };
    },
  });
}
