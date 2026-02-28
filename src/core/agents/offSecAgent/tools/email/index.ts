/**
 * Email tool suite for agent inbox interaction.
 *
 * Provides six tools that let agents comprehensively interact with
 * Gmail, Outlook, and IMAP inboxes configured at the workspace level.
 */

export { emailListInboxes } from "./listInboxes";
export { emailListMessages } from "./listMessages";
export { emailGetMessage } from "./getMessage";
export { emailSearchMessages } from "./searchMessages";
export { emailGetAttachments } from "./getAttachments";
export { emailMarkRead } from "./markRead";

import type { ToolContext } from "../types";
import { emailListInboxes } from "./listInboxes";
import { emailListMessages } from "./listMessages";
import { emailGetMessage } from "./getMessage";
import { emailSearchMessages } from "./searchMessages";
import { emailGetAttachments } from "./getAttachments";
import { emailMarkRead } from "./markRead";

/**
 * Create the full email toolset. All six tools share the same ToolContext
 * and pull inbox config from `ctx.session.config.emailIntegration`.
 */
export function createEmailToolset(ctx: ToolContext) {
  return {
    email_list_inboxes: emailListInboxes(ctx),
    email_list_messages: emailListMessages(ctx),
    email_get_message: emailGetMessage(ctx),
    email_search_messages: emailSearchMessages(ctx),
    email_get_attachments: emailGetAttachments(ctx),
    email_mark_read: emailMarkRead(ctx),
  } as const;
}

/** All email tool names as a typed array. */
export const EMAIL_TOOL_NAMES = [
  "email_list_inboxes",
  "email_list_messages",
  "email_get_message",
  "email_search_messages",
  "email_get_attachments",
  "email_mark_read",
] as const;

export type EmailToolName = (typeof EMAIL_TOOL_NAMES)[number];
