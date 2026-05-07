/**
 * Email tool suite for agent inbox interaction and outbound email.
 *
 * Provides six read-only inbox tools (Gmail, Outlook, IMAP) plus a
 * send_email tool that uses SMTP (works with any SMTP server including
 * Resend's SMTP relay).
 */

export { emailListInboxes } from "./listInboxes";
export { emailListMessages } from "./listMessages";
export { emailGetMessage } from "./getMessage";
export { emailSearchMessages } from "./searchMessages";
export { emailGetAttachments } from "./getAttachments";
export { emailMarkRead } from "./markRead";
export { sendEmail } from "./sendEmail";

import type { ToolContext } from "../types";
import { emailListInboxes } from "./listInboxes";
import { emailListMessages } from "./listMessages";
import { emailGetMessage } from "./getMessage";
import { emailSearchMessages } from "./searchMessages";
import { emailGetAttachments } from "./getAttachments";
import { emailMarkRead } from "./markRead";
import { sendEmail } from "./sendEmail";

/**
 * Create the full email toolset. Inbox tools pull config from
 * `ctx.session.config.emailIntegration`; send_email pulls from
 * `ctx.session.config.smtpConfig`. Gating for each subset is
 * handled by the base agent class at the activeTools level.
 */
export function createEmailToolset(ctx: ToolContext) {
  return {
    email_list_inboxes: emailListInboxes(ctx),
    email_list_messages: emailListMessages(ctx),
    email_get_message: emailGetMessage(ctx),
    email_search_messages: emailSearchMessages(ctx),
    email_get_attachments: emailGetAttachments(ctx),
    email_mark_read: emailMarkRead(ctx),
    send_email: sendEmail(ctx),
  } as const;
}

/** All email tool names. Inbox tools gated on emailIntegration.inboxes; send_email gated on smtpConfig. */
export const EMAIL_TOOL_NAMES = [
  "email_list_inboxes",
  "email_list_messages",
  "email_get_message",
  "email_search_messages",
  "email_get_attachments",
  "email_mark_read",
  "send_email",
] as const;

export const SEND_EMAIL_TOOL_NAME = "send_email" as const;

export type EmailToolName = (typeof EMAIL_TOOL_NAMES)[number];
