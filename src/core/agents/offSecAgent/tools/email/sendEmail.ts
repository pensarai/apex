import { tool } from "ai";
import { readFile } from "fs/promises";
import { lookup } from "mime-types";
import { createTransport } from "nodemailer";
import { basename } from "path";
import { z } from "zod";
import type { ToolContext } from "../types";

const attachmentSchema = z.object({
  path: z
    .string()
    .describe(
      "Absolute path to the file on disk to attach. The file is read and included inline.",
    ),
  filename: z
    .string()
    .optional()
    .describe(
      "Override the attachment filename (defaults to the basename of the path)",
    ),
});

const sendEmailInputSchema = z.object({
  to: z
    .union([z.string(), z.array(z.string())])
    .describe("Recipient email address(es)"),
  from: z
    .string()
    .optional()
    .describe(
      "Sender address (defaults to the configured fromAddress in SMTP config)",
    ),
  subject: z.string().describe("Email subject line"),
  body: z.string().describe("Email body content (plain text)"),
  html: z
    .string()
    .optional()
    .describe("HTML body content (takes precedence over plain text body)"),
  cc: z
    .union([z.string(), z.array(z.string())])
    .optional()
    .describe("CC recipient(s)"),
  bcc: z
    .union([z.string(), z.array(z.string())])
    .optional()
    .describe("BCC recipient(s)"),
  replyTo: z.string().optional().describe("Reply-To address"),
  headers: z
    .record(z.string(), z.string())
    .optional()
    .describe("Custom email headers"),
  attachments: z
    .array(attachmentSchema)
    .optional()
    .describe(
      "File attachments. Each entry specifies a file path on disk to read and attach.",
    ),
  toolCallDescription: z
    .string()
    .describe(
      "A concise, human-readable description of what this tool call is doing",
    ),
});

export type SendEmailInput = z.infer<typeof sendEmailInputSchema>;

export interface SendEmailResult {
  success: boolean;
  messageId?: string;
  error?: string;
}

/**
 * Tool: send_email
 *
 * Sends an email via SMTP. Works with any SMTP server including Resend's
 * SMTP relay (smtp.resend.com:465, user "resend", password = API key).
 */
export function sendEmail(ctx: ToolContext) {
  return tool({
    description: `Send an email via SMTP with optional file attachments.

Sends an outbound email using the configured SMTP server. Supports plain
text and HTML bodies, CC/BCC, custom headers, Reply-To, and file
attachments. Attachments are read from disk by absolute path and included
inline. Use this for sending reports, exploit PoCs, session logs, or any
scenario that requires sending emails from the agent.`,
    inputSchema: sendEmailInputSchema,
    execute: async ({
      to,
      from,
      subject,
      body,
      html,
      cc,
      bcc,
      replyTo,
      headers,
      attachments,
    }): Promise<SendEmailResult> => {
      const smtp = ctx.session.config?.smtpConfig;
      if (!smtp) {
        return {
          success: false,
          error:
            "No SMTP configuration found. Provide smtpConfig in session config or set the RESEND_API_KEY environment variable.",
        };
      }

      const sender = from ?? smtp.fromAddress;
      if (!sender) {
        return {
          success: false,
          error:
            'No sender address. Provide a "from" parameter or set fromAddress in SMTP config.',
        };
      }

      try {
        const mailAttachments = await Promise.all(
          (attachments ?? []).map(async (att) => {
            const content = await readFile(att.path);
            const filename = att.filename ?? basename(att.path);
            const contentType = lookup(filename) || "application/octet-stream";
            return { filename, content, contentType };
          }),
        );

        const transport = createTransport({
          host: smtp.host,
          port: smtp.port,
          secure: smtp.port === 465 || smtp.port === 2465,
          auth: {
            user: smtp.username,
            pass: smtp.password,
          },
          tls: smtp.tls ? { rejectUnauthorized: false } : undefined,
        });

        const info = await transport.sendMail({
          from: sender,
          to: Array.isArray(to) ? to.join(", ") : to,
          cc: cc ? (Array.isArray(cc) ? cc.join(", ") : cc) : undefined,
          bcc: bcc ? (Array.isArray(bcc) ? bcc.join(", ") : bcc) : undefined,
          replyTo,
          subject,
          text: body,
          html: html ?? undefined,
          headers: headers ?? undefined,
          attachments: mailAttachments.length > 0 ? mailAttachments : undefined,
        });

        return {
          success: true,
          messageId: info.messageId,
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
