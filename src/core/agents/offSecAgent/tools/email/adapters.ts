/**
 * Email provider adapters.
 *
 * Each adapter wraps a first-party SDK into the shared {@link EmailAdapter}
 * interface so individual tool files stay provider-agnostic.
 *
 * - Gmail  → @googleapis/gmail
 * - Outlook → @microsoft/microsoft-graph-client
 * - IMAP   → imapflow
 */

import type { Attachment as ParsedAttachment } from "mailparser";
import { simpleParser } from "mailparser";
import type { EmailInboxConfig } from "../../../../session";
import type {
  EmailAttachment,
  EmailListResult,
  EmailMessageFull,
  EmailMessageSummary,
  EmailSearchResult,
} from "./types";

// ---------------------------------------------------------------------------
// Unified adapter interface
// ---------------------------------------------------------------------------

export interface EmailAdapter {
  listMessages(opts: {
    folder?: string;
    maxResults?: number;
    pageToken?: string;
  }): Promise<EmailListResult>;

  getMessage(messageId: string, folder?: string): Promise<EmailMessageFull>;

  searchMessages(opts: {
    query: string;
    folder?: string;
    maxResults?: number;
    pageToken?: string;
  }): Promise<EmailSearchResult>;

  getAttachments(
    messageId: string,
    folder?: string,
  ): Promise<EmailAttachment[]>;

  getAttachmentContent(
    messageId: string,
    attachmentId: string,
    folder?: string,
  ): Promise<{ filename: string; mimeType: string; base64Content: string }>;

  markAsRead(messageId: string, folder?: string): Promise<void>;
}

// ---------------------------------------------------------------------------
// Factory
// ---------------------------------------------------------------------------

export function createEmailAdapter(inbox: EmailInboxConfig): EmailAdapter {
  switch (inbox.provider) {
    case "gmail":
      return new GmailAdapter(
        inbox.accessToken,
        inbox.refreshToken,
        inbox.clientId,
        inbox.clientSecret,
        inbox.tokenExpiry,
      );
    case "outlook":
      return new OutlookAdapter(
        inbox.accessToken,
        inbox.refreshToken,
        inbox.clientId,
        inbox.clientSecret,
      );
    case "imap":
      return new ImapAdapter(inbox);
    default:
      throw new Error(
        `Unsupported email provider: ${(inbox as { provider: string }).provider}`,
      );
  }
}

// ---------------------------------------------------------------------------
// Gmail adapter  (@googleapis/gmail)
// ---------------------------------------------------------------------------

import { auth as gauth, gmail_v1 } from "@googleapis/gmail";

/**
 * Extract a useful message from a Google API / GaxiosError.  The raw
 * `error.message` is often just "invalid_request" — the real detail
 * lives in the response body.
 */
function gmailErrorMessage(error: unknown): string {
  if (!(error instanceof Error)) return String(error);
  const msg = error.message;

  const res = (error as { response?: { data?: unknown } }).response;
  if (res?.data) {
    const data = res.data as {
      error?: string;
      error_description?: string;
    };
    if (data.error_description) {
      return `Gmail API error: ${data.error} – ${data.error_description}`;
    }
    if (typeof res.data === "string") {
      return `Gmail API error: ${msg} – ${res.data}`;
    }
  }

  if (msg === "invalid_request" || msg === "invalid_grant") {
    return `Gmail OAuth error: ${msg}. This usually means the access token has expired and the refresh token could not be used. Ensure clientId and clientSecret are provided in the inbox config.`;
  }

  return msg;
}

class GmailAdapter implements EmailAdapter {
  private client: gmail_v1.Gmail;

  constructor(
    accessToken: string,
    refreshToken: string,
    clientId?: string,
    clientSecret?: string,
    tokenExpiry?: number,
  ) {
    const oauth2 = new gauth.OAuth2(clientId, clientSecret);
    oauth2.setCredentials({
      access_token: accessToken,
      refresh_token: refreshToken,
      expiry_date: tokenExpiry,
    });
    this.client = new gmail_v1.Gmail({ auth: oauth2 });
  }

  async listMessages(opts: {
    folder?: string;
    maxResults?: number;
    pageToken?: string;
  }): Promise<EmailListResult> {
    try {
      const q = opts.folder ? `in:${opts.folder}` : "in:inbox";
      const res = await this.client.users.messages.list({
        userId: "me",
        q,
        maxResults: opts.maxResults ?? 20,
        pageToken: opts.pageToken,
      });

      if (!res.data.messages?.length) {
        return {
          messages: [],
          totalEstimate: res.data.resultSizeEstimate ?? 0,
        };
      }

      const summaries = await Promise.all(
        res.data.messages.map((m) => this.fetchSummary(m.id!)),
      );

      return {
        messages: summaries,
        nextPageToken: res.data.nextPageToken ?? undefined,
        totalEstimate: res.data.resultSizeEstimate ?? undefined,
      };
    } catch (error) {
      throw new Error(gmailErrorMessage(error), { cause: error });
    }
  }

  private async fetchSummary(id: string): Promise<EmailMessageSummary> {
    const res = await this.client.users.messages.get({
      userId: "me",
      id,
      format: "metadata",
      metadataHeaders: ["From", "To", "Subject", "Date"],
    });
    return gmailToSummary(res.data);
  }

  async getMessage(
    messageId: string,
    _folder?: string,
  ): Promise<EmailMessageFull> {
    try {
      const res = await this.client.users.messages.get({
        userId: "me",
        id: messageId,
        format: "full",
      });
      return gmailToFull(res.data);
    } catch (error) {
      throw new Error(gmailErrorMessage(error), { cause: error });
    }
  }

  async searchMessages(opts: {
    query: string;
    folder?: string;
    maxResults?: number;
    pageToken?: string;
  }): Promise<EmailSearchResult> {
    try {
      const res = await this.client.users.messages.list({
        userId: "me",
        q: opts.query,
        maxResults: opts.maxResults ?? 20,
        pageToken: opts.pageToken,
      });

      if (!res.data.messages?.length) {
        return {
          messages: [],
          totalEstimate: res.data.resultSizeEstimate ?? 0,
        };
      }

      const summaries = await Promise.all(
        res.data.messages.map((m) => this.fetchSummary(m.id!)),
      );

      return {
        messages: summaries,
        nextPageToken: res.data.nextPageToken ?? undefined,
        totalEstimate: res.data.resultSizeEstimate ?? undefined,
      };
    } catch (error) {
      throw new Error(gmailErrorMessage(error), { cause: error });
    }
  }

  async getAttachments(
    messageId: string,
    _folder?: string,
  ): Promise<EmailAttachment[]> {
    const res = await this.client.users.messages.get({
      userId: "me",
      id: messageId,
      format: "full",
    });
    return extractGmailAttachments(res.data);
  }

  async getAttachmentContent(
    messageId: string,
    attachmentId: string,
    _folder?: string,
  ): Promise<{ filename: string; mimeType: string; base64Content: string }> {
    const attRes = await this.client.users.messages.attachments.get({
      userId: "me",
      messageId,
      id: attachmentId,
    });

    const attachments = await this.getAttachments(messageId);
    const meta = attachments.find((a) => a.id === attachmentId);

    return {
      filename: meta?.filename ?? "attachment",
      mimeType: meta?.mimeType ?? "application/octet-stream",
      base64Content: attRes.data.data ?? "",
    };
  }

  async markAsRead(messageId: string, _folder?: string): Promise<void> {
    await this.client.users.messages.modify({
      userId: "me",
      id: messageId,
      requestBody: { removeLabelIds: ["UNREAD"] },
    });
  }
}

// Gmail response helpers

function hdr(msg: gmail_v1.Schema$Message, name: string): string {
  return (
    msg.payload?.headers?.find(
      (h) => h.name?.toLowerCase() === name.toLowerCase(),
    )?.value ?? ""
  );
}

/**
 * Split an RFC 5322 address-list header on commas while respecting
 * quoted strings (e.g. `"Doe, John" <john@example.com>`).
 */
function splitAddressList(header: string): string[] {
  const result: string[] = [];
  let current = "";
  let inQuotes = false;

  for (let i = 0; i < header.length; i++) {
    const ch = header[i];
    if (ch === '"' && (i === 0 || header[i - 1] !== "\\")) {
      inQuotes = !inQuotes;
      current += ch;
    } else if (ch === "," && !inQuotes) {
      const trimmed = current.trim();
      if (trimmed) result.push(trimmed);
      current = "";
    } else {
      current += ch;
    }
  }

  const trimmed = current.trim();
  if (trimmed) result.push(trimmed);
  return result;
}

function gmailToSummary(msg: gmail_v1.Schema$Message): EmailMessageSummary {
  return {
    id: msg.id ?? "",
    from: hdr(msg, "From"),
    to: splitAddressList(hdr(msg, "To")),
    subject: hdr(msg, "Subject"),
    date: hdr(msg, "Date"),
    snippet: msg.snippet ?? "",
    isRead: !msg.labelIds?.includes("UNREAD"),
    hasAttachments: hasAttachmentParts(msg.payload?.parts),
    labels: msg.labelIds ?? undefined,
  };
}

function gmailToFull(msg: gmail_v1.Schema$Message): EmailMessageFull {
  return {
    ...gmailToSummary(msg),
    body: extractGmailBody(msg),
    cc: splitAddressList(hdr(msg, "Cc")),
    replyTo: hdr(msg, "Reply-To") || undefined,
  };
}

function extractGmailBody(msg: gmail_v1.Schema$Message): string {
  const findBody = (
    parts: gmail_v1.Schema$MessagePart[] | undefined,
  ): string => {
    if (!parts) return "";
    for (const part of parts) {
      if (part.mimeType === "text/plain" && part.body?.data) {
        return Buffer.from(part.body.data, "base64url").toString("utf-8");
      }
      if (part.parts) {
        const nested = findBody(part.parts);
        if (nested) return nested;
      }
    }
    for (const part of parts) {
      if (part.mimeType === "text/html" && part.body?.data) {
        return Buffer.from(part.body.data, "base64url").toString("utf-8");
      }
    }
    return "";
  };

  if (msg.payload?.parts) return findBody(msg.payload.parts);
  if (msg.payload?.body?.data)
    return Buffer.from(msg.payload.body.data, "base64url").toString("utf-8");
  return "";
}

function hasAttachmentParts(
  parts: gmail_v1.Schema$MessagePart[] | undefined,
): boolean {
  if (!parts) return false;
  return parts.some(
    (p) =>
      (p.filename && p.filename.length > 0) ||
      hasAttachmentParts(p.parts ?? undefined),
  );
}

function extractGmailAttachments(
  msg: gmail_v1.Schema$Message,
): EmailAttachment[] {
  const result: EmailAttachment[] = [];
  const walk = (parts: gmail_v1.Schema$MessagePart[] | undefined) => {
    if (!parts) return;
    for (const part of parts) {
      if (
        part.filename &&
        part.filename.length > 0 &&
        part.body?.attachmentId
      ) {
        result.push({
          id: part.body.attachmentId,
          filename: part.filename,
          mimeType: part.mimeType ?? "application/octet-stream",
          size: part.body.size ?? 0,
        });
      }
      if (part.parts) walk(part.parts);
    }
  };
  walk(msg.payload?.parts ?? undefined);
  return result;
}

// ---------------------------------------------------------------------------
// Outlook adapter  (@microsoft/microsoft-graph-client)
// ---------------------------------------------------------------------------

import { Client as GraphClient } from "@microsoft/microsoft-graph-client";

/** Encode a value for safe use in a Graph API URL path segment. */
function graphPathSegment(value: string): string {
  const stripped = value.replace(/\.\.|[/\\]/g, "");
  return encodeURIComponent(stripped);
}

class OutlookAdapter implements EmailAdapter {
  private accessToken: string;
  private refreshToken: string;
  private clientId: string | undefined;
  private clientSecret: string | undefined;
  private tokenExpiresAt = 0;
  private refreshPromise: Promise<void> | null = null;
  private client: GraphClient;

  constructor(
    accessToken: string,
    refreshToken: string,
    clientId?: string,
    clientSecret?: string,
  ) {
    this.accessToken = accessToken;
    this.refreshToken = refreshToken;
    this.clientId = clientId;
    this.clientSecret = clientSecret;
    this.tokenExpiresAt = OutlookAdapter.parseJwtExpiry(accessToken);
    this.client = GraphClient.init({
      authProvider: (done) => {
        this.ensureFreshToken()
          .then(() => done(null, this.accessToken))
          .catch(() => done(null, this.accessToken));
      },
    });
  }

  /**
   * Decode the `exp` claim from a JWT without verifying the signature.
   * Returns epoch-seconds, or 0 if the token is not a parseable JWT.
   */
  private static parseJwtExpiry(token: string): number {
    try {
      const payload = JSON.parse(
        Buffer.from(token.split(".")[1], "base64url").toString(),
      );
      return typeof payload.exp === "number" ? payload.exp : 0;
    } catch {
      return 0;
    }
  }

  private async ensureFreshToken(): Promise<void> {
    const nowSec = Math.floor(Date.now() / 1000);
    const bufferSec = 300; // refresh 5 min before expiry
    if (this.tokenExpiresAt > 0 && nowSec < this.tokenExpiresAt - bufferSec) {
      return;
    }
    if (!this.clientId || !this.refreshToken) return;
    if (this.refreshPromise) return this.refreshPromise;

    this.refreshPromise = (async () => {
      try {
        const params: Record<string, string> = {
          client_id: this.clientId!,
          grant_type: "refresh_token",
          refresh_token: this.refreshToken,
          scope: "https://graph.microsoft.com/.default offline_access",
        };
        if (this.clientSecret) {
          params.client_secret = this.clientSecret;
        }
        const body = new URLSearchParams(params);

        const res = await fetch(
          "https://login.microsoftonline.com/common/oauth2/v2.0/token",
          { method: "POST", body },
        );

        if (!res.ok) return;

        const data = (await res.json()) as {
          access_token?: string;
          refresh_token?: string;
        };

        if (data.access_token) {
          this.accessToken = data.access_token;
          this.tokenExpiresAt = OutlookAdapter.parseJwtExpiry(
            data.access_token,
          );
        }
        if (data.refresh_token) {
          this.refreshToken = data.refresh_token;
        }
      } finally {
        this.refreshPromise = null;
      }
    })();

    return this.refreshPromise;
  }

  async listMessages(opts: {
    folder?: string;
    maxResults?: number;
    pageToken?: string;
  }): Promise<EmailListResult> {
    const top = opts.maxResults ?? 20;
    const folder = opts.folder ?? "inbox";

    let req = this.client
      .api(`/me/mailFolders/${graphPathSegment(folder)}/messages`)
      .top(top)
      .orderby("receivedDateTime desc")
      .select(
        "id,from,toRecipients,subject,receivedDateTime,bodyPreview,isRead,hasAttachments",
      );

    if (opts.pageToken) {
      req = this.client.api(opts.pageToken);
    }

    const data = await req.get();
    return {
      messages: (data.value as OutlookMsg[]).map(outlookToSummary),
      nextPageToken: data["@odata.nextLink"] ?? undefined,
      totalEstimate: data["@odata.count"] ?? undefined,
    };
  }

  async getMessage(
    messageId: string,
    _folder?: string,
  ): Promise<EmailMessageFull> {
    const msg: OutlookMsg = await this.client
      .api(`/me/messages/${graphPathSegment(messageId)}`)
      .get();
    return outlookToFull(msg);
  }

  async searchMessages(opts: {
    query: string;
    folder?: string;
    maxResults?: number;
    pageToken?: string;
  }): Promise<EmailSearchResult> {
    const top = opts.maxResults ?? 20;

    let req = this.client
      .api("/me/messages")
      .search(opts.query)
      .top(top)
      .select(
        "id,from,toRecipients,subject,receivedDateTime,bodyPreview,isRead,hasAttachments",
      );

    if (opts.pageToken) {
      req = this.client.api(opts.pageToken);
    }

    const data = await req.get();
    return {
      messages: (data.value as OutlookMsg[]).map(outlookToSummary),
      nextPageToken: data["@odata.nextLink"] ?? undefined,
      totalEstimate: data["@odata.count"] ?? undefined,
    };
  }

  async getAttachments(
    messageId: string,
    _folder?: string,
  ): Promise<EmailAttachment[]> {
    const data = await this.client
      .api(`/me/messages/${graphPathSegment(messageId)}/attachments`)
      .get();
    return (
      data.value as {
        id: string;
        name: string;
        contentType: string;
        size: number;
      }[]
    ).map((a) => ({
      id: a.id,
      filename: a.name,
      mimeType: a.contentType,
      size: a.size,
    }));
  }

  async getAttachmentContent(
    messageId: string,
    attachmentId: string,
    _folder?: string,
  ): Promise<{ filename: string; mimeType: string; base64Content: string }> {
    const data = await this.client
      .api(
        `/me/messages/${graphPathSegment(messageId)}/attachments/${graphPathSegment(attachmentId)}`,
      )
      .get();
    return {
      filename: data.name,
      mimeType: data.contentType,
      base64Content: data.contentBytes,
    };
  }

  async markAsRead(messageId: string, _folder?: string): Promise<void> {
    await this.client
      .api(`/me/messages/${graphPathSegment(messageId)}`)
      .patch({ isRead: true });
  }
}

type OutlookMsg = {
  id: string;
  from?: { emailAddress: { name?: string; address: string } };
  toRecipients?: { emailAddress: { name?: string; address: string } }[];
  ccRecipients?: { emailAddress: { name?: string; address: string } }[];
  subject?: string;
  receivedDateTime?: string;
  bodyPreview?: string;
  isRead?: boolean;
  hasAttachments?: boolean;
  body?: { contentType: string; content: string };
  replyTo?: { emailAddress: { name?: string; address: string } }[];
};

function fmtAddr(a: { name?: string; address: string }): string {
  return a.name ? `${a.name} <${a.address}>` : a.address;
}

function outlookToSummary(msg: OutlookMsg): EmailMessageSummary {
  return {
    id: msg.id,
    from: msg.from?.emailAddress ? fmtAddr(msg.from.emailAddress) : "",
    to: (msg.toRecipients ?? []).map((r) => fmtAddr(r.emailAddress)),
    subject: msg.subject ?? "",
    date: msg.receivedDateTime ?? "",
    snippet: msg.bodyPreview ?? "",
    isRead: msg.isRead ?? false,
    hasAttachments: msg.hasAttachments ?? false,
  };
}

function outlookToFull(msg: OutlookMsg): EmailMessageFull {
  return {
    ...outlookToSummary(msg),
    body: msg.body?.content ?? "",
    cc: (msg.ccRecipients ?? []).map((r) => fmtAddr(r.emailAddress)),
    replyTo: msg.replyTo?.[0]?.emailAddress?.address ?? undefined,
  };
}

// ---------------------------------------------------------------------------
// IMAP adapter  (imapflow)
// ---------------------------------------------------------------------------

import {
  ImapFlow,
  type MessageAddressObject,
  type MessageStructureObject,
} from "imapflow";

class ImapAdapter implements EmailAdapter {
  private cfg: {
    host: string;
    port: number;
    user: string;
    pass: string;
    tls: boolean;
  };

  constructor(inbox: {
    imapHost: string;
    imapPort: number;
    username: string;
    password: string;
    tls: boolean;
  }) {
    this.cfg = {
      host: inbox.imapHost,
      port: inbox.imapPort,
      user: inbox.username,
      pass: inbox.password,
      tls: inbox.tls,
    };
  }

  private async connect(): Promise<ImapFlow> {
    const client = new ImapFlow({
      host: this.cfg.host,
      port: this.cfg.port,
      secure: this.cfg.tls,
      auth: { user: this.cfg.user, pass: this.cfg.pass },
      logger: false,
    });
    await client.connect();
    return client;
  }

  async listMessages(opts: {
    folder?: string;
    maxResults?: number;
    pageToken?: string;
  }): Promise<EmailListResult> {
    const client = await this.connect();
    try {
      const folder = opts.folder ?? "INBOX";
      const max = opts.maxResults ?? 20;
      const offset = opts.pageToken ? parseInt(opts.pageToken, 10) : 0;

      const lock = await client.getMailboxLock(folder);
      try {
        const status = await client.status(folder, { messages: true });
        const total = status.messages ?? 0;
        if (total === 0 || offset >= total) {
          return { messages: [], totalEstimate: total };
        }

        // IMAP sequence numbers are 1-based, newest last
        const start = Math.max(1, total - offset - max + 1);
        const end = Math.max(1, total - offset);
        const range = `${start}:${end}`;

        const messages: EmailMessageSummary[] = [];
        for await (const msg of client.fetch(range, {
          envelope: true,
          flags: true,
          bodyStructure: true,
        })) {
          const env = msg.envelope;
          messages.push({
            id: String(msg.uid),
            from: env?.from?.[0] ? fmtImapAddr(env.from[0]) : "",
            to: (env?.to ?? []).map(fmtImapAddr),
            subject: env?.subject ?? "",
            date: env?.date?.toISOString() ?? "",
            snippet: "",
            isRead: msg.flags?.has("\\Seen") ?? false,
            hasAttachments: hasImapAttachments(msg.bodyStructure),
          });
        }

        messages.reverse(); // newest first
        const nextOffset = offset + max;
        return {
          messages,
          nextPageToken: nextOffset < total ? String(nextOffset) : undefined,
          totalEstimate: total,
        };
      } finally {
        lock.release();
      }
    } finally {
      await client.logout();
    }
  }

  async getMessage(
    messageId: string,
    folder?: string,
  ): Promise<EmailMessageFull> {
    const client = await this.connect();
    try {
      const lock = await client.getMailboxLock(folder ?? "INBOX");
      try {
        const uid = parseInt(messageId, 10);
        let result: EmailMessageFull | null = null;

        for await (const msg of client.fetch(
          { uid },
          {
            envelope: true,
            flags: true,
            bodyStructure: true,
            source: true,
          },
        )) {
          const env = msg.envelope;
          if (!msg.source) continue;
          const parsed = await simpleParser(msg.source);

          result = {
            id: String(msg.uid),
            from: env?.from?.[0] ? fmtImapAddr(env.from[0]) : "",
            to: (env?.to ?? []).map(fmtImapAddr),
            subject: env?.subject ?? "",
            date: env?.date?.toISOString() ?? "",
            snippet: (parsed.text ?? "").slice(0, 200),
            isRead: msg.flags?.has("\\Seen") ?? false,
            hasAttachments: (parsed.attachments?.length ?? 0) > 0,
            body: truncate(parsed.text || parsed.html || "", 50000),
            cc: (env?.cc ?? []).map(fmtImapAddr),
            replyTo: env?.replyTo?.[0]?.address ?? undefined,
          };
        }

        if (!result) throw new Error(`Message UID ${messageId} not found`);
        return result;
      } finally {
        lock.release();
      }
    } finally {
      await client.logout();
    }
  }

  async searchMessages(opts: {
    query: string;
    folder?: string;
    maxResults?: number;
    pageToken?: string;
  }): Promise<EmailSearchResult> {
    const client = await this.connect();
    try {
      const lock = await client.getMailboxLock(opts.folder ?? "INBOX");
      try {
        const uids = await client.search({ body: opts.query });
        if (!uids || uids.length === 0) {
          return { messages: [], totalEstimate: 0 };
        }

        const total = uids.length;
        const max = opts.maxResults ?? 20;
        const page = uids.slice(-max).reverse();
        const messages: EmailMessageSummary[] = [];

        for await (const msg of client.fetch(
          { uid: page.join(",") },
          { envelope: true, flags: true, bodyStructure: true },
        )) {
          const env = msg.envelope;
          messages.push({
            id: String(msg.uid),
            from: env?.from?.[0] ? fmtImapAddr(env.from[0]) : "",
            to: (env?.to ?? []).map(fmtImapAddr),
            subject: env?.subject ?? "",
            date: env?.date?.toISOString() ?? "",
            snippet: "",
            isRead: msg.flags?.has("\\Seen") ?? false,
            hasAttachments: hasImapAttachments(msg.bodyStructure),
          });
        }

        return { messages, totalEstimate: total };
      } finally {
        lock.release();
      }
    } finally {
      await client.logout();
    }
  }

  async getAttachments(
    messageId: string,
    folder?: string,
  ): Promise<EmailAttachment[]> {
    const client = await this.connect();
    try {
      const lock = await client.getMailboxLock(folder ?? "INBOX");
      try {
        const uid = parseInt(messageId, 10);

        for await (const msg of client.fetch({ uid }, { source: true })) {
          if (!msg.source) continue;
          const parsed = await simpleParser(msg.source);
          return (parsed.attachments ?? []).map(
            (att: ParsedAttachment, i: number) => ({
              id: att.checksum ?? String(i),
              filename: att.filename ?? `attachment_${i}`,
              mimeType: att.contentType ?? "application/octet-stream",
              size: att.size ?? 0,
            }),
          );
        }

        return [];
      } finally {
        lock.release();
      }
    } finally {
      await client.logout();
    }
  }

  async getAttachmentContent(
    messageId: string,
    attachmentId: string,
    folder?: string,
  ): Promise<{ filename: string; mimeType: string; base64Content: string }> {
    const client = await this.connect();
    try {
      const lock = await client.getMailboxLock(folder ?? "INBOX");
      try {
        const uid = parseInt(messageId, 10);

        for await (const msg of client.fetch({ uid }, { source: true })) {
          if (!msg.source) continue;
          const parsed = await simpleParser(msg.source);

          const att = (parsed.attachments ?? []).find(
            (a: ParsedAttachment, i: number) =>
              (a.checksum ?? String(i)) === attachmentId,
          );

          if (!att) throw new Error(`Attachment ${attachmentId} not found`);

          return {
            filename: att.filename ?? "attachment",
            mimeType: att.contentType ?? "application/octet-stream",
            base64Content: att.content.toString("base64"),
          };
        }

        throw new Error(`Message UID ${messageId} not found`);
      } finally {
        lock.release();
      }
    } finally {
      await client.logout();
    }
  }

  async markAsRead(messageId: string, folder?: string): Promise<void> {
    const client = await this.connect();
    try {
      const lock = await client.getMailboxLock(folder ?? "INBOX");
      try {
        await client.messageFlagsAdd({ uid: parseInt(messageId, 10) }, [
          "\\Seen",
        ]);
      } finally {
        lock.release();
      }
    } finally {
      await client.logout();
    }
  }
}

function fmtImapAddr(a: MessageAddressObject): string {
  return `${a.name ?? ""} <${a.address ?? ""}>`.trim();
}

function hasImapAttachments(
  bodyStructure: MessageStructureObject | undefined,
): boolean {
  if (!bodyStructure) return false;
  if (bodyStructure.disposition === "attachment") return true;
  if (bodyStructure.childNodes) {
    return bodyStructure.childNodes.some(hasImapAttachments);
  }
  return false;
}

function truncate(s: string, max: number): string {
  return s.length > max ? s.slice(0, max) + "\n\n(truncated)" : s;
}
