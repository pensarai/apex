/**
 * Integration tests for the Gmail email adapter.
 *
 * These tests hit the real Gmail API and require valid OAuth2 credentials.
 * They are skipped automatically when the required env vars are missing.
 *
 * Required env vars:
 *   GMAIL_CLIENT_ID       – Google Cloud OAuth2 client ID
 *   GMAIL_CLIENT_SECRET   – Google Cloud OAuth2 client secret
 *   GMAIL_ACCESS_TOKEN    – Current OAuth2 access token (can be expired if refresh token works)
 *   GMAIL_REFRESH_TOKEN   – Long-lived OAuth2 refresh token
 *   GMAIL_TEST_EMAIL      – The Gmail address under test (e.g. dev@pensarai.com)
 */

import { beforeAll, describe, expect, it } from "vitest";
import type { EmailInboxConfig } from "../../../../session";
import { createEmailAdapter, type EmailAdapter } from "./adapters";

const REQUIRED_ENV = [
  "GMAIL_CLIENT_ID",
  "GMAIL_CLIENT_SECRET",
  "GMAIL_REFRESH_TOKEN",
  "GMAIL_TEST_EMAIL",
] as const;

const hasCredentials = REQUIRED_ENV.every((key) => process.env[key]);

const describeGmail = hasCredentials ? describe : describe.skip;

describeGmail("GmailAdapter (integration)", () => {
  let adapter: EmailAdapter;

  beforeAll(() => {
    const inbox: EmailInboxConfig = {
      provider: "gmail",
      id: "test-gmail-inbox",
      name: process.env.GMAIL_TEST_EMAIL!,
      emailAddress: process.env.GMAIL_TEST_EMAIL!,
      accessToken: process.env.GMAIL_ACCESS_TOKEN ?? "",
      refreshToken: process.env.GMAIL_REFRESH_TOKEN!,
      clientId: process.env.GMAIL_CLIENT_ID!,
      clientSecret: process.env.GMAIL_CLIENT_SECRET!,
    };

    adapter = createEmailAdapter(inbox);
  });

  it("listMessages returns messages from inbox", async () => {
    const result = await adapter.listMessages({ maxResults: 5 });

    expect(result).toBeDefined();
    expect(result.messages).toBeInstanceOf(Array);
    expect(result.totalEstimate).toBeGreaterThanOrEqual(0);

    if (result.messages.length > 0) {
      const msg = result.messages[0];
      expect(msg.id).toBeTruthy();
      expect(msg.from).toBeTruthy();
      expect(msg.subject).toBeDefined();
      expect(msg.date).toBeTruthy();
      expect(typeof msg.isRead).toBe("boolean");
    }
  });

  it("searchMessages returns results for a broad query", async () => {
    const result = await adapter.searchMessages({
      query: "in:inbox",
      maxResults: 5,
    });

    expect(result).toBeDefined();
    expect(result.messages).toBeInstanceOf(Array);
  });

  it("getMessage retrieves a full message by ID", async () => {
    const list = await adapter.listMessages({ maxResults: 1 });
    if (list.messages.length === 0) {
      return; // empty inbox, nothing to test
    }

    const messageId = list.messages[0].id;
    const full = await adapter.getMessage(messageId);

    expect(full.id).toBe(messageId);
    expect(full.body).toBeDefined();
    expect(full.from).toBeTruthy();
    expect(full.subject).toBeDefined();
  });

  it("getAttachments returns attachment list for a message", async () => {
    const list = await adapter.listMessages({ maxResults: 1 });
    if (list.messages.length === 0) return;

    const attachments = await adapter.getAttachments(list.messages[0].id);
    expect(attachments).toBeInstanceOf(Array);
  });

  it("listMessages supports folder parameter", async () => {
    const result = await adapter.listMessages({
      folder: "sent",
      maxResults: 3,
    });

    expect(result).toBeDefined();
    expect(result.messages).toBeInstanceOf(Array);
  });

  it("listMessages supports pagination", async () => {
    const page1 = await adapter.listMessages({ maxResults: 2 });

    if (page1.nextPageToken) {
      const page2 = await adapter.listMessages({
        maxResults: 2,
        pageToken: page1.nextPageToken,
      });

      expect(page2.messages).toBeInstanceOf(Array);
      if (page2.messages.length > 0 && page1.messages.length > 0) {
        expect(page2.messages[0].id).not.toBe(page1.messages[0].id);
      }
    }
  });
});
