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

import {
  afterEach,
  beforeAll,
  beforeEach,
  describe,
  expect,
  it,
  vi,
} from "vitest";
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

// ---------------------------------------------------------------------------
// HTTP adapter (unit — mocked fetch)
// ---------------------------------------------------------------------------

const HTTP_INBOX: EmailInboxConfig = {
  provider: "http",
  id: "test-http-inbox",
  name: "Managed inbox",
  emailAddress: "pentest-acme-1@agents.pensar.dev",
  endpoint: "https://api.example.dev/agent/mailbox",
  token: "run-jwt-token",
};

const SUMMARY = {
  id: "msg-1",
  from: "target@example.com",
  to: ["pentest-acme-1@agents.pensar.dev"],
  subject: "Your code",
  date: "2026-07-15T00:00:00.000Z",
  snippet: "Your verification code is 123456",
  isRead: false,
  hasAttachments: false,
};

describe("HttpAdapter (unit)", () => {
  const fetchMock = vi.fn();

  beforeEach(() => {
    vi.stubGlobal("fetch", fetchMock);
    fetchMock.mockReset();
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  function jsonResponse(body: unknown, ok = true, status = 200): Response {
    return {
      ok,
      status,
      statusText: ok ? "OK" : "Error",
      json: async () => body,
    } as unknown as Response;
  }

  function lastRequestUrl(): URL {
    const arg = fetchMock.mock.calls.at(-1)?.[0];
    return arg instanceof URL ? arg : new URL(String(arg));
  }

  function lastAuthHeader(): string | undefined {
    const init = fetchMock.mock.calls.at(-1)?.[1] as RequestInit | undefined;
    return (init?.headers as Record<string, string> | undefined)?.Authorization;
  }

  it("listMessages maps the wire shape and sends address/limit/cursor + bearer", async () => {
    fetchMock.mockResolvedValueOnce(
      jsonResponse({ messages: [SUMMARY], nextCursor: "cursor-2" }),
    );

    const adapter = createEmailAdapter(HTTP_INBOX);
    const result = await adapter.listMessages({
      maxResults: 10,
      pageToken: "cursor-1",
    });

    expect(result.messages).toEqual([SUMMARY]);
    expect(result.nextPageToken).toBe("cursor-2");

    const url = lastRequestUrl();
    expect(url.pathname).toBe("/agent/mailbox/messages");
    expect(url.searchParams.get("address")).toBe(HTTP_INBOX.emailAddress);
    expect(url.searchParams.get("limit")).toBe("10");
    expect(url.searchParams.get("cursor")).toBe("cursor-1");
    expect(lastAuthHeader()).toBe("Bearer run-jwt-token");
  });

  it("searchMessages passes the q param", async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse({ messages: [SUMMARY] }));

    const adapter = createEmailAdapter(HTTP_INBOX);
    const result = await adapter.searchMessages({ query: "verification" });

    expect(result.messages).toEqual([SUMMARY]);
    expect(result.nextPageToken).toBeUndefined();

    const url = lastRequestUrl();
    expect(url.pathname).toBe("/agent/mailbox/messages");
    expect(url.searchParams.get("q")).toBe("verification");
    expect(url.searchParams.get("address")).toBe(HTTP_INBOX.emailAddress);
  });

  it("getMessage fetches by id path and returns the full message", async () => {
    const full = { ...SUMMARY, body: "Your verification code is 123456" };
    fetchMock.mockResolvedValueOnce(jsonResponse(full));

    const adapter = createEmailAdapter(HTTP_INBOX);
    const result = await adapter.getMessage("msg-1");

    expect(result).toEqual(full);
    expect(lastRequestUrl().pathname).toBe("/agent/mailbox/messages/msg-1");
    expect(lastAuthHeader()).toBe("Bearer run-jwt-token");
  });

  it("getAttachments returns empty and markAsRead is a no-op (no fetch)", async () => {
    const adapter = createEmailAdapter(HTTP_INBOX);

    await expect(adapter.getAttachments("msg-1")).resolves.toEqual([]);
    await expect(adapter.markAsRead("msg-1")).resolves.toBeUndefined();
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("throws on a non-ok response", async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse(null, false, 401));

    const adapter = createEmailAdapter(HTTP_INBOX);
    await expect(adapter.listMessages({})).rejects.toThrow(/401/);
  });
});
