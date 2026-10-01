import { describe, expect, it, vi } from "vitest";
import type { EmailInboxConfig } from "../../../../session";
import type { ToolBackends } from "../../../../tools/backends/types";
import type { ToolContext } from "../types";
import type { EmailAdapter } from "./adapters";
import { emailGetAttachments } from "./getAttachments";
import { emailGetMessage } from "./getMessage";
import { emailListMessages } from "./listMessages";
import { emailMarkRead } from "./markRead";
import { emailSearchMessages } from "./searchMessages";

const executeOpts = { toolCallId: "call_1", messages: [] };

const INBOX: EmailInboxConfig = {
  provider: "pensar-managed",
  id: "inbox-1",
  name: "Primary",
  emailAddress: "alice@example.com",
};

function fakeAdapter(): EmailAdapter {
  return {
    listMessages: vi.fn(async () => ({ messages: [], totalEstimate: 0 })),
    getMessage: vi.fn(async () => ({
      id: "m1",
      from: "",
      to: [],
      subject: "",
      date: "",
      snippet: "",
      isRead: true,
      hasAttachments: false,
      body: "",
    })),
    searchMessages: vi.fn(async () => ({ messages: [], totalEstimate: 0 })),
    getAttachments: vi.fn(async () => []),
    getAttachmentContent: vi.fn(async () => ({
      filename: "f",
      mimeType: "text/plain",
      base64Content: "",
    })),
    markAsRead: vi.fn(async () => {}),
  };
}

function makeCtx(backends?: Partial<ToolBackends>): ToolContext {
  return {
    session: { config: { emailIntegration: { inboxes: [INBOX] } } },
    agentCwd: "/tmp",
    ...(backends ? { backends: backends as ToolBackends } : {}),
  } as ToolContext;
}

describe("email tools resolve the adapter from ctx.backends.inbox", () => {
  it("email_list_messages uses the injected resolver, not the pensar-managed default", async () => {
    const adapter = fakeAdapter();
    const email = vi.fn(() => adapter);
    const ctx = makeCtx({ inbox: { email, sms: undefined as never } });

    const result = await emailListMessages(ctx).execute?.(
      { toolCallDescription: "test", inboxId: INBOX.id },
      executeOpts,
    );

    expect(email).toHaveBeenCalledWith(INBOX);
    expect(adapter.listMessages).toHaveBeenCalled();
    expect(result).toMatchObject({ success: true });
  });

  it("email_get_message uses the injected resolver", async () => {
    const adapter = fakeAdapter();
    const email = vi.fn(() => adapter);
    const ctx = makeCtx({ inbox: { email, sms: undefined as never } });

    await emailGetMessage(ctx).execute?.(
      { toolCallDescription: "test", inboxId: INBOX.id, messageId: "m1" },
      executeOpts,
    );

    expect(email).toHaveBeenCalledWith(INBOX);
    expect(adapter.getMessage).toHaveBeenCalledWith("m1", undefined);
  });

  it("email_search_messages uses the injected resolver", async () => {
    const adapter = fakeAdapter();
    const email = vi.fn(() => adapter);
    const ctx = makeCtx({ inbox: { email, sms: undefined as never } });

    await emailSearchMessages(ctx).execute?.(
      { toolCallDescription: "test", inboxId: INBOX.id, query: "otp" },
      executeOpts,
    );

    expect(email).toHaveBeenCalledWith(INBOX);
    expect(adapter.searchMessages).toHaveBeenCalled();
  });

  it("email_get_attachments uses the injected resolver", async () => {
    const adapter = fakeAdapter();
    const email = vi.fn(() => adapter);
    const ctx = makeCtx({ inbox: { email, sms: undefined as never } });

    await emailGetAttachments(ctx).execute?.(
      { toolCallDescription: "test", inboxId: INBOX.id, messageId: "m1" },
      executeOpts,
    );

    expect(email).toHaveBeenCalledWith(INBOX);
    expect(adapter.getAttachments).toHaveBeenCalledWith("m1", undefined);
  });

  it("email_mark_read uses the injected resolver", async () => {
    const adapter = fakeAdapter();
    const email = vi.fn(() => adapter);
    const ctx = makeCtx({ inbox: { email, sms: undefined as never } });

    await emailMarkRead(ctx).execute?.(
      { toolCallDescription: "test", inboxId: INBOX.id, messageId: "m1" },
      executeOpts,
    );

    expect(email).toHaveBeenCalledWith(INBOX);
    expect(adapter.markAsRead).toHaveBeenCalledWith("m1", undefined);
  });

  it("without an injected resolver, a pensar-managed inbox fails loud instead of silently reading nothing", async () => {
    const ctx = makeCtx();

    const result = (await emailListMessages(ctx).execute?.(
      { toolCallDescription: "test", inboxId: INBOX.id },
      executeOpts,
    )) as { success: boolean; error?: string };

    expect(result.success).toBe(false);
    expect(result.error).toContain("pensar-managed");
  });
});
