import { afterEach, describe, expect, it, vi } from "vitest";
import { CredentialManager } from "../../../credentials";
import type { SessionInfo } from "../../../session";
import { PLAN_MODE_TOOL_NAMES } from "./index";
import {
  SMS_LIST_MESSAGES_TOOL_NAME,
  sessionHasSmsPasswordless,
  smsListMessages,
} from "./smsListMessages";
import { inProcessSubagentSpawner } from "../subagentSpawner";
import type { ToolContext } from "./types";

const executeOpts = { toolCallId: "call_1", messages: [] };

function makeCtx(cm?: CredentialManager): ToolContext {
  const credentialManager = cm ?? new CredentialManager();
  return {
    session: { credentialManager } as SessionInfo,
    agentCwd: "/tmp",
    credentialManager,
    subagentSpawner: inProcessSubagentSpawner,
  };
}

function listedResponse() {
  return {
    ok: true,
    status: 200,
    json: async () => ({
      messages: [
        {
          id: "msg-1",
          body: "Your code is 424242",
          code: "424242",
          fromPhoneNumber: "+15550001111",
          toPhoneNumber: "+15551234567",
          receivedAt: "2026-04-10T12:00:00.000Z",
          consumedAt: null,
        },
      ],
      claimed: null,
    }),
  };
}

function claimedResponse() {
  return {
    ok: true,
    status: 200,
    json: async () => ({
      messages: [
        {
          id: "msg-1",
          body: "Your code is 424242",
          code: "424242",
          fromPhoneNumber: "+15550001111",
          toPhoneNumber: "+15551234567",
          receivedAt: "2026-04-10T12:00:00.000Z",
          consumedAt: "2026-04-10T12:00:01.000Z",
        },
      ],
      claimed: {
        id: "msg-1",
        body: "Your code is 424242",
        code: "424242",
        fromPhoneNumber: "+15550001111",
        toPhoneNumber: "+15551234567",
        receivedAt: "2026-04-10T12:00:00.000Z",
        consumedAt: "2026-04-10T12:00:01.000Z",
      },
    }),
  };
}

describe("sessionHasSmsPasswordless", () => {
  it("detects a phoneNumber additional field on the credential manager", () => {
    const cm = new CredentialManager();
    cm.add({
      additionalFields: { phoneNumber: "+15551234567" },
      loginUrl: "https://app.example.com/login",
    });
    expect(
      sessionHasSmsPasswordless({ credentialManager: cm } as SessionInfo),
    ).toBe(true);
  });

  it("detects a phoneNumber on session authCredentials", () => {
    expect(
      sessionHasSmsPasswordless({
        config: {
          authCredentials: {
            additionalFields: { phoneNumber: "test-phone-number" },
          },
        },
      } as unknown as SessionInfo),
    ).toBe(true);
  });

  it("requires a phoneNumber for sms-passwordless credentials", () => {
    expect(
      sessionHasSmsPasswordless({
        config: {
          authCredentials: {
            additionalFields: { authMethod: "sms-passwordless" },
          },
        },
      } as unknown as SessionInfo),
    ).toBe(false);
  });

  it("returns false when the session has no Mobile OTP credential", () => {
    expect(sessionHasSmsPasswordless({} as SessionInfo)).toBe(false);
  });
});

describe("smsListMessages", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
    vi.unstubAllEnvs();
  });

  it("uses the stable tool name", () => {
    expect(SMS_LIST_MESSAGES_TOOL_NAME).toBe("sms_list_messages");
  });

  it("is available in plan mode", () => {
    expect(PLAN_MODE_TOOL_NAMES).toContain(SMS_LIST_MESSAGES_TOOL_NAME);
  });

  it("fails loud when AGENT_API_URL is unset", async () => {
    vi.stubEnv("AGENT_API_URL", "");
    vi.stubEnv("AGENT_API_TOKEN", "token");
    const tool = smsListMessages(makeCtx());
    await expect(
      tool.execute?.(
        {
          sinceMs: 1,
          phoneNumber: "+15551234567",
          toolCallDescription: "list",
        },
        executeOpts,
      ),
    ).rejects.toThrow("AGENT_API_URL");
  });

  it("lists inbound SMS without claiming", async () => {
    vi.stubEnv("AGENT_API_URL", "https://api.example.com");
    vi.stubEnv("AGENT_API_TOKEN", "token");
    const cm = new CredentialManager();
    cm.add({
      id: "cred-1",
      additionalFields: { phoneNumber: "+15551234567" },
      loginUrl: "https://app.example.com/login",
    });

    const fetchMock = vi.fn().mockResolvedValue(listedResponse());
    vi.stubGlobal("fetch", fetchMock);

    const tool = smsListMessages(makeCtx(cm));
    const result = await tool.execute?.(
      {
        credentialId: "cred-1",
        sinceMs: 1_700_000_000_000,
        toolCallDescription: "list inbound SMS",
      },
      executeOpts,
    );

    expect(result).toEqual({
      success: true,
      messages: [
        {
          id: "msg-1",
          body: "Your code is 424242",
          code: "424242",
          fromPhoneNumber: "+15550001111",
          toPhoneNumber: "+15551234567",
          receivedAt: "2026-04-10T12:00:00.000Z",
          consumedAt: null,
        },
      ],
      claimed: null,
    });
    expect(fetchMock).toHaveBeenCalledTimes(1);
    const url = String(fetchMock.mock.calls[0]?.[0]);
    expect(url).toContain("/agent/sms/messages?");
    expect(url).toContain("toPhoneNumber=%2B15551234567");
    expect(url).not.toContain("claim=");
  });

  it("claims the newest unconsumed SMS when claim is true", async () => {
    vi.stubEnv("AGENT_API_URL", "https://api.example.com");
    vi.stubEnv("AGENT_API_TOKEN", "token");

    const fetchMock = vi.fn().mockResolvedValue(claimedResponse());
    vi.stubGlobal("fetch", fetchMock);

    const tool = smsListMessages(makeCtx());
    const result = await tool.execute?.(
      {
        phoneNumber: "+15551234567",
        sinceMs: 1,
        claim: true,
        toolCallDescription: "claim login code",
      },
      executeOpts,
    );

    expect(result).toMatchObject({
      success: true,
      claimed: { id: "msg-1", code: "424242" },
    });
    const url = String(fetchMock.mock.calls[0]?.[0]);
    expect(url).toContain("claim=1");
  });

  it("returns a lease conflict without retrying", async () => {
    vi.stubEnv("AGENT_API_URL", "https://api.example.com");
    vi.stubEnv("AGENT_API_TOKEN", "token");

    const fetchMock = vi.fn().mockResolvedValue({
      ok: false,
      status: 429,
      statusText: "Too Many Requests",
    });
    vi.stubGlobal("fetch", fetchMock);

    const tool = smsListMessages(makeCtx());
    const result = await tool.execute?.(
      {
        phoneNumber: "+15551234567",
        sinceMs: 1,
        toolCallDescription: "list",
      },
      executeOpts,
    );

    expect(result).toEqual({
      success: false,
      error:
        "Another agent run holds the exclusive lease on this phone number. Wait and retry, or use a different Mobile OTP number.",
    });
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it("lists from session authCredentials when no credential manager phone is present", async () => {
    vi.stubEnv("AGENT_API_URL", "https://api.example.com");
    vi.stubEnv("AGENT_API_TOKEN", "token");

    const fetchMock = vi.fn().mockResolvedValue(listedResponse());
    vi.stubGlobal("fetch", fetchMock);

    const tool = smsListMessages({
      session: {
        config: {
          authCredentials: {
            additionalFields: { phoneNumber: "+15551234567" },
          },
        },
      } as unknown as SessionInfo,
      agentCwd: "/tmp",
      subagentSpawner: inProcessSubagentSpawner,
    });
    const result = await tool.execute?.(
      {
        sinceMs: 1,
        toolCallDescription: "list",
      },
      executeOpts,
    );

    expect(result).toMatchObject({ success: true });
    const url = String(fetchMock.mock.calls[0]?.[0]);
    expect(url).toContain("toPhoneNumber=%2B15551234567");
  });

  it("fails the credentialId path when the stored credential has no phoneNumber", async () => {
    vi.stubEnv("AGENT_API_URL", "https://api.example.com");
    vi.stubEnv("AGENT_API_TOKEN", "token");
    const cm = new CredentialManager();
    cm.add({
      id: "cred-1",
      additionalFields: { authMethod: "sms-passwordless" },
      loginUrl: "https://app.example.com/login",
    });
    const tool = smsListMessages(makeCtx(cm));
    await expect(
      tool.execute?.(
        {
          credentialId: "cred-1",
          sinceMs: 1,
          toolCallDescription: "list",
        },
        executeOpts,
      ),
    ).rejects.toThrow("has no phoneNumber additional field");
  });

  it("returns already-consumed without polling", async () => {
    vi.stubEnv("AGENT_API_URL", "https://api.example.com");
    vi.stubEnv("AGENT_API_TOKEN", "token");

    const fetchMock = vi.fn().mockResolvedValue({
      ok: false,
      status: 409,
      statusText: "Conflict",
    });
    vi.stubGlobal("fetch", fetchMock);

    const tool = smsListMessages(makeCtx());
    const result = await tool.execute?.(
      {
        phoneNumber: "+15551234567",
        sinceMs: 1,
        claim: true,
        toolCallDescription: "claim",
      },
      executeOpts,
    );

    expect(result).toEqual({
      success: false,
      error:
        "That SMS was already claimed. List without claim, or wait for a newer message.",
    });
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });
});
