import { afterEach, describe, expect, it, vi } from "vitest";
import { CredentialManager } from "../../../credentials";
import type { SessionInfo } from "../../../session";
import {
  SMS_WAIT_FOR_CODE_TOOL_NAME,
  sessionHasSmsPasswordless,
  smsWaitForCode,
} from "./smsWaitForCode";
import type { ToolContext } from "./types";

const executeOpts = { toolCallId: "call_1", messages: [] };

function makeCtx(cm?: CredentialManager): ToolContext {
  const credentialManager = cm ?? new CredentialManager();
  return {
    session: { credentialManager } as SessionInfo,
    agentCwd: "/tmp",
    credentialManager,
  };
}

function claimedResponse() {
  return {
    ok: true,
    status: 200,
    json: async () => ({
      messages: [],
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

  it("detects authMethod sms-passwordless on session authCredentials", () => {
    expect(
      sessionHasSmsPasswordless({
        config: {
          authCredentials: {
            additionalFields: { authMethod: "sms-passwordless" },
          },
        },
      } as SessionInfo),
    ).toBe(true);
  });

  it("returns false when the session has no Mobile OTP credential", () => {
    expect(sessionHasSmsPasswordless({} as SessionInfo)).toBe(false);
  });
});

describe("smsWaitForCode", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
    vi.unstubAllEnvs();
    vi.useRealTimers();
  });

  it("uses the stable tool name", () => {
    expect(SMS_WAIT_FOR_CODE_TOOL_NAME).toBe("sms_wait_for_code");
  });

  it("fails loud when AGENT_API_URL is unset", async () => {
    vi.stubEnv("AGENT_API_URL", "");
    vi.stubEnv("AGENT_API_TOKEN", "token");
    const tool = smsWaitForCode(makeCtx());
    await expect(
      tool.execute?.(
        {
          sinceMs: 1,
          phoneNumber: "+15551234567",
          toolCallDescription: "wait",
        },
        executeOpts,
      ),
    ).rejects.toThrow("AGENT_API_URL");
  });

  it("claims the first inbound SMS and returns the parsed code", async () => {
    vi.stubEnv("AGENT_API_URL", "https://api.example.com");
    vi.stubEnv("AGENT_API_TOKEN", "token");
    const cm = new CredentialManager();
    cm.add({
      id: "cred-1",
      additionalFields: { phoneNumber: "+15551234567" },
      loginUrl: "https://app.example.com/login",
    });

    const fetchMock = vi.fn().mockResolvedValue(claimedResponse());
    vi.stubGlobal("fetch", fetchMock);

    const tool = smsWaitForCode(makeCtx(cm));
    const result = await tool.execute?.(
      {
        credentialId: "cred-1",
        sinceMs: 1_700_000_000_000,
        toolCallDescription: "wait for login code",
      },
      executeOpts,
    );

    expect(result).toEqual({
      success: true,
      code: "424242",
      body: "Your code is 424242",
      fromPhoneNumber: "+15550001111",
      receivedAt: "2026-04-10T12:00:00.000Z",
      messageId: "msg-1",
    });
    expect(fetchMock).toHaveBeenCalledTimes(1);
    const url = String(fetchMock.mock.calls[0]?.[0]);
    expect(url).toContain("/agent/sms/messages?");
    expect(url).toContain("toPhoneNumber=%2B15551234567");
    expect(url).toContain("claim=1");
  });

  it("returns a lease conflict without retrying forever", async () => {
    vi.stubEnv("AGENT_API_URL", "https://api.example.com");
    vi.stubEnv("AGENT_API_TOKEN", "token");

    const fetchMock = vi.fn().mockResolvedValue({
      ok: false,
      status: 429,
      statusText: "Too Many Requests",
    });
    vi.stubGlobal("fetch", fetchMock);

    const tool = smsWaitForCode(makeCtx());
    const result = await tool.execute?.(
      {
        phoneNumber: "+15551234567",
        sinceMs: 1,
        toolCallDescription: "wait",
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

  it("keeps polling after a 409 already-consumed race, then claims the next message", async () => {
    vi.stubEnv("AGENT_API_URL", "https://api.example.com");
    vi.stubEnv("AGENT_API_TOKEN", "token");
    vi.useFakeTimers();

    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce({
        ok: false,
        status: 409,
        statusText: "Conflict",
      })
      .mockResolvedValueOnce(claimedResponse());
    vi.stubGlobal("fetch", fetchMock);

    const tool = smsWaitForCode(makeCtx());
    const pending = tool.execute?.(
      {
        phoneNumber: "+15551234567",
        sinceMs: 1,
        toolCallDescription: "wait",
      },
      executeOpts,
    );

    await vi.advanceTimersByTimeAsync(2_000);
    const result = await pending;

    expect(result).toMatchObject({ success: true, code: "424242" });
    expect(fetchMock).toHaveBeenCalledTimes(2);
  });

  it("releases the lease after timeout", async () => {
    vi.stubEnv("AGENT_API_URL", "https://api.example.com");
    vi.stubEnv("AGENT_API_TOKEN", "token");
    vi.useFakeTimers();

    const fetchMock = vi.fn().mockImplementation(async (url: string) => {
      if (String(url).includes("/agent/sms/lease/release")) {
        return {
          ok: true,
          status: 200,
          json: async () => ({ released: true }),
        };
      }
      return {
        ok: true,
        status: 200,
        json: async () => ({ claimed: null, messages: [] }),
      };
    });
    vi.stubGlobal("fetch", fetchMock);

    const tool = smsWaitForCode(makeCtx());
    const pending = tool.execute?.(
      {
        phoneNumber: "+15551234567",
        sinceMs: 1,
        toolCallDescription: "wait",
      },
      executeOpts,
    );

    await vi.advanceTimersByTimeAsync(95_000);
    const result = await pending;

    expect(result).toMatchObject({
      success: false,
      error: expect.stringContaining("Timed out after 90s"),
    });
    expect(
      fetchMock.mock.calls.some((call) =>
        String(call[0]).includes("/agent/sms/lease/release"),
      ),
    ).toBe(true);
  });
});
