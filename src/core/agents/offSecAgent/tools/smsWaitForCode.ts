/**
 * Tool: sms_wait_for_code
 *
 * Polls the Console Agent API for an inbound Telnyx SMS on a workspace Mobile
 * OTP number, claims the first unconsumed message, and returns the body plus a
 * parsed OTP. Exclusive number lease is acquired server-side; this tool only
 * polls. Console-only — AGENT_API_URL must be set (sandbox dispatch).
 */

import { tool } from "ai";
import { z } from "zod";
import type { SessionInfo } from "../../../session";
import type { ToolContext } from "./types";

export const SMS_WAIT_FOR_CODE_TOOL_NAME = "sms_wait_for_code" as const;

export const SMS_TOOL_NAMES = [SMS_WAIT_FOR_CODE_TOOL_NAME] as const;

export const SMS_WAIT_TIMEOUT_MS = 90_000;
export const SMS_WAIT_POLL_MS = 2_000;

export function sessionHasSmsPasswordless(session: SessionInfo): boolean {
  const refs = session.credentialManager?.listReferences() ?? [];
  if (refs.some((ref) => ref.additionalFieldKeys?.includes("phoneNumber"))) {
    return true;
  }
  const creds = session.config?.authCredentials;
  const list = creds ? (Array.isArray(creds) ? creds : [creds]) : [];
  return list.some(
    (cred) =>
      Boolean(cred.additionalFields?.phoneNumber) ||
      cred.additionalFields?.authMethod === "sms-passwordless",
  );
}

function requireAgentApi(): { base: string; token: string } {
  const base = process.env.AGENT_API_URL;
  const token = process.env.AGENT_API_TOKEN;
  if (!base || !token) {
    throw new Error(
      "sms_wait_for_code requires AGENT_API_URL and AGENT_API_TOKEN (Console sandbox dispatch). Local CLI without Console cannot wait for inbound SMS.",
    );
  }
  return { base: base.replace(/\/+$/, ""), token };
}

function resolvePhoneNumber(
  ctx: ToolContext,
  input: { credentialId?: string; phoneNumber?: string },
): string {
  if (input.phoneNumber) return input.phoneNumber;

  const cm = ctx.credentialManager ?? ctx.session.credentialManager;
  if (input.credentialId) {
    const stored = cm?.resolve(input.credentialId);
    const phone = stored?.additionalFields?.phoneNumber;
    if (!phone) {
      throw new Error(
        `Credential ${input.credentialId} has no phoneNumber additional field`,
      );
    }
    return phone;
  }

  const refs = cm?.listReferences() ?? [];
  const smsRef = refs.find((ref) =>
    ref.additionalFieldKeys?.includes("phoneNumber"),
  );
  if (!smsRef) {
    throw new Error(
      "No sms-passwordless credential with a phoneNumber field is available",
    );
  }
  const stored = cm?.resolve(smsRef.id);
  const phone = stored?.additionalFields?.phoneNumber;
  if (!phone) {
    throw new Error(
      `Credential ${smsRef.id} has no phoneNumber additional field`,
    );
  }
  return phone;
}

async function sleep(ms: number, signal?: AbortSignal): Promise<void> {
  if (signal?.aborted) {
    throw signal.reason instanceof Error
      ? signal.reason
      : new Error("sms_wait_for_code aborted");
  }
  await new Promise<void>((resolve, reject) => {
    const timer = setTimeout(resolve, ms);
    const onAbort = () => {
      clearTimeout(timer);
      reject(
        signal?.reason instanceof Error
          ? signal.reason
          : new Error("sms_wait_for_code aborted"),
      );
    };
    signal?.addEventListener("abort", onAbort, { once: true });
  });
}

type SmsWireMessage = {
  id: string;
  fromPhoneNumber: string;
  toPhoneNumber: string;
  body: string;
  receivedAt: string;
  consumedAt: string | null;
  code: string | null;
};

type SmsListResponse = {
  messages: SmsWireMessage[];
  claimed: SmsWireMessage | null;
};

async function agentFetch(
  path: string,
  init: RequestInit & { token: string },
): Promise<Response> {
  const { token, ...rest } = init;
  // biome-ignore lint/style/noRestrictedGlobals: Agent API (not the pentest target); must not pass through targetFetch.
  return fetch(path, {
    ...rest,
    headers: {
      Authorization: `Bearer ${token}`,
      ...(rest.headers ?? {}),
    },
  });
}

async function releaseLease(
  base: string,
  token: string,
  toPhoneNumber: string,
): Promise<void> {
  const url = new URL(`${base}/agent/sms/lease/release`);
  url.searchParams.set("toPhoneNumber", toPhoneNumber);
  const res = await agentFetch(url.toString(), { method: "POST", token });
  if (!res.ok) {
    throw new Error(
      `SMS lease release failed: ${res.status} ${res.statusText}`,
    );
  }
}

export function smsWaitForCode(ctx: ToolContext) {
  return tool({
    description: `Wait for an inbound SMS one-time code on a Mobile OTP (sms-passwordless) credential.

Call this AFTER clicking the target's "send code" / "text me" control. Pass sinceMs as Date.now() from that click so earlier messages are ignored.

Returns the plaintext message body and a parsed numeric code when one is obvious. Fill the OTP with browser_fill — do not report phone_verification as a barrier for this flow.

Requires a Console sandbox (AGENT_API_URL). Concurrent waits on the same shared number are exclusive; a 429 means another run holds the number.`,
    inputSchema: z.object({
      credentialId: z
        .string()
        .optional()
        .describe(
          "Credential ID whose additionalFields.phoneNumber is the receiving number. Omit to use the session's sms-passwordless credential.",
        ),
      phoneNumber: z
        .string()
        .optional()
        .describe(
          "Explicit E.164 receiving number. Prefer credentialId so the number is resolved from the stored credential.",
        ),
      sinceMs: z
        .number()
        .describe(
          "Epoch milliseconds of the send-code click. Messages received before this timestamp are ignored.",
        ),
      toolCallDescription: z
        .string()
        .describe(
          "A concise, human-readable description of what this tool call is doing",
        ),
    }),
    execute: async ({ credentialId, phoneNumber, sinceMs }) => {
      const { base, token } = requireAgentApi();
      const toPhoneNumber = resolvePhoneNumber(ctx, {
        credentialId,
        phoneNumber,
      });
      const deadline = Date.now() + SMS_WAIT_TIMEOUT_MS;
      const since = new Date(sinceMs).toISOString();

      try {
        while (Date.now() < deadline) {
          const url = new URL(`${base}/agent/sms/messages`);
          url.searchParams.set("toPhoneNumber", toPhoneNumber);
          url.searchParams.set("since", since);
          url.searchParams.set("claim", "1");

          const res = await agentFetch(url.toString(), {
            method: "GET",
            token,
            signal: ctx.abortSignal,
          });

          if (res.status === 429) {
            return {
              success: false as const,
              error:
                "Another agent run holds the exclusive lease on this phone number. Wait and retry, or use a different Mobile OTP number.",
            };
          }
          if (res.status === 403) {
            return {
              success: false as const,
              error:
                "This phone number is not configured as a Mobile OTP credential in this workspace.",
            };
          }
          // Another waiter consumed this row; keep the lease and poll for the next message.
          if (res.status === 409) {
            await sleep(SMS_WAIT_POLL_MS, ctx.abortSignal);
            continue;
          }
          if (!res.ok) {
            throw new Error(
              `SMS wait API error ${res.status} ${res.statusText}`,
            );
          }

          const data = (await res.json()) as SmsListResponse;
          if (data.claimed) {
            return {
              success: true as const,
              code: data.claimed.code,
              body: data.claimed.body,
              fromPhoneNumber: data.claimed.fromPhoneNumber,
              receivedAt: data.claimed.receivedAt,
              messageId: data.claimed.id,
            };
          }

          await sleep(SMS_WAIT_POLL_MS, ctx.abortSignal);
        }

        await releaseLease(base, token, toPhoneNumber);
        return {
          success: false as const,
          error: `Timed out after ${SMS_WAIT_TIMEOUT_MS / 1000}s waiting for an inbound SMS to ${toPhoneNumber}`,
        };
      } catch (error: unknown) {
        await releaseLease(base, token, toPhoneNumber).catch(() => {
          // Lease TTL will expire; surface the original error.
        });
        if (error instanceof Error) {
          return { success: false as const, error: error.message };
        }
        return { success: false as const, error: String(error) };
      }
    },
  });
}
