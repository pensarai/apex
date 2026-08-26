/**
 * Tool: sms_list_messages
 *
 * Lists inbound Telnyx SMS on a workspace Mobile OTP number via the Console
 * Agent API. Exclusive number lease is acquired server-side on each list.
 * Console-only — AGENT_API_URL must be set (sandbox dispatch).
 */

import { tool } from "ai";
import { z } from "zod";
import type { SessionInfo } from "../../../session";
import type { ToolContext } from "./types";

export const SMS_LIST_MESSAGES_TOOL_NAME = "sms_list_messages" as const;

export const SMS_TOOL_NAMES = [SMS_LIST_MESSAGES_TOOL_NAME] as const;

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
      "sms_list_messages requires AGENT_API_URL and AGENT_API_TOKEN (Console sandbox dispatch). Local CLI without Console cannot read inbound SMS.",
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

export function smsListMessages(ctx: ToolContext) {
  return tool({
    description: `List inbound SMS on a Mobile OTP (sms-passwordless) receiving number.

This is a single read — it does not wait. After the target sends a code, sleep with execute_command (e.g. sleep 5) then call this tool. If the list is empty, sleep and list again, or stop and report what you observed. Do not hang in a wait loop.

Pass sinceMs as Date.now() from the send-code click so earlier messages are ignored. Set claim=true to consume the newest unconsumed message (exclusive; other runs cannot reuse that OTP). Fill the OTP with browser_fill from the returned code/body — do not report phone_verification as a barrier for this flow.

Requires a Console sandbox (AGENT_API_URL). Concurrent lists on the same shared number are exclusive; a 429 means another run holds the number.`,
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
      claim: z
        .boolean()
        .optional()
        .describe(
          "If true, consume the newest unconsumed message so other runs cannot reuse the OTP. Defaults to false (list only).",
        ),
      toolCallDescription: z
        .string()
        .describe(
          "A concise, human-readable description of what this tool call is doing",
        ),
    }),
    execute: async ({ credentialId, phoneNumber, sinceMs, claim }) => {
      const { base, token } = requireAgentApi();
      const toPhoneNumber = resolvePhoneNumber(ctx, {
        credentialId,
        phoneNumber,
      });
      const since = new Date(sinceMs).toISOString();

      const url = new URL(`${base}/agent/sms/messages`);
      url.searchParams.set("toPhoneNumber", toPhoneNumber);
      url.searchParams.set("since", since);
      if (claim) url.searchParams.set("claim", "1");

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
      if (res.status === 409) {
        return {
          success: false as const,
          error:
            "That SMS was already claimed. List without claim, or wait for a newer message.",
        };
      }
      if (!res.ok) {
        throw new Error(`SMS list API error ${res.status} ${res.statusText}`);
      }

      const data = (await res.json()) as SmsListResponse;
      return {
        success: true as const,
        messages: data.messages,
        claimed: data.claimed,
      };
    },
  });
}
