/**
 * Tool: sms_list_messages
 *
 * Reserves or lists inbound SMS on a stage-managed Mobile OTP number via the
 * Console Agent API. Number selection and leasing are server-side.
 * Console-only — AGENT_API_URL must be set (sandbox dispatch).
 */

import { tool } from "ai";
import { z } from "zod";
import type { SessionInfo } from "../../../session";
import type { ToolContext } from "./types";

export const SMS_LIST_MESSAGES_TOOL_NAME = "sms_list_messages" as const;

export const SMS_TOOL_NAMES = [SMS_LIST_MESSAGES_TOOL_NAME] as const;

function hasPhoneNumberAuthCredential(session: SessionInfo): boolean {
  const creds = session.config?.authCredentials;
  const list = creds ? (Array.isArray(creds) ? creds : [creds]) : [];
  return list.some((cred) => Boolean(cred.additionalFields?.phoneNumber));
}

export function sessionHasSmsPasswordless(session: SessionInfo): boolean {
  const refs = session.credentialManager?.listReferences() ?? [];
  if (refs.some((ref) => ref.additionalFieldKeys?.includes("phoneNumber"))) {
    return true;
  }
  return hasPhoneNumberAuthCredential(session);
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
    description: `Reserve or list inbound SMS on the stage-managed Mobile OTP (sms-passwordless) receiving number.

Reserve immediately before filling the target phone field and clicking send-code: call with reserve=true. The Console chooses and leases the receiving number from the signed session; never supply or request a phone number here.

After the target sends a code, sleep with execute_command (e.g. sleep 5), then call with sinceMs from the send-code click. Set claim=true to consume the newest unconsumed message (exclusive; other runs cannot reuse that OTP). This is a single request — it does not wait. A 429 means the shared number is busy; retry the reservation later rather than waiting in this tool.

Requires a Console sandbox (AGENT_API_URL).`,
    inputSchema: z
      .object({
        reserve: z
          .boolean()
          .optional()
          .describe(
            "Reserve the session-bound shared number before requesting a code. Cannot be combined with sinceMs or claim.",
          ),
        sinceMs: z
          .number()
          .optional()
          .describe(
            "Epoch milliseconds of the send-code click. Required unless reserving; messages received before this timestamp are ignored.",
          ),
        claim: z
          .boolean()
          .optional()
          .describe(
            "Consume the newest unconsumed message so other runs cannot reuse the OTP. Defaults to false (list only).",
          ),
        toolCallDescription: z
          .string()
          .describe(
            "A concise, human-readable description of what this tool call is doing",
          ),
      })
      .strict()
      .superRefine((input, refinementCtx) => {
        if (input.reserve) {
          if (input.sinceMs !== undefined || input.claim !== undefined) {
            refinementCtx.addIssue({
              code: "custom",
              message: "reserve=true cannot be combined with sinceMs or claim",
            });
          }
          return;
        }
        if (input.sinceMs === undefined) {
          refinementCtx.addIssue({
            code: "custom",
            path: ["sinceMs"],
            message: "sinceMs is required when listing SMS messages",
          });
        }
      }),
    execute: async ({ reserve, sinceMs, claim }) => {
      const { base, token } = requireAgentApi();

      const url = new URL(`${base}/agent/sms/messages`);
      if (reserve) {
        url.searchParams.set("reserve", "1");
      } else {
        if (sinceMs === undefined) {
          throw new Error("sms_list_messages requires sinceMs when listing");
        }
        url.searchParams.set("since", new Date(sinceMs).toISOString());
        if (claim) url.searchParams.set("claim", "1");
      }

      const res = await agentFetch(url.toString(), {
        method: "GET",
        token,
        signal: ctx.abortSignal,
      });

      if (res.status === 429) {
        return {
          success: false as const,
          error:
            "The shared Mobile OTP number is busy. Retry the reservation later; this tool does not wait.",
        };
      }
      if (res.status === 403) {
        return {
          success: false as const,
          error:
            "No Mobile OTP receiving number is configured for this session.",
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
