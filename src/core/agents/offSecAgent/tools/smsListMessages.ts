/**
 * Tool: sms_list_messages
 *
 * Reserves or lists inbound SMS on a stage-managed Mobile OTP number. Number
 * selection and leasing belong to the host, reached through the `SmsInbox`
 * seam: the default talks to the Console Agent API and needs sandbox dispatch
 * (AGENT_API_URL), while a host with direct database access injects its own.
 */

import { tool } from "ai";
import { z } from "zod";
import type { SessionInfo } from "../../../session";
import { HttpSmsInbox, type SmsInboxRefusal } from "./smsInbox";
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

const REFUSALS: Record<SmsInboxRefusal, string> = {
  "lease-held":
    "The shared Mobile OTP number is busy. Retry the reservation later; this tool does not wait.",
  "not-configured":
    "No Mobile OTP receiving number is configured for this session.",
  "already-claimed":
    "That SMS was already claimed. List without claim, or wait for a newer message.",
};

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
          .optional()
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
      const inbox = ctx.smsInbox ?? new HttpSmsInbox();

      if (reserve) {
        const reserved = await inbox.reserve(ctx.abortSignal);
        if (!reserved.ok) {
          return { success: false as const, error: REFUSALS[reserved.reason] };
        }
        return { success: true as const, messages: [], claimed: null };
      }

      if (sinceMs === undefined) {
        throw new Error("sms_list_messages requires sinceMs when listing");
      }
      const listed = await inbox.list({ sinceMs, claim }, ctx.abortSignal);
      if (!listed.ok) {
        return { success: false as const, error: REFUSALS[listed.reason] };
      }
      return {
        success: true as const,
        messages: listed.messages,
        claimed: listed.claimed,
      };
    },
  });
}
