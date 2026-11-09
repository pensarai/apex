import { tool } from "ai";
import { z } from "zod";
import type { ToolContext } from "./types";

export const RECORD_RUN_RESOURCE_TOOL_NAME = "record_run_resource" as const;

const KINDS = [
  "account",
  "record",
  "file",
  "configuration",
  "message",
  "other",
] as const;
const OPERATIONS = ["created", "modified", "deleted", "observed"] as const;
const ATTRIBUTIONS = ["created_by_run", "preexisting", "ambiguous"] as const;
const OUTCOMES = ["succeeded", "failed"] as const;

export const recordRunResourceInputSchema = z.object({
  kind: z.enum(KINDS).describe("What was touched on the target."),
  operation: z
    .enum(OPERATIONS)
    .describe(
      "created, modified, or deleted when this run changed it. observed when this run only saw it.",
    ),
  attribution: z
    .enum(ATTRIBUTIONS)
    .describe(
      "created_by_run only when you performed the operation. preexisting only for a resource that already existed (operation must be observed). ambiguous when you cannot tell. Never choose from a similar name.",
    ),
  outcome: z
    .enum(OUTCOMES)
    .describe(
      "succeeded if the operation completed. failed if the attempt did not.",
    ),
  label: z
    .string()
    .describe(
      "Short name a person can recognize, such as an email or record title. Do not include a password, token, or cookie.",
    ),
  stableId: z
    .string()
    .optional()
    .describe("Stable id on the target, when the response included one."),
  locator: z
    .string()
    .optional()
    .describe("Path or URL of the resource, without secret query parameters."),
  target: z
    .string()
    .optional()
    .describe("Host or application the resource belongs to."),
  detail: z
    .record(z.string(), z.union([z.string(), z.number(), z.boolean()]))
    .optional()
    .describe(
      "Extra non-secret facts. Omit passwords, tokens, cookies, and authorization headers.",
    ),
  toolCallDescription: z
    .string()
    .describe("A concise description of the resource change, shown in the UI."),
});

type RecordInput = z.infer<typeof recordRunResourceInputSchema>;

export function buildRunResourceCall(
  input: RecordInput,
  ctx: { sessionId?: string; toolCallId?: string },
): { method: string; args: [Record<string, unknown>] } {
  const { toolCallDescription: _shown, ...resource } = input;
  return {
    method: "runResources.record",
    args: [
      {
        ...resource,
        sessionId: ctx.sessionId,
        toolCallId: ctx.toolCallId,
      },
    ],
  };
}

/**
 * Record one customer-side resource this run created, changed, deleted, or
 * only observed. The Console stores the catalog; this tool does not delete it.
 */
export function recordRunResource(ctx: ToolContext) {
  return tool({
    description: `Record a customer-side account or artifact this run created, modified, deleted, or only observed.

Call this in the same turn as the change. attribution is required:
- created_by_run: you performed the operation and can point at the request that did it. Not valid for operation observed.
- preexisting: the resource already existed. operation must be observed.
- ambiguous: you cannot tell. Do not guess from a similar name.

Do not include passwords, tokens, cookies, or other secrets. A failed attempt is still recorded with outcome failed. This tool does not delete the resource.`,
    inputSchema: recordRunResourceInputSchema,
    execute: async (input, options) => {
      const base = process.env.AGENT_API_URL?.replace(/\/+$/, "");
      const token = process.env.AGENT_API_TOKEN;
      if (!base || !token) {
        return {
          success: false,
          message:
            "record_run_resource requires a Console sandbox (AGENT_API_URL). The change was not catalogued.",
        };
      }
      const body = buildRunResourceCall(input, {
        sessionId: ctx.subagentId ?? ctx.session.id,
        toolCallId: options.toolCallId,
      });
      // biome-ignore lint/style/noRestrictedGlobals: Agent API, not the pentest target.
      const response = await fetch(`${base}/agent/call`, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          authorization: `Bearer ${token}`,
        },
        body: JSON.stringify(body),
        signal: ctx.abortSignal,
      });
      const text = await response.text();
      if (!response.ok) {
        return {
          success: false,
          message: `record_run_resource was not saved (${response.status}).`,
        };
      }
      let id: string | undefined;
      try {
        const parsed = JSON.parse(text) as { result?: { id?: string } };
        id = parsed.result?.id;
      } catch {
        return {
          success: false,
          message: "record_run_resource returned an unreadable response.",
        };
      }
      return {
        success: true,
        id,
        message:
          "Recorded. The customer catalog does not store secrets and does not delete the resource.",
      };
    },
  });
}
