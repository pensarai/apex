import { tool } from "ai";
import { z } from "zod";

export const REPORT_ERROR_TOOL_NAME = "report_error" as const;

/** Coarse classification of why the agent cannot proceed. */
export const ReportErrorReasonSchema = z.enum([
  "authentication_failed",
  "target_unreachable",
  "blocked",
  "other",
]);

export type ReportedError = {
  reason: z.infer<typeof ReportErrorReasonSchema>;
  message: string;
};

/**
 * Terminal "I cannot proceed" tool. Mirrors the `response` tool — calling it
 * ends the run (pair with `hasToolCall(REPORT_ERROR_TOOL_NAME)`) — but instead
 * of a successful result it surfaces a blocking error so the caller can turn
 * the run into a failure (e.g. mark a scan endpoint failed with this message).
 */
export function createReportErrorTool(onError: (error: ReportedError) => void) {
  return tool({
    description: `Report a blocking error that prevents you from completing the pentest, and END your run.

Call this ONLY when you genuinely cannot continue, for example:
- You cannot authenticate to the target with the available credentials.
- The target is unreachable or responds in a way that makes testing impossible.
- Some other runtime condition blocks you from carrying out the objectives.

Do NOT use this for vulnerabilities (use document_vulnerability) or for normal completion (use response). Provide a clear, specific message describing exactly what blocked you — include the failing URL, status codes, or the auth step that failed where relevant — so it can be surfaced to the operator.`,
    inputSchema: z.object({
      reason: ReportErrorReasonSchema.describe(
        "Coarse category of the blocking error.",
      ),
      message: z
        .string()
        .min(1)
        .describe(
          "Clear, specific explanation of what blocked you (the failing URL, status codes, or auth step where relevant).",
        ),
    }),
    execute: async ({ reason, message }) => {
      onError({ reason, message });
      return {
        success: true,
        message: "Blocking error reported. Ending run.",
      };
    },
  });
}

/** Error thrown by an agent run that called {@link REPORT_ERROR_TOOL_NAME}. */
export class PentestReportedError extends Error {
  readonly reason: ReportedError["reason"];

  constructor(error: ReportedError) {
    super(error.message);
    this.name = "PentestReportedError";
    this.reason = error.reason;
  }
}
