import { tool } from "ai";
import { z } from "zod";

export const REPORT_FAILURE_TOOL_NAME = "report_failure";

export const FailureTypeEnum = z.enum([
  "missing_credentials",
  "access_denied",
  "configuration_error",
  "manual_step_required",
  "rate_limited",
  "other",
]);

export const FailureReportSchema = z.object({
  reason: z.string().describe("Why testing cannot proceed"),
  failureType: FailureTypeEnum.describe("Category of the blocker"),
  objectiveIndex: z
    .number()
    .optional()
    .describe("Which objective hit the blocker, if specific to one"),
});

export type FailureReport = z.infer<typeof FailureReportSchema>;

/**
 * Creates the `report_failure` tool for pentest agents.
 *
 * When an agent hits an unrecoverable blocker (missing credentials,
 * unreachable target, manual step required), it calls this tool to
 * short-circuit the run. The tool acts as a stop condition — the
 * agent terminates immediately after calling it.
 *
 * @param onReport Callback invoked with the failure report before the agent stops.
 */
export function reportFailure(onReport: (report: FailureReport) => void) {
  return tool({
    description:
      "Report an unrecoverable blocker that prevents further testing. " +
      "Use this when you cannot proceed due to: missing credentials, target unreachable, " +
      "access denied, configuration error, rate limiting that cannot be waited out, or a " +
      "manual step that the agent cannot perform. This terminates the agent run early — " +
      "use it instead of the response tool when you are blocked, not when testing is complete.",
    inputSchema: z.object({
      response: FailureReportSchema,
    }),
    execute: async (input) => {
      onReport(input.response);
      return {
        success: true,
        message: "Failure report recorded. Agent run terminating.",
      };
    },
  });
}
