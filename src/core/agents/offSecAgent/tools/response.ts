import { tool } from "ai";
import { z } from "zod";

export const RESPONSE_TOOL_NAME = "response" as const;

export type ResponseGuardContext = { rejectionCount: number };
export type ResponseGuardDecision = string | { message: string } | undefined;
export type ResponseGuard = (
  result: unknown,
  context: ResponseGuardContext,
) => ResponseGuardDecision | Promise<ResponseGuardDecision>;

/**
 * Create a structured response tool that captures the agent's final output.
 *
 * When the agent calls this tool, `onResult` fires with the validated
 * response data. Pair with `hasToolCall("response")` as a stop condition
 * to end the agent run and extract the result.
 */
export function createResponseTool(
  responseSchema: z.ZodSchema,
  onResult: (result: unknown) => void,
  guard?: ResponseGuard,
) {
  let rejectionCount = 0;
  return tool({
    description: `Submit your final structured response. Call this ONCE when you have completed your task and assembled all results. This ends your run — make sure all data is included.`,
    inputSchema: z.object({
      result: responseSchema,
    }),
    execute: async ({ result }) => {
      const rejection = await guard?.(result, { rejectionCount });
      if (rejection) {
        rejectionCount += 1;
        return {
          success: false,
          responseRejected: true,
          rejectionCount,
          message:
            typeof rejection === "string" ? rejection : rejection.message,
        };
      }
      onResult(result);
      return {
        success: true,
        responseAccepted: true,
        message: "Response submitted.",
      };
    },
  });
}
