import { tool } from "ai";
import { z } from "zod";

export const RESPONSE_TOOL_NAME = "response" as const;

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
) {
  return tool({
    description: `Submit your final structured response. Call this ONCE when you have completed your task and assembled all results. This ends your run — make sure all data is included.`,
    inputSchema: z.object({
      result: responseSchema,
    }),
    execute: async ({ result }) => {
      onResult(result);
      return { success: true, message: "Response submitted." };
    },
  });
}
