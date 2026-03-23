import { z } from "zod";

/**
 * Structured result returned by a CodeAgent that analyzes git diffs
 * to determine which endpoints need re-testing.
 *
 * Exported for use by Console — must be defined here with apex's Zod v3
 * to avoid v3/v4 schema incompatibility at runtime.
 */
export const EndpointSelectionResultSchema = z.object({
  runAll: z
    .boolean()
    .describe(
      "If true, all endpoints should be tested (e.g. global config change, too many indirect effects to determine scope).",
    ),
  affectedEndpointIds: z
    .array(z.string())
    .describe(
      "IDs of endpoints affected by the diff. Empty when runAll is true.",
    ),
  reasoning: z
    .string()
    .describe(
      "Brief explanation of how the affected endpoints were determined.",
    ),
});

export type EndpointSelectionResult = z.infer<
  typeof EndpointSelectionResultSchema
>;
