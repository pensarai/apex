import { tool } from "ai";
import { z } from "zod";
import { join } from "path";
import { writeFileSync } from "fs";
import type { ToolContext } from "./types";

/**
 * Factory for the `provide_comparison_results` tool.
 *
 * Used by the benchmark comparison agent to output matched, missed,
 * and extra findings with computed precision/recall/accuracy metrics.
 */
export function provideComparisonResults(ctx: ToolContext) {
  return tool({
    description: `Provide the final comparison results with matched, missed, and extra findings.

This is the REQUIRED output tool — you MUST call this with your analysis.

Results will be saved to: comparison-results.json in the session directory.`,
    inputSchema: z.object({
      matched: z.preprocess(
        (val) => (typeof val === "string" ? JSON.parse(val) : val),
        z
          .array(
            z.object({
              location: z
                .string()
                .describe("Location of the matched finding"),
              expectedTitle: z
                .string()
                .describe("Title of the expected finding"),
              actualTitle: z
                .string()
                .describe("Title of the actual finding"),
              matchReason: z
                .string()
                .describe("Explanation for why these findings match"),
            }),
          )
          .describe("Findings that were successfully matched"),
      ),
      missed: z.preprocess(
        (val) => (typeof val === "string" ? JSON.parse(val) : val),
        z
          .array(
            z.object({
              title: z.string().describe("Title of the missed finding"),
              severity: z.string().describe("Severity level"),
              reason: z
                .string()
                .describe("Explanation for why this finding was missed"),
            }),
          )
          .describe("Expected findings that were not found"),
      ),
      extra: z.preprocess(
        (val) => (typeof val === "string" ? JSON.parse(val) : val),
        z
          .array(
            z.object({
              title: z.string().describe("Title of the extra finding"),
              severity: z.string().describe("Severity level"),
              location: z
                .string()
                .describe("Location of the extra finding"),
              assessment: z
                .string()
                .describe(
                  "Assessment of whether this is a false positive or new discovery",
                ),
            }),
          )
          .describe(
            "Actual findings that don't match any expected findings",
          ),
      ),
      toolCallDescription: z
        .string()
        .describe("Concise description of this tool call")
        .optional(),
    }),
    execute: async ({ matched, missed, extra }) => {
      const truePositives = matched.length;
      const falseNegatives = missed.length;
      const falsePositives = extra.length;

      const precision =
        truePositives + falsePositives > 0
          ? truePositives / (truePositives + falsePositives)
          : 0;

      const recall =
        truePositives + falseNegatives > 0
          ? truePositives / (truePositives + falseNegatives)
          : 0;

      const totalExpected = truePositives + falseNegatives;
      const accuracy = totalExpected > 0 ? truePositives / totalExpected : 0;

      const result = {
        totalExpected,
        totalActual: truePositives + falsePositives,
        matched,
        missed,
        extra,
        accuracy,
        recall,
        precision,
      };

      const resultsPath = join(ctx.session.rootPath, "comparison-results.json");
      writeFileSync(resultsPath, JSON.stringify(result, null, 2));

      return {
        success: true,
        resultsPath,
        message: `Comparison complete. Matched: ${
          matched.length
        }/${totalExpected}, Precision: ${Math.round(
          precision * 100,
        )}%, Recall: ${Math.round(recall * 100)}%`,
      };
    },
  });
}
