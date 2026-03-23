import { tool } from "ai";
import { z } from "zod";
import { join } from "path";
import { writeFileSync } from "fs";
import type { ToolContext } from "./types";

/**
 * Factory for the `create_attack_surface_report` tool.
 *
 * Writes the final attack-surface report to the session directory
 * and fires persistence callbacks.
 */
export function createAttackSurfaceReport(ctx: ToolContext) {
  return tool({
    description:
      "Submit final attack surface results to orchestrator. Call at END of analysis with summary, assets, ALL targets with objectives, and key findings.",
    inputSchema: z.object({
      summary: z
        .object({
          totalAssets: z.number(),
          totalDomains: z.number(),
          analysisComplete: z.boolean(),
        })
        .describe("Summary statistics"),
      discoveredAssets: z
        .array(z.string())
        .describe(
          "List of discovered assets with descriptions. Format: 'example.com - Web server (nginx) - Ports 80,443'",
        ),
      targets: z
        .array(
          z.object({
            target: z.string().describe("Target URL, IP, or domain"),
            objective: z.string().describe("Pentest objective for this target"),
            rationale: z
              .string()
              .describe("Why this target needs deep testing"),
          }),
        )
        .describe("ALL targets for deep penetration testing"),
      keyFindings: z.preprocess(
        (val) => (Array.isArray(val) ? val : [val]),
        z
          .array(z.string())
          .describe(
            "Key findings from reconnaissance. Format: '[SEVERITY] Finding description'",
          ),
      ),
    }),
    execute: async (results) => {
      const resultsPath = join(
        ctx.session.rootPath,
        "attack-surface-results.json",
      );
      writeFileSync(resultsPath, JSON.stringify(results, null, 2));

      return {
        success: true,
        resultsPath,
        summary: results.summary,
        message: `Attack surface analysis complete. ${results.summary.totalAssets} assets identified for penetration testing.`,
      };
    },
  });
}
