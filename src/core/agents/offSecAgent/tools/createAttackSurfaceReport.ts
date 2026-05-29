import { tool } from "ai";
import { writeFileSync } from "node:fs";
import { join } from "node:path";
import { z } from "zod";
import type { ToolContext } from "./types";

/**
 * Factory for the `create_attack_surface_report` tool.
 *
 * Writes the final attack-surface report to the session directory
 * and fires persistence callbacks.
 */
export function createAttackSurfaceReport(ctx: ToolContext) {
  return tool({
    description: `Provide attack surface analysis results to the orchestrator agent.

Call this at the END of your analysis with:
- Summary statistics
- Discovered assets (simple list)
- ALL targets for deep testing with objectives. Do not prioritize any targets, optimize for breadth of testing.
- Key findings`,
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
      toolCallDescription: z
        .string()
        .describe(
          "A concise, human-readable description of what this tool call is doing",
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
