import { tool } from "ai";
import { z } from "zod";
import type { ToolContext } from "./types";
import { generatePentestReport } from "../../agents/legacy/reportGeneratorAgent";

/**
 * Factory for the `generate_report` tool.
 *
 * Wraps the existing report generator to produce a full markdown
 * pentest report from all findings in the session directory.
 */
export function generateReport(ctx: ToolContext) {
  return tool({
    description: `Generate a comprehensive penetration testing report from all documented findings.

Call this at the END of a penetration test to produce a full markdown report including:
- Executive summary with risk assessment
- Findings summary with severity breakdown
- Detailed findings with evidence and remediation
- CVSS 4.0 scores (if available)
- Recommendations prioritised by severity
- Appendix with POC scripts and session info

The report is written to the session directory as pentest-report.md.`,
    inputSchema: z.object({
      reportTitle: z
        .string()
        .optional()
        .describe("Custom report title (default: 'Penetration Test Report')"),
      includeMethodology: z
        .boolean()
        .default(true)
        .describe("Include methodology section in report"),
      toolCallDescription: z
        .string()
        .describe(
          "A concise, human-readable description of what this tool call is doing",
        ),
    }),
    execute: async (params) => {
      try {
        const result = await generatePentestReport({
          sessionRootPath: ctx.session.rootPath,
          sessionId: ctx.session.id,
          target: ctx.session.targets[0] || "unknown",
          reportTitle: params.reportTitle,
          includeMethodology: params.includeMethodology,
        });

        if (result.success) {
          return {
            success: true,
            reportPath: result.reportPath,
            findingsCount: result.findingsCount,
            message: `Report generated successfully at ${result.reportPath}. Total findings: ${result.findingsCount.total} (${result.findingsCount.critical} critical, ${result.findingsCount.high} high, ${result.findingsCount.medium} medium, ${result.findingsCount.low} low)`,
          };
        }

        return {
          success: false,
          message: `Report generation failed: ${result.error}`,
        };
      } catch (error: unknown) {
        const errorMessage =
          error instanceof Error ? error.message : String(error);
        return {
          success: false,
          message: `Report generation error: ${errorMessage}`,
        };
      }
    },
  });
}
