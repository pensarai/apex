import { tool } from "ai";
import { z } from "zod";
import { analyzeBugBountyListing } from "../../../bugBounty/analyze";
import { compileEngagementPolicy } from "../../../bugBounty/policy";
import type { ToolContext } from "./types";

export function runBugBountyWorkflow(ctx: ToolContext) {
  return tool({
    description: `Re-fetch an approved bug bounty listing and run the bounded autonomous workflow.

The caller must pass the exact policy hash shown during preflight. The listing
is re-fetched and execution is rejected if its content or compiled policy has
changed. This is the only tool the bug-bounty skill should use to start target
traffic after human approval.`,
    inputSchema: z.object({
      listingUrl: z.string().url(),
      approvedPolicyHash: z
        .string()
        .regex(/^[a-f0-9]{64}$/)
        .describe("Policy hash explicitly approved by the human reviewer"),
      maxTargets: z.number().int().positive().max(100).optional(),
      toolCallDescription: z.string(),
    }),
    execute: async ({ listingUrl, approvedPolicyHash, maxTargets }) => {
      if (!ctx.model) {
        return {
          success: false,
          message:
            "run_bug_bounty_workflow requires a model in the tool context.",
        };
      }
      try {
        const brief = await analyzeBugBountyListing({
          listingUrl,
          abortSignal: ctx.abortSignal,
        });
        const policy = compileEngagementPolicy(brief, {
          configuredHeaders: ctx.session.config?.headers,
        });
        if (policy.policyHash !== approvedPolicyHash) {
          return {
            success: false,
            staleApproval: true,
            currentPolicyHash: policy.policyHash,
            message:
              "The bounty listing or effective policy changed after approval. Run preflight again and obtain a new approval.",
          };
        }
        if (!policy.canExecute) {
          return {
            success: false,
            blockers: policy.blockers,
            message: "The approved preflight is not executable.",
          };
        }
        const { runBugBountyWorkflow: runWorkflow } = await import(
          "../../../bugBounty/workflow"
        );
        const result = await runWorkflow({
          policy,
          model: ctx.model,
          session: ctx.session,
          authConfig: ctx.authConfig,
          abortSignal: ctx.abortSignal,
          eventBus: ctx.eventBus,
          maxTargets,
        });
        return {
          success: true,
          policyHash: result.policyHash,
          totalFindings: result.findings.length,
          findingsBySeverity: summarizeFindings(result.findings),
          targets: result.targets.map((target) => ({
            target: target.target,
            status: target.status,
            sessionId: target.sessionId,
            reportPath: target.reportPath,
            findings: target.findings.length,
            reason: target.reason,
          })),
          skippedTargets: result.skippedTargets,
          message: `Bug bounty run completed with ${result.findings.length} validated findings.`,
        };
      } catch (error) {
        if (error instanceof Error && error.name === "AbortError") {
          return { success: false, message: "Bug bounty run was cancelled." };
        }
        return {
          success: false,
          message: error instanceof Error ? error.message : String(error),
        };
      }
    },
  });
}

function summarizeFindings(
  findings: Array<{ severity?: string }>,
): Record<string, number> {
  const counts: Record<string, number> = {};
  for (const finding of findings) {
    const severity = (finding.severity ?? "unknown").toLowerCase();
    counts[severity] = (counts[severity] ?? 0) + 1;
  }
  return counts;
}
