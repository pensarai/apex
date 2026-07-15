import { tool } from "ai";
import { z } from "zod";
import {
  AgentRedTeamAttemptLedger,
  finalizeAgentRedTeamCampaign as finalizeCampaign,
} from "../../../agent-redteam";
import type { ToolContext } from "./types";

export function finalizeAgentRedTeamCampaign(ctx: ToolContext) {
  return tool({
    description:
      "Finalize an agent red-team campaign and report evaluated coverage plus explicit evidence gaps.",
    inputSchema: z.object({
      campaignId: z.string(),
      toolCallDescription: z.string(),
    }),
    execute: async ({ campaignId }) => {
      const ledger = new AgentRedTeamAttemptLedger(
        ctx.session.rootPath,
        campaignId,
      );
      const campaign = ledger.readCampaign();
      if (!campaign) {
        return {
          success: false,
          message: `Unknown agent red-team campaign: ${campaignId}`,
        };
      }
      const summary = finalizeCampaign({
        campaign,
        evaluations: ledger.readEvaluations(),
      });
      return {
        success: true,
        summary,
        message: `Finalized campaign ${campaignId}: ${summary.counts.vulnerable} vulnerable, ${summary.counts.resilient} resilient, ${summary.evidenceGaps.length} unobserved.`,
      };
    },
  });
}
