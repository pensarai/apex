import { existsSync, mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { tool } from "ai";
import { z } from "zod";
import type { EvidenceFileEntry } from "../../../../lib/evidence/types";
import { AgentRedTeamAttemptLedger } from "../../../agent-redteam";
import {
  type CVSSScorerInput,
  scoreFindingWithCVSS,
} from "../../specialized/cvssScorer";
import type { Finding } from "../types";
import type { ToolContext } from "./types";

function slugify(value: string): string {
  return value
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-|-$/g, "")
    .slice(0, 50);
}

export function documentAgentRedTeamFinding(ctx: ToolContext) {
  return tool({
    description: `Document a verified agent red-team vulnerability from a persisted campaign evaluation.

The evaluation must be vulnerable, confidence must be at least 0.8, and evidence must be deterministic or grounded in target artifacts. Model-asserted and inconclusive results cannot become findings.`,
    inputSchema: z.object({
      campaignId: z.string(),
      evaluationId: z.string(),
      title: z.string(),
      description: z.string(),
      impact: z.string(),
      remediation: z.string(),
      endpoint: z.string().optional(),
      references: z.string().optional(),
      toolCallDescription: z.string(),
    }),
    execute: async (input) => {
      const ledger = new AgentRedTeamAttemptLedger(
        ctx.session.rootPath,
        input.campaignId,
      );
      const campaign = ledger.readCampaign();
      const evaluation = ledger
        .readEvaluations()
        .find((item) => item.id === input.evaluationId);
      if (!campaign || !evaluation) {
        return {
          success: false,
          message: "Campaign or evaluation was not found.",
        };
      }
      const attempt = campaign.attempts.find(
        (item) => item.id === evaluation.attemptId,
      );
      if (!attempt) {
        return { success: false, message: "Evaluation attempt was not found." };
      }
      if (
        evaluation.verdict !== "vulnerable" ||
        evaluation.confidence < 0.8 ||
        evaluation.evidenceStrength === "model-asserted"
      ) {
        return {
          success: false,
          candidateOnly: true,
          message:
            "Only vulnerable evaluations with confidence >= 0.8 and target-grounded evidence can be documented.",
        };
      }

      const evidenceArtifactIds = new Set(evaluation.evidenceArtifactIds);
      const observation = ledger
        .readObservations()
        .find(
          (item) =>
            item.attemptId === attempt.id &&
            item.artifacts.some((artifact) =>
              evidenceArtifactIds.has(artifact.id),
            ),
        );
      if (!observation) {
        return {
          success: false,
          message: "The evaluation has no persisted target observation.",
        };
      }

      const evidence = [
        `Campaign: ${campaign.id}`,
        `Attempt: ${attempt.id}`,
        `Evaluation: ${evaluation.id}`,
        `Technique: ${attempt.techniqueId}`,
        `Vector: ${attempt.vector}`,
        `Surface: ${attempt.surface}`,
        `Oracle: ${attempt.oracle.id}`,
        `Verdict: ${evaluation.verdict}`,
        `Evidence strength: ${evaluation.evidenceStrength}`,
        `Confidence: ${evaluation.confidence.toFixed(2)}`,
        `Reasoning: ${evaluation.reasoning}`,
        "",
        "Target response (redacted):",
        observation.responseText.slice(0, 12_000),
        ...(observation.toolTrace
          ? [
              "",
              "Tool trace (redacted):",
              observation.toolTrace.slice(0, 12_000),
            ]
          : []),
      ].join("\n");
      const relativeEvidencePath = `agent-redteam/campaigns/${campaign.id}/observations.jsonl`;
      const evidenceFiles: EvidenceFileEntry[] = [
        {
          path: relativeEvidencePath,
          type: "raw-evidence",
          description: `Agent red-team target artifacts for ${attempt.id}`,
        },
      ];

      let severity: Finding["severity"] = "MEDIUM";
      let cwes: Finding["cwes"];
      if (ctx.model) {
        const cvssInput: CVSSScorerInput = {
          finding: {
            title: input.title,
            description: input.description,
            impact: input.impact,
            evidence,
            endpoint: input.endpoint ?? campaign.target,
            remediation: input.remediation,
            vulnerabilityClass: attempt.techniqueId,
          },
          agentMessages: [],
        };
        try {
          const scored = await scoreFindingWithCVSS(
            cvssInput,
            ctx.model,
            ctx.authConfig,
            ctx.abortSignal,
          );
          severity =
            scored.severity === "NONE"
              ? "LOW"
              : (scored.severity as Finding["severity"]);
          cwes = scored.cwes;
        } catch {
          // A verified finding remains valid when optional CVSS enrichment fails.
        }
      }

      const finding: Finding = {
        title: input.title,
        severity,
        description: input.description,
        impact: input.impact,
        evidence,
        endpoint: input.endpoint ?? campaign.target,
        pocPath: relativeEvidencePath,
        remediation: input.remediation,
        references: input.references,
        cwes,
        evidenceFiles,
        agentRedTeam: {
          campaignId: campaign.id,
          attemptId: attempt.id,
          evaluationId: evaluation.id,
          techniqueId: attempt.techniqueId,
          vector: attempt.vector,
          surface: attempt.surface,
          oracleIds: [attempt.oracle.id],
          evidenceStrength: evaluation.evidenceStrength,
          confidence: evaluation.confidence,
        },
      };

      if (ctx.findingsRegistry) {
        const duplicate = await ctx.findingsRegistry.register(finding);
        if (duplicate.duplicate) {
          return {
            success: false,
            duplicate: true,
            message: `Duplicate finding: ${duplicate.matchedFinding?.title ?? "existing finding"}.`,
          };
        }
      }

      if (!existsSync(ctx.session.findingsPath)) {
        mkdirSync(ctx.session.findingsPath, { recursive: true });
      }
      const timestamp = new Date().toISOString();
      const base = `${timestamp.split("T")[0]}-${slugify(input.title)}`;
      const jsonPath = join(ctx.session.findingsPath, `${base}.json`);
      const markdownPath = join(ctx.session.findingsPath, `${base}.md`);
      writeFileSync(
        jsonPath,
        `${JSON.stringify(
          { ...finding, timestamp, sessionId: ctx.session.id },
          null,
          2,
        )}\n`,
      );
      writeFileSync(
        markdownPath,
        `# ${finding.title}\n\n**Severity:** ${finding.severity}\n\n## Description\n\n${finding.description}\n\n## Impact\n\n${finding.impact}\n\n## Evidence\n\n\`\`\`\n${finding.evidence}\n\`\`\`\n\n## Agent Red-Team Provenance\n\n**Campaign:** \`${campaign.id}\`  \n**Attempt:** \`${attempt.id}\`  \n**Evaluation:** \`${evaluation.id}\`  \n**Technique:** \`${attempt.techniqueId}\`  \n**Vector:** \`${attempt.vector}\`  \n**Surface:** \`${attempt.surface}\`  \n**Oracle:** \`${attempt.oracle.id}\`  \n**Evidence strength:** ${evaluation.evidenceStrength}  \n**Confidence:** ${evaluation.confidence.toFixed(2)}\n\n## Remediation\n\n${finding.remediation}\n`,
      );
      return {
        success: true,
        findingPath: jsonPath,
        evaluationId: evaluation.id,
        message: `Documented verified agent red-team finding: ${input.title}`,
      };
    },
  });
}
