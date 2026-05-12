import {
  type AIAuthConfig,
  type AIModel,
  generateObjectResponse,
} from "../../../ai";
import type {
  BountyReport,
  LiveVerificationResult,
  ProgramContext,
  ThreatModelAlignment,
} from "./types";
import { ThreatModelAlignmentSchema } from "./types";

const ALIGN_SYSTEM = `You are mapping an inbound, reproduced bug bounty finding onto an existing threat model and business-context document.

Given:
- The reproduced vulnerability (title, class, affected URL, reproduction evidence).
- The full threat model markdown (attacker profiles, attack paths, controls).
- Optional business-context markdown that may declare accepted risks.

Decide:
1. aligned — does this finding map onto a documented attack path (or an attacker profile + entry point combination)?
2. mappedThreats — list the attack-path titles or IDs (verbatim) that this finding corresponds to. Empty array if none.
3. businessAcceptedRisk — does either document explicitly declare this issue (or the affected behavior) an accepted risk? Be strict: vague statements like "we know about this" do NOT count. Look for explicit "accepted risk", "won't fix", or equivalent.
4. notes — one or two sentences explaining the mapping or its absence.

Be conservative on businessAcceptedRisk. Default to false unless the documents explicitly mark it accepted.`;

export async function alignWithThreatModel(opts: {
  report: BountyReport;
  verification: LiveVerificationResult;
  programContext: ProgramContext;
  model: AIModel;
  authConfig?: AIAuthConfig;
  abortSignal?: AbortSignal;
}): Promise<ThreatModelAlignment | null> {
  const { threatModel, businessContext } = opts.programContext;
  if (!threatModel) return null;

  const prompt = buildAlignmentPrompt(
    opts.report,
    opts.verification,
    threatModel,
    businessContext,
  );

  return generateObjectResponse({
    model: opts.model,
    schema: ThreatModelAlignmentSchema,
    system: ALIGN_SYSTEM,
    prompt,
    authConfig: opts.authConfig,
    abortSignal: opts.abortSignal,
  });
}

function buildAlignmentPrompt(
  report: BountyReport,
  verification: LiveVerificationResult,
  threatModel: string,
  businessContext: string | null,
): string {
  const sections: string[] = [
    "# Reproduced Finding",
    `Title: ${report.title}`,
    `Vulnerability class: ${report.vulnerabilityClass}`,
    `Affected URL: ${report.affectedUrl}`,
    `Attacker model: ${report.attackerModel}`,
    "",
    "## Description",
    report.description,
    "",
    "## Reproduction evidence",
    verification.evidence,
    "",
    "# Threat Model",
    threatModel,
    "",
  ];

  if (businessContext) {
    sections.push("# Business Context");
    sections.push(businessContext);
    sections.push("");
  }

  sections.push(
    "Map the finding onto the threat model and detect any explicit accepted risk.",
  );
  return sections.join("\n");
}
