import { mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { tool } from "ai";
import { z } from "zod";
import { calculateCVSS4Score } from "../../../../lib/cvss";
import type { EvidenceFileEntry } from "../../../../lib/evidence/types";
import {
  type CVSSScorerResult,
  scoreFindingWithCVSS,
} from "../../specialized/cvssScorer";
import { judgeFinding } from "../../specialized/findingJudge";
import type { Finding } from "../types";
import type { ToolContext } from "./types";

const FALLBACK_CVSS: CVSSScorerResult = {
  score: 5.0,
  severity: "MEDIUM",
  vectorString:
    "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N",
  metrics: {
    AV: "N",
    AC: "L",
    AT: "N",
    PR: "N",
    UI: "N",
    VC: "L",
    VI: "L",
    VA: "N",
    SC: "N",
    SI: "N",
    SA: "N",
    E: "A",
  },
  scoreType: "CVSS-BT",
  reasoning: "CVSS scoring unavailable — using conservative MEDIUM default.",
  cwes: [],
};

const CALLBACK_SIGNAL = "canary-callback";

/**
 * Proof-aware UI guardrail. A `canary-token-echo` proves the agent *emitted* the
 * attacker URL / secret into its output — NOT that any client fetched it. So a
 * zero-interaction (UI:N) data-egress claim is unproven unless an actual
 * outbound `canary-callback` fired. When only an echo was observed, clamp
 * UI:N → UI:P (delivery requires the response to be rendered/clicked) and
 * recompute the score. UI:N is reserved for confirmed callbacks. Idempotent:
 * a no-op when a callback fired or UI is already P/A.
 */
function clampUiForProof(
  cvss: CVSSScorerResult,
  signals: string[],
): CVSSScorerResult {
  const hasCallback = signals.some((s) =>
    s.toLowerCase().includes(CALLBACK_SIGNAL),
  );
  if (hasCallback || cvss.metrics.UI !== "N") return cvss;

  const metrics = { ...cvss.metrics, UI: "P" as const };
  const recalced = calculateCVSS4Score(metrics);
  return {
    ...cvss,
    score: recalced.score,
    severity: recalced.severity,
    vectorString: recalced.vectorString,
    metrics: recalced.metrics,
    reasoning: `${cvss.reasoning} [Guardrail: UI:N→UI:P — only canary-token-echo was observed (agent emitted the URL/secret), not an outbound canary-callback, so zero-interaction delivery is unproven; exfiltration requires the response to be rendered or clicked.]`,
  };
}

function slugify(str: string, maxLen: number): string {
  return str
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-|-$/g, "")
    .substring(0, maxLen);
}

export const documentAgenticFindingInputSchema = z.object({
  title: z
    .string()
    .describe(
      "Finding title (include the class, e.g. 'Indirect prompt injection: ...')",
    ),
  description: z.string().describe("Detailed description of the finding"),
  impact: z.string().describe("Potential impact if exploited"),
  endpoint: z
    .string()
    .describe(
      "The agent endpoint label (e.g. agent://host or agent://host/<channel>)",
    ),
  remediation: z.string().describe("Steps to fix the issue"),
  vulnerabilityClass: z
    .string()
    .describe(
      "Agentic class: prompt-injection | indirect-prompt-injection | tool-abuse | data-exfiltration | agent-handoff",
    ),
  agentTranscript: z
    .string()
    .describe(
      "The conversation transcript proving the exploit (from probe_agent)",
    ),
  canarySignals: z
    .array(z.string())
    .describe("Observed signals (e.g. canary-callback, canary-token-echo)"),
  materiality: z.object({
    exploitPath: z
      .string()
      .describe("Concrete exploit path confirmed by the transcript"),
    securityImpact: z.string().describe("Material security impact"),
    affectedAssetOrAbusePath: z
      .string()
      .describe("Asset / privileged action / abuse path affected"),
    falsePositiveRationale: z
      .string()
      .describe(
        "Why this is not a refusal / incidental URL mention / unobeyed injection",
      ),
  }),
  references: z.string().optional().describe("CWE / related references"),
  toolCallDescription: z
    .string()
    .describe("Concise description of this tool call"),
});

export type DocumentAgenticFindingInput = z.infer<
  typeof documentAgenticFindingInputSchema
>;

function formatEvidence(input: DocumentAgenticFindingInput): string {
  return [
    `Signals: ${input.canarySignals.join(", ") || "(none)"}`,
    "",
    "Materiality:",
    `- Exploit path: ${input.materiality.exploitPath}`,
    `- Security impact: ${input.materiality.securityImpact}`,
    `- Affected asset or abuse path: ${input.materiality.affectedAssetOrAbusePath}`,
    `- False-positive rationale: ${input.materiality.falsePositiveRationale}`,
  ].join("\n");
}

/**
 * Document a CONFIRMED agentic (AI agent / LLM app) exploit proven by a canary
 * callback / transcript signal — the no-executable-POC sibling of
 * `document_vulnerability`. Reuses the same FindingJudge (canary mode),
 * cvssScorer, FindingsRegistry, and report so agentic findings are first-class.
 */
export function documentAgenticFinding(ctx: ToolContext) {
  const { session } = ctx;

  return tool({
    description: `Document a CONFIRMED AI-agent vulnerability proven by a canary signal (no executable POC).

Call this ONLY after probe_agent reported a signal (canary-callback or canary-token-echo) — or the agent verbatim revealed a planted secret. Provide the transcript and the observed signals; an automated judge validates the transcript + signals, then the finding is CVSS-scored, deduplicated, and persisted like any other finding.

Do NOT call this for: refusals, incidental URL mentions, unobeyed injections, or anything probe_agent did not confirm with a signal.`,
    inputSchema: documentAgenticFindingInputSchema,
    execute: async (input) => {
      try {
        const evidence = formatEvidence(input);

        // Early dedup
        if (ctx.findingsRegistry) {
          const quick = ctx.findingsRegistry.isDuplicate({
            title: input.title,
            description: input.description,
            endpoint: input.endpoint,
            severity: "MEDIUM",
            impact: input.impact,
            evidence,
            pocPath: "",
            remediation: input.remediation,
            vulnerabilityClass: input.vulnerabilityClass,
          });
          if (quick.duplicate) {
            return {
              success: false,
              duplicate: true,
              matchType: quick.matchType,
              matchedFinding: quick.matchedFinding?.title ?? "unknown",
              message: `Duplicate finding (${quick.matchType}). Skipping.`,
            };
          }
        }

        const timestamp = new Date().toISOString();
        const findingId = `${timestamp.split("T")[0]}-${slugify(`${input.vulnerabilityClass}-${input.title}`, 50)}`;

        // Persist the transcript as the proof artifact
        const evidenceDir = join(session.findingsPath, "evidence");
        mkdirSync(evidenceDir, { recursive: true });
        const transcriptRel = join(
          "findings",
          "evidence",
          `${findingId}-transcript.txt`,
        );
        writeFileSync(
          join(evidenceDir, `${findingId}-transcript.txt`),
          `Signals: ${input.canarySignals.join(", ")}\n\nTranscript:\n${input.agentTranscript}`,
        );

        // Judge (canary mode)
        const judgeResult = await judgeFinding(
          {
            proofType: "canary",
            target: ctx.target ?? session.targets[0],
            agentEvidence: {
              transcript: input.agentTranscript,
              signals: input.canarySignals,
            },
            claim: {
              title: input.title,
              description: input.description,
              impact: input.impact,
              evidence,
              endpoint: input.endpoint,
              vulnerabilityClass: input.vulnerabilityClass,
            },
          },
          {
            model: ctx.model!,
            session: ctx.session,
            authConfig: ctx.authConfig,
            abortSignal: ctx.abortSignal,
            eventBus: ctx.eventBus,
            sandbox: ctx.sandbox,
            target: ctx.target,
            enableThinking: ctx.enableThinking,
            openAIReasoningEffort: ctx.openAIReasoningEffort,
          },
        );

        if (!judgeResult.valid) {
          return {
            success: false,
            judgeRejected: true,
            judgeReasoning: judgeResult.reasoning,
            judgeConcerns: judgeResult.concerns,
            message: `Finding rejected by validation judge: ${judgeResult.reasoning}`,
          };
        }

        const isVulnerability = judgeResult.findingType === "vulnerability";

        // CVSS (agentic guidance) or fallback
        let cvssResult: CVSSScorerResult = FALLBACK_CVSS;
        let cvssWarning: string | undefined;
        if (isVulnerability) {
          try {
            cvssResult = await scoreFindingWithCVSS(
              {
                finding: {
                  title: input.title,
                  description: input.description,
                  impact: input.impact,
                  evidence:
                    `${evidence}\n\nTranscript:\n${input.agentTranscript}`.slice(
                      0,
                      16_000,
                    ),
                  endpoint: input.endpoint,
                  remediation: input.remediation,
                  vulnerabilityClass: input.vulnerabilityClass,
                },
                agentMessages: [],
              },
              ctx.model!,
              ctx.authConfig,
              ctx.abortSignal,
            );
            cvssResult = clampUiForProof(cvssResult, input.canarySignals);
          } catch (err) {
            cvssWarning = `CVSS scoring failed (${err instanceof Error ? err.message : String(err)}); using MEDIUM default.`;
            cvssResult = FALLBACK_CVSS;
          }
        } else {
          cvssResult = {
            ...FALLBACK_CVSS,
            score: 0,
            severity: "LOW",
            vectorString: "",
            scoreType: "N/A",
            reasoning: `Classified as ${judgeResult.findingType} — CVSS scoring skipped.`,
          };
        }

        const severity =
          cvssResult.severity === "NONE" ? "LOW" : cvssResult.severity;

        const evidenceFiles: EvidenceFileEntry[] = [
          {
            path: transcriptRel,
            type: "agent-transcript",
            description: "Conversation transcript proving the exploit",
          },
        ];

        const finding: Finding = {
          title: input.title,
          description: input.description,
          impact: input.impact,
          evidence,
          endpoint: input.endpoint,
          pocPath: transcriptRel,
          remediation: input.remediation,
          ...(input.references && { references: input.references }),
          vulnerabilityClass: input.vulnerabilityClass,
          severity: severity as Finding["severity"],
          evidenceFiles,
        };

        if (isVulnerability && ctx.findingsRegistry) {
          const check = await ctx.findingsRegistry.register(finding);
          if (check.duplicate) {
            return {
              success: false,
              duplicate: true,
              matchType: check.matchType,
              matchedFinding: check.matchedFinding?.title ?? "unknown",
              message: `Duplicate finding (${check.matchType}). Skipping.`,
            };
          }
        }

        const outputDir = isVulnerability
          ? session.findingsPath
          : join(session.rootPath, "informational");
        mkdirSync(outputDir, { recursive: true });

        const findingWithMeta = {
          ...finding,
          timestamp,
          sessionId: session.id,
          target: session.targets[0],
          proofType: "canary",
          signals: input.canarySignals,
          cvss: {
            scored: cvssWarning === undefined && isVulnerability,
            score: cvssResult.score,
            severity: cvssResult.severity,
            vectorString: cvssResult.vectorString,
            reasoning: cvssResult.reasoning,
          },
          judge: {
            valid: judgeResult.valid,
            findingType: judgeResult.findingType,
            confidence: judgeResult.confidence,
            reasoning: judgeResult.reasoning,
            concerns: judgeResult.concerns,
          },
        };

        writeFileSync(
          join(outputDir, `${findingId}.json`),
          JSON.stringify(findingWithMeta, null, 2),
        );
        writeFileSync(
          join(outputDir, `${findingId}.md`),
          `# ${finding.title}

**Severity:** ${severity}${cvssWarning ? " (estimated)" : ""}
**Class:** ${finding.vulnerabilityClass}
**Endpoint:** ${finding.endpoint}
**Proof:** canary (${input.canarySignals.join(", ")})
**Date:** ${timestamp}

## Description

${finding.description}

## Impact

${finding.impact}

## Evidence

\`\`\`
${evidence}
\`\`\`

Transcript: \`${transcriptRel}\`

## Remediation

${finding.remediation}
`,
        );

        return {
          success: true,
          findingId,
          severity,
          vulnerabilityClass: finding.vulnerabilityClass,
          message: `Documented ${severity} ${finding.vulnerabilityClass} finding (${input.canarySignals.join(", ")}).`,
        };
      } catch (err) {
        return {
          success: false,
          message: `document_agentic_finding failed: ${err instanceof Error ? err.message : String(err)}`,
        };
      }
    },
  });
}
