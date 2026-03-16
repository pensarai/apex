import { tool } from "ai";
import { z } from "zod";
import { join } from "path";
import { writeFileSync, appendFileSync, readFileSync } from "fs";
import type { ToolContext } from "./types";
import {
  scoreFindingWithCVSS,
  type CVSSScorerResult,
} from "../../specialized/cvssScorer";
import type { Finding } from "../types";

export const documentVulnerabilityInputSchema = z.object({
  title: z.string().describe("Finding title"),
  description: z.string().describe("Detailed description of the finding"),
  impact: z.string().describe("Potential impact if exploited"),
  evidence: z.string().describe("Evidence/proof of the vulnerability"),
  endpoint: z.string().describe("The affected endpoint or URL"),
  pocPath: z
    .string()
    .describe("Relative path to the POC script (e.g., pocs/poc_sqli.sh)"),
  remediation: z.string().describe("Steps to fix the issue"),
  references: z.string().optional().describe("CVE, CWE, or related references"),
  vulnerabilityClass: z
    .string()
    .optional()
    .describe(
      "The class of vulnerability (e.g., sqli, xss, command-injection, idor, ssrf, path-traversal, crypto, cve)",
    ),
  toolCallDescription: z
    .string()
    .describe(
      "A concise, human-readable description of what this tool call is doing (e.g., 'Documenting SQL injection finding')",
    ),
});

export type DocumentVulnerabilityInput = z.infer<
  typeof documentVulnerabilityInputSchema
>;

const EVIDENCE_FILE_THRESHOLD = 20_000;

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

export function documentVulnerability(ctx: ToolContext) {
  const { session } = ctx;

  return tool({
    description: `Document a CONFIRMED security vulnerability that you have successfully exploited with a working proof-of-concept.

CRITICAL RULES — READ BEFORE CALLING:
- ONLY call this tool for actual security vulnerabilities you have verified and exploited
- You MUST have a working PoC script (created via create_poc) that reliably demonstrates the vulnerability BEFORE calling this tool
- Do NOT use this tool for: positive/negative observations, informational notes, testing limitations, authentication issues, rate-limiting, infrastructure notes, or anything that is not a exploitable security vulnerability
- If you could not exploit a vulnerability, do NOT document it — mention it in your final response summary instead
- Severity is automatically determined from CVSS 4.0 scoring — you do NOT need to specify it

FINDING STRUCTURE:
- Title: Clear, concise description of the vulnerability
- Description: Detailed technical explanation of the vulnerability
- Impact: Business and technical consequences if exploited
- Evidence: Commands run, responses received, proof of exploitation
- Remediation: Specific, actionable steps to fix
- References: CVE, CWE, OWASP, or security advisories
- Vulnerability Class: The class of vulnerability (e.g., sqli, xss, command-injection) — improves CWE accuracy`,
    inputSchema: documentVulnerabilityInputSchema,
    execute: async (input) => {
      try {
        const timestamp = new Date().toISOString();

        // -- Persist large evidence to a sidecar file -----------------------
        let evidenceForPrompt = input.evidence;
        let evidenceFilePath: string | undefined;

        if (input.evidence.length > EVIDENCE_FILE_THRESHOLD) {
          const safeSlug = input.title
            .toLowerCase()
            .replace(/[^a-z0-9]+/g, "-")
            .replace(/^-|-$/g, "")
            .substring(0, 40);
          const evidenceFilename = `${timestamp.split("T")[0]}-${safeSlug}-evidence.txt`;
          evidenceFilePath = join(session.findingsPath, evidenceFilename);
          writeFileSync(evidenceFilePath, input.evidence);
          evidenceForPrompt =
            input.evidence.substring(0, EVIDENCE_FILE_THRESHOLD) +
            `\n... [truncated — full output saved to ${evidenceFilename}]`;
        }

        // -- CVSS 4.0 scoring (determines severity) ------------------------
        let cvssResult: CVSSScorerResult;
        let cvssWarning: string | undefined;

        try {
          cvssResult = await scoreFindingWithCVSS(
            {
              finding: {
                title: input.title,
                description: input.description,
                impact: input.impact,
                evidence: evidenceForPrompt,
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
        } catch (cvssError: unknown) {
          const msg =
            cvssError instanceof Error ? cvssError.message : String(cvssError);
          cvssWarning = `CVSS scoring failed (${msg}), using fallback severity.`;
          cvssResult = FALLBACK_CVSS;
        }

        const severity =
          cvssResult.severity === "NONE" ? "LOW" : cvssResult.severity;

        const finding: Finding = {
          ...input,
          severity: severity as Finding["severity"],
        };

        // -- Dedup check (when a shared registry is available) --------------
        if (ctx.findingsRegistry) {
          const check = await ctx.findingsRegistry.register(finding);
          if (check.duplicate) {
            const matchTitle = check.matchedFinding?.title ?? "unknown";
            return {
              success: false,
              duplicate: true,
              matchType: check.matchType,
              matchedFinding: matchTitle,
              message: `Duplicate finding (${check.matchType}): already documented as "${matchTitle}". Skipping.`,
            };
          }
        }

        // Read POC execution output if available
        let pocOutput: {
          stdout: string;
          stderr: string;
          exitCode: number;
          executedAt: string;
        } | null = null;

        if (input.pocPath) {
          try {
            const pocBasename = input.pocPath.replace(/^pocs\//, "");
            const outputPath = join(
              session.pocsPath,
              `${pocBasename}.output.json`,
            );
            pocOutput = JSON.parse(readFileSync(outputPath, "utf-8"));
          } catch {
            // Non-critical: file may not exist or be malformed
          }
        }

        const findingWithMeta = {
          ...finding,
          timestamp,
          sessionId: session.id,
          target: session.targets[0],
          ...(evidenceFilePath && { evidenceFile: evidenceFilePath }),
          ...(pocOutput && { pocOutput }),
          cwes: cvssResult.cwes,
          cvss: {
            score: cvssResult.score,
            severity: cvssResult.severity,
            vectorString: cvssResult.vectorString,
            metrics: cvssResult.metrics,
            scoreType: cvssResult.scoreType,
            reasoning: cvssResult.reasoning,
          },
        };

        // Safe filename from title
        const safeTitle = finding.title
          .toLowerCase()
          .replace(/[^a-z0-9]+/g, "-")
          .replace(/^-|-$/g, "")
          .substring(0, 50);

        const findingId = `${timestamp.split("T")[0]}-${safeTitle}`;
        const jsonFilename = `${findingId}.json`;
        const jsonPath = join(session.findingsPath, jsonFilename);
        const mdFilename = `${findingId}.md`;
        const mdPath = join(session.findingsPath, mdFilename);

        try {
          writeFileSync(jsonPath, JSON.stringify(findingWithMeta, null, 2));

          const cvssSection = cvssWarning
            ? `## CVSS 4.0 Assessment

**Warning:** ${cvssWarning}

**Score:** ${cvssResult.score} / 10.0 (${cvssResult.severity})  
**Score Type:** ${cvssResult.scoreType}`
            : `## CVSS 4.0 Assessment

**Score:** ${cvssResult.score} / 10.0 (${cvssResult.severity})  
**Vector:** \`${cvssResult.vectorString}\`  
**Score Type:** ${cvssResult.scoreType}

**Reasoning:** ${cvssResult.reasoning}`;

          const cweSection = cvssResult.cwes?.length
            ? `## CWE Classification

${cvssResult.cwes.map((cwe) => `- **${cwe.id}** — ${cwe.reasoning}`).join("\n")}`
            : "";

          const evidenceSection = evidenceFilePath
            ? `## Evidence

\`\`\`
${input.evidence.substring(0, 5_000)}
\`\`\`

> Full evidence output: \`${evidenceFilePath}\``
            : `## Evidence

\`\`\`
${finding.evidence}
\`\`\``;

          const markdown = `# ${finding.title}

**Severity:** ${finding.severity}  
**CVSS 4.0 Score:** ${cvssResult.score} (${cvssResult.severity})  
**Vector:** \`${cvssResult.vectorString}\`  
**Target:** ${session.targets[0]}  
**Endpoint:** ${finding.endpoint}  
**Date:** ${timestamp}  
**Session:** ${session.id}

## Description

${finding.description}

## Impact

${finding.impact}

${cvssSection}

${cweSection ? `${cweSection}\n\n` : ""}${evidenceSection}

## POC

Path: \`${finding.pocPath}\`

## Remediation

${finding.remediation}

${finding.references ? `## References\n\n${finding.references}` : ""}

---

*This finding was automatically documented by the Pensar penetration testing agent.*
`;

          writeFileSync(mdPath, markdown);

          // Append to summary
          const summaryPath = join(session.rootPath, "findings-summary.md");
          const cweTag = cvssResult.cwes?.length
            ? ` (${cvssResult.cwes.map((c) => c.id).join(", ")})`
            : "";
          const summaryEntry = `- [${finding.severity}] (CVSS ${cvssResult.score})${cweTag} ${finding.title} - \`findings/${mdFilename}\`\n`;

          try {
            appendFileSync(summaryPath, summaryEntry);
          } catch {
            const header = `# Findings Summary\n\n**Target:** ${session.targets[0]}  \n**Session:** ${session.id}\n\n## All Findings\n\n`;
            writeFileSync(summaryPath, header + summaryEntry);
          }
        } catch (writeError: unknown) {
          if (ctx.findingsRegistry) {
            await ctx.findingsRegistry.unregister(finding);
          }
          throw writeError;
        }

        const resultMessage = cvssWarning
          ? `Finding documented: [${finding.severity}] ${finding.title} (${cvssWarning})`
          : `Finding documented: [${finding.severity}] ${finding.title}`;

        return {
          success: true,
          finding: findingWithMeta,
          filepath: mdPath,
          message: resultMessage,
        };
      } catch (error: unknown) {
        const errorMsg = error instanceof Error ? error.message : String(error);
        return {
          success: false,
          error: errorMsg,
          message: `Failed to document finding: ${errorMsg}`,
        };
      }
    },
  });
}
