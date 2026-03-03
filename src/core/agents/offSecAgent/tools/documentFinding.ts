import { tool } from "ai";
import { z } from "zod";
import { join } from "path";
import { writeFileSync, appendFileSync } from "fs";
import type { ToolContext } from "./types";
import {
  scoreFindingWithCVSS,
  type CVSSScorerResult,
} from "../../specialized/cvssScorer";
import { executePocScript, type CreatePocResult } from "./createPoc";

export const documentVulnerabilityInputSchema = z.object({
  title: z.string().describe("Finding title"),
  severity: z.enum(["CRITICAL", "HIGH", "MEDIUM", "LOW"]),
  description: z.string().describe("Detailed description of the finding"),
  impact: z.string().describe("Potential impact if exploited"),
  evidence: z.string().describe("Evidence/proof of the vulnerability"),
  endpoint: z.string().describe("The affected endpoint or URL"),
  poc: z.object({
    name: z.string().describe("Short descriptive name for the POC"),
    type: z
      .enum(["bash", "python", "javascript"])
      .describe("Script language for the POC"),
    content: z.string().describe("The full POC script content"),
    description: z
      .string()
      .describe(
        "What this POC demonstrates (e.g., 'SQL injection via id parameter')",
      ),
  }),
  remediation: z.string().describe("Steps to fix the issue"),
  references: z.string().optional().describe("CVE, CWE, or related references"),
  toolCallDescription: z
    .string()
    .describe(
      "A concise, human-readable description of what this tool call is doing (e.g., 'Documenting SQL injection finding')",
    ),
});

export type DocumentVulnerabilityInput = z.infer<
  typeof documentVulnerabilityInputSchema
>;

export function documentVulnerability(ctx: ToolContext) {
  const { session } = ctx;

  return tool({
    description: `Document a CONFIRMED security vulnerability with an embedded proof-of-concept.

This tool creates, executes, and validates a POC script, then documents the finding only if the POC succeeds. This guarantees every documented vulnerability has a working, verified POC on disk.

CRITICAL RULES — READ BEFORE CALLING:
- ONLY call this tool for actual security vulnerabilities you have verified and exploited
- You MUST provide a POC script (in the \`poc\` field) that reliably demonstrates the vulnerability — this tool will execute it and only document the finding if it exits 0
- Do NOT use this tool for: positive/negative observations, informational notes, testing limitations, authentication issues, rate-limiting, infrastructure notes, or anything that is not an exploitable security vulnerability
- If you could not exploit a vulnerability, do NOT document it — mention it in your final response summary instead

POC REQUIREMENTS:
- The POC script must exit 0 on success (vulnerability confirmed) and non-zero on failure
- The script should print clear evidence of exploitation to stdout
- Supported languages: bash (.sh), python (.py), javascript (.js)
- Include rate limiting (sleep between requests) if the POC makes multiple HTTP calls

SEVERITY LEVELS:
- CRITICAL: Immediate risk of system compromise (RCE, auth bypass, SQL injection with data access)
- HIGH: Significant security risk (XSS, CSRF, sensitive data exposure, privilege escalation)
- MEDIUM: Security weakness that could be exploited (information disclosure, weak configs)
- LOW: Minor security concern (missing headers, verbose errors)

FINDING STRUCTURE:
- Title: Clear, concise description of the vulnerability
- Severity: Use CVSS if applicable
- Description: Detailed technical explanation of the vulnerability
- Impact: Business and technical consequences if exploited
- Evidence: Commands run, responses received, proof of exploitation
- POC: The proof-of-concept script (name, type, content, description)
- Remediation: Specific, actionable steps to fix
- References: CVE, CWE, OWASP, or security advisories`,
    inputSchema: documentVulnerabilityInputSchema,
    execute: async (input) => {
      try {
        // -- Step 1: Create and execute the POC ----------------------------------
        let pocResult: CreatePocResult;
        try {
          pocResult = await executePocScript(ctx, {
            pocName: input.poc.name,
            pocType: input.poc.type,
            pocContent: input.poc.content,
            description: input.poc.description,
            toolCallDescription: `POC for: ${input.title}`,
          });
        } catch (pocError: unknown) {
          const msg =
            pocError instanceof Error ? pocError.message : String(pocError);
          return {
            success: false,
            error: `POC execution failed: ${msg}`,
            message: `Could not create/run POC for "${input.title}". Fix the POC script and retry.`,
          };
        }

        if (!pocResult.success || !pocResult.pocPath) {
          return {
            success: false,
            pocFailed: true,
            stdout: pocResult.stdout,
            stderr: pocResult.stderr,
            exitCode: pocResult.exitCode,
            error:
              pocResult.error ??
              `POC exited with code ${pocResult.exitCode ?? "unknown"}`,
            message: `POC did not succeed for "${input.title}". The script must exit 0 to confirm the vulnerability. Fix the POC and call document_vulnerability again.`,
          };
        }

        const pocPath = pocResult.pocPath;

        // Build a Finding-shaped object (pocPath comes from the verified POC)
        const finding = {
          title: input.title,
          severity: input.severity,
          description: input.description,
          impact: input.impact,
          evidence: input.evidence,
          endpoint: input.endpoint,
          pocPath,
          remediation: input.remediation,
          references: input.references,
          toolCallDescription: input.toolCallDescription,
        };

        // -- Step 2: Dedup check (when a shared registry is available) -----------
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

        const timestamp = new Date().toISOString();

        // -- Step 3: CVSS 4.0 scoring ------------------------------------------
        let cvssResult: CVSSScorerResult | undefined;
        try {
          cvssResult = await scoreFindingWithCVSS(
            {
              finding: {
                title: finding.title,
                description: finding.description,
                impact: finding.impact,
                evidence: finding.evidence,
                endpoint: finding.endpoint,
                remediation: finding.remediation,
              },
              agentMessages: [],
            },
            ctx.model!,
            ctx.authConfig,
          );
        } catch (err) {
          console.warn(
            "CVSS scoring failed, proceeding without score:",
            err instanceof Error ? err.message : err,
          );
        }

        const findingWithMeta = {
          ...finding,
          timestamp,
          sessionId: session.id,
          target: session.targets[0],
          ...(cvssResult && {
            cvss: {
              score: cvssResult.score,
              severity: cvssResult.severity,
              vectorString: cvssResult.vectorString,
              metrics: cvssResult.metrics,
              scoreType: cvssResult.scoreType,
              reasoning: cvssResult.reasoning,
            },
          }),
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

        // -- Step 4: Persist finding to disk ------------------------------------
        try {
          writeFileSync(jsonPath, JSON.stringify(findingWithMeta, null, 2));

          const cvssLine = cvssResult
            ? `\n**CVSS 4.0 Score:** ${cvssResult.score} (${cvssResult.severity})  \n**Vector:** \`${cvssResult.vectorString}\`  `
            : "";
          const cvssSection = cvssResult
            ? `\n## CVSS 4.0 Assessment\n\n**Score:** ${cvssResult.score} / 10.0 (${cvssResult.severity})  \n**Vector:** \`${cvssResult.vectorString}\`  \n**Score Type:** ${cvssResult.scoreType}\n\n**Reasoning:** ${cvssResult.reasoning}\n`
            : "";

          const markdown = `# ${finding.title}

**Severity:** ${finding.severity}  ${cvssLine}
**Target:** ${session.targets[0]}  
**Endpoint:** ${finding.endpoint}  
**Date:** ${timestamp}  
**Session:** ${session.id}

## Description

${finding.description}

## Impact

${finding.impact}
${cvssSection}
## Evidence

\`\`\`
${finding.evidence}
\`\`\`

## POC

Path: \`${pocPath}\`

## Remediation

${finding.remediation}

${finding.references ? `## References\n\n${finding.references}` : ""}

---

*This finding was automatically documented by the Pensar penetration testing agent.*
`;

          writeFileSync(mdPath, markdown);

          const summaryPath = join(session.rootPath, "findings-summary.md");
          const cvssTag = cvssResult ? ` (CVSS ${cvssResult.score})` : "";
          const summaryEntry = `- [${finding.severity}]${cvssTag} ${finding.title} - \`findings/${mdFilename}\`\n`;

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

        return {
          success: true,
          finding: findingWithMeta,
          pocPath,
          pocStdout: pocResult.stdout,
          filepath: mdPath,
          message: `Finding documented: [${finding.severity}] ${finding.title} (POC verified: ${pocPath})`,
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
