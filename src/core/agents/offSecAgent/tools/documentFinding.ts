import { tool } from "ai";
import { z } from "zod";
import { join } from "path";
import { writeFileSync, appendFileSync } from "fs";
import type { ToolContext } from "./types";

export const documentFindingInputSchema = z.object({
  title: z.string().describe("Finding title"),
  severity: z.enum(["CRITICAL", "HIGH", "MEDIUM", "LOW"]),
  description: z.string().describe("Detailed description of the finding"),
  impact: z.string().describe("Potential impact if exploited"),
  evidence: z.string().describe("Evidence/proof of the vulnerability"),
  endpoint: z.string().describe("The affected endpoint or URL"),
  pocPath: z
    .string()
    .describe("Relative path to the POC script (e.g., pocs/poc_sqli.sh)"),
  remediation: z.string().describe("Steps to fix the issue"),
  references: z.string().optional().describe("CVE, CWE, or related references"),
  toolCallDescription: z
    .string()
    .describe(
      "A concise, human-readable description of what this tool call is doing (e.g., 'Documenting SQL injection finding')",
    ),
});

export type DocumentFindingInput = z.infer<typeof documentFindingInputSchema>;

export function documentFinding(ctx: ToolContext) {
  const { session } = ctx;

  return tool({
    description: `Document a confirmed security finding with severity, impact, and remediation guidance.

SEVERITY LEVELS:
- CRITICAL: Immediate risk of system compromise (RCE, auth bypass, SQL injection with data access)
- HIGH: Significant security risk (XSS, CSRF, sensitive data exposure, privilege escalation)
- MEDIUM: Security weakness that could be exploited (information disclosure, weak configs)
- LOW: Minor security concern (missing headers, verbose errors)

FINDING STRUCTURE:
- Title: Clear, concise description
- Severity: Use CVSS if applicable
- Description: Detailed technical explanation
- Impact: Business and technical consequences
- Evidence: Commands run, responses received, proof of vulnerability
- Remediation: Specific, actionable steps to fix
- References: CVE, CWE, OWASP, or security advisories`,
    inputSchema: documentFindingInputSchema,
    execute: async (finding) => {
      try {
        // -- Dedup check (when a shared registry is available) ----------------
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
        const findingWithMeta = {
          ...finding,
          timestamp,
          sessionId: session.id,
          target: session.targets[0],
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
          // Write structured JSON (consumed by resolveResult)
          writeFileSync(jsonPath, JSON.stringify(findingWithMeta, null, 2));

          // Write human-readable markdown
          const markdown = `# ${finding.title}

**Severity:** ${finding.severity}  
**Target:** ${session.targets[0]}  
**Endpoint:** ${finding.endpoint}  
**Date:** ${timestamp}  
**Session:** ${session.id}

## Description

${finding.description}

## Impact

${finding.impact}

## Evidence

\`\`\`
${finding.evidence}
\`\`\`

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
          const summaryEntry = `- [${finding.severity}] ${finding.title} - \`findings/${mdFilename}\`\n`;

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
          filepath: mdPath,
          message: `Finding documented: [${finding.severity}] ${finding.title}`,
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
