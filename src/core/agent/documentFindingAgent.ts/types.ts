import z from "zod";

export const ApexFindingObject = z.object({
  title: z.string().describe("Finding title"),
  severity: z.enum(["CRITICAL", "HIGH", "MEDIUM", "LOW"]),
  description: z.string().describe("Detailed description of the finding"),
  impact: z.string().describe("Potential impact if exploited"),
  endpoint: z.string().describe("URL Endpoint of the finding"),
  evidence: z.string().describe("Evidence/proof of the vulnerability"),
  pocPath: z
    .string()
    .describe(
      "Path to POC script relative to session root (e.g., 'pocs/poc_sqli_login.sh')"
    ),
  remediation: z.string().describe("Steps to fix the issue"),
  references: z.string().optional().describe("CVE, CWE, or related references"),
  toolCallDescription: z
    .string()
    .describe("Concise description of this tool call"),
});

export type ApexFinding = z.infer<typeof ApexFindingObject>;
