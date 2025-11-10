import z from 'zod';

export const ApexFindingObject = z.object({
  title: z.string().describe('Finding title'),
  severity: z.enum(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']),
  description: z.string().describe('Detailed description of the finding'),
  impact: z.string().describe('Potential impact if exploited'),
  endpoint: z
    .string()
    .describe(
      'ONLY the full URL Endpoint of the finding. Do not include any other text. i.e. https://example.com/endpoint'
    ),
  evidence: z.string().describe('Evidence/proof of the vulnerability'),
  pocPath: z
    .string()
    .describe(
      "Path to POC script relative to session root (e.g., 'pocs/poc_sqli_login.sh')"
    ),
  remediation: z.string().describe('Steps to fix the issue'),
  references: z.string().optional().describe('CVE, CWE, or related references'),
  toolCallDescription: z
    .string()
    .describe('Concise description of this tool call'),
});

export type ApexFinding = z.infer<typeof ApexFindingObject>;

export const CreatePocObject = z.object({
  pocName: z
    .string()
    .describe(
      "Name for the POC file (e.g., 'sqli_login', 'xss_stored', 'csrf_attack')"
    ),
  pocType: z
    .enum(['bash', 'html'])
    .describe(
      "Type of POC: 'bash' for executable scripts (RECOMMENDED) or 'html' for web-based exploits"
    ),
  pocContent: z.string().describe('Complete file content for the POC'),
  description: z
    .string()
    .describe('Brief description of what this POC demonstrates'),
  toolCallDescription: z
    .string()
    .describe('Concise description of this tool call'),
});

export type CreatePocOpts = z.infer<typeof CreatePocObject>;
export type CreatePocResult = {
  success: boolean;
  exitCode?: number;
  stdout?: string;
  stderr?: string;
  pocPath?: string | null;
  fullPath?: string | null;
  pocType?: string;
  description?: string;
  execution?: {
    success: boolean;
    exitCode?: number;
    stdout?: string;
    stderr?: string;
    executionSkipped?: boolean;
    reason?: string;
    error?: string;
  };
  fileDeleted?: boolean;
  message?: string;
  error?: string;
};

export type DocumentFindingResult = {
  success: boolean;
  error: string;
  message: string;
  pocPath: string;
  expectedLocation: string;
  filepath: string;
};
