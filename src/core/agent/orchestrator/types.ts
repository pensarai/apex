import { z } from 'zod';

/**
 * Supported vulnerability classes for testing
 */
export type VulnerabilityClass =
  | 'sqli'             // SQL/NoSQL Injection
  | 'idor'             // IDOR/Authorization/Access Control
  | 'xss'              // Cross-Site Scripting
  | 'command-injection' // Command/OS Injection
  | 'lfi'              // Local File Inclusion / Path Traversal
  | 'ssrf'             // Server-Side Request Forgery
  | 'crypto'           // Cryptographic vulnerabilities (malleability, padding oracle, weak algorithms)
  | 'cve'              // Known CVE exploitation (version-specific vulnerabilities)
  | 'generic';         // XXE, SSTI, CSRF, etc.

/**
 * Authentication information for testing
 */
export interface AuthenticationInfo {
  method: string;        // e.g., "cookie-based session", "bearer token"
  details: string;       // How to authenticate
  credentials?: string;  // username:password
  cookies?: string;      // Session cookies
  headers?: string;      // Auth headers
}

/**
 * Session information passed to VulnerabilityTestAgent
 */
export interface SessionInfo {
  id: string;
  rootPath: string;
  findingsPath: string;
  logsPath: string;
  pocsPath: string;
}

/**
 * Input for VulnerabilityTestAgent
 */
export interface VulnerabilityTestInput {
  /** Target endpoint URL */
  target: string;

  /** Testing objective from AttackSurfaceAgent */
  objective: string;

  /** Vulnerability class to test for */
  vulnerabilityClass: VulnerabilityClass;

  /** Authentication information */
  authenticationInfo?: AuthenticationInfo;

  /** Human-readable authentication instructions */
  authenticationInstructions?: string;

  /** Outcome guidance controlling exploit behavior */
  outcomeGuidance: string;

  /** Session information */
  session: SessionInfo;
}

/**
 * Result from VulnerabilityTestAgent
 */
export interface VulnerabilityTestResult {
  /** Whether any vulnerabilities were found */
  vulnerabilitiesFound: boolean;

  /** Number of findings documented */
  findingsCount: number;

  /** Paths to POC scripts created */
  pocPaths: string[];

  /** Paths to finding JSON files */
  findingPaths: string[];

  /** Summary of testing performed */
  summary: string;

  /** Error if agent encountered issues */
  error?: string;
}

/**
 * Zod schema for document_finding tool input
 */
export const DocumentFindingSchema = z.object({
  title: z.string().describe('Clear, concise finding title'),
  severity: z.preprocess(
    (val) => {
      if (typeof val === 'string') {
        const upper = val.toUpperCase();
        if (upper.includes('CRITICAL')) return 'CRITICAL';
        if (upper.includes('HIGH')) return 'HIGH';
        if (upper.includes('MEDIUM')) return 'MEDIUM';
        if (upper.includes('LOW')) return 'LOW';
      }
      return val;
    },
    z.enum(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'])
  ),
  description: z.string().describe('Detailed technical description'),
  impact: z.string().describe('Potential impact if exploited'),
  evidence: z.string().describe('Evidence/proof of vulnerability including POC output'),
  endpoint: z.string().describe('Full URL endpoint (e.g., https://example.com/api/endpoint)'),
  pocPath: z.string().describe('Relative path to POC script (e.g., pocs/poc_sqli_login.sh)'),
  remediation: z.string().describe('Steps to fix the vulnerability'),
  references: z.string().optional().describe('CVE, CWE, or related references'),
});

export type DocumentFindingInput = z.infer<typeof DocumentFindingSchema>;

/**
 * Zod schema for create_poc tool input
 */
export const CreatePocSchema = z.object({
  pocName: z.string().describe('POC filename without extension (e.g., sqli_login_bypass)'),
  pocType: z.enum(['bash', 'html']).describe('POC type: bash for scripts, html for browser-based'),
  pocContent: z.string().describe('Complete POC content'),
  description: z.string().describe('Brief description of what the POC demonstrates'),
});

export type CreatePocInput = z.infer<typeof CreatePocSchema>;

/**
 * Result from create_poc tool
 */
export interface CreatePocResult {
  success: boolean;
  pocPath?: string;
  execution?: {
    success: boolean;
    exitCode?: number;
    stdout?: string;
    stderr?: string;
  };
  error?: string;
  message: string;
}

/**
 * Result from document_finding tool
 */
export interface DocumentFindingResult {
  success: boolean;
  findingPath?: string;
  error?: string;
  message: string;
}
