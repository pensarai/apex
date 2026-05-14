import { z } from "zod";
import { CweEntrySchema, ValidatedCweEntrySchema } from "../../lib/cwe/types";
import { EvidenceFileEntrySchema } from "../../lib/evidence/types";
import { FindingSeveritySchema } from "../findings/severity";

/**
 * Supported vulnerability classes for testing
 */
export type VulnerabilityClass =
  | "sqli" // SQL/NoSQL Injection
  | "idor" // IDOR/Authorization/Access Control
  | "xss" // Cross-Site Scripting
  | "command-injection" // Command/OS Injection
  | "lfi" // Local File Inclusion / Path Traversal
  | "ssrf" // Server-Side Request Forgery
  | "crypto" // Cryptographic vulnerabilities (malleability, padding oracle, weak algorithms)
  | "cve" // Known CVE exploitation (version-specific vulnerabilities)
  | "generic"; // XXE, SSTI, CSRF, etc.

/**
 * Authentication information for testing
 */
export interface AuthenticationInfo {
  method: string; // e.g., "cookie-based session", "bearer token"
  details: string; // How to authenticate
  credentials?: string; // username:password
  cookies?: string; // Session cookies
  headers?: string; // Auth headers
}

/**
 * Session information passed to VulnerabilityTestAgent
 */
interface SessionInfo {
  id: string;
  rootPath: string;
  findingsPath: string;
  logsPath: string;
  pocsPath: string;
}

/**
 * Input for VulnerabilityTestAgent
 */
interface VulnerabilityTestInput {
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
interface VulnerabilityTestResult {
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
 * Zod schema for document_vulnerability tool input
 */
export const DocumentFindingSchema = z.object({
  title: z.string().describe("Clear, concise finding title"),
  severity: FindingSeveritySchema,
  description: z.string().describe("Detailed technical description"),
  impact: z.string().describe("Potential impact if exploited"),
  evidence: z
    .string()
    .describe("Evidence/proof of vulnerability including POC output"),
  endpoint: z
    .string()
    .describe("Full URL endpoint (e.g., https://example.com/api/endpoint)"),
  pocPath: z
    .string()
    .describe("Relative path to POC script (e.g., pocs/poc_sqli_login.sh)"),
  remediation: z.string().describe("Steps to fix the vulnerability"),
  references: z.string().optional().describe("CVE, CWE, or related references"),
  cwes: z.array(ValidatedCweEntrySchema.or(CweEntrySchema)).optional(),
  evidenceFiles: z.array(EvidenceFileEntrySchema).optional(),
});

type DocumentFindingInput = z.infer<typeof DocumentFindingSchema>;

/**
 * Result from document_vulnerability tool
 */
interface DocumentFindingResult {
  success: boolean;
  findingPath?: string;
  error?: string;
  message: string;
}
