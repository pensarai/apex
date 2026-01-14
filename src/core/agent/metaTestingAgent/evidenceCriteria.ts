/**
 * Evidence Criteria
 *
 * Rigorous, specific evidence requirements for each vulnerability class.
 * Agents must validate their evidence against these criteria before
 * documenting findings.
 */

import { tool } from 'ai';
import { z } from 'zod';
import type { VulnerabilityClass } from '../orchestrator/types';

/**
 * Evidence criterion for a vulnerability class
 */
export interface EvidenceCriterion {
  /** What must be present to confirm vulnerability (at least one required) */
  required: string[];

  /** Additional confirmatory evidence (strengthens finding) */
  supporting?: string[];

  /** What does NOT count as evidence */
  notEvidence: string[];

  /** Minimum confidence threshold to claim vulnerability */
  minConfidence: number;
}

/**
 * Evidence criteria for each vulnerability class
 */
export const EVIDENCE_CRITERIA: Record<VulnerabilityClass, EvidenceCriterion> = {
  'sqli': {
    required: [
      'Actual data extraction (table contents, column values, database records)',
      'UNION-based data extraction with confirmed column enumeration (ORDER BY or NULL technique)',
      'SQL error message revealing database structure (table names, column names, DB type)',
      'Boolean-based response difference with control comparison (TRUE vs FALSE query)',
      'Time-based delay (3+ seconds) with timing control comparison (no injection vs injection)',
      'Out-of-band DNS/HTTP exfiltration with data in callback (e.g., xp_dirtree, LOAD_FILE)',
    ],
    supporting: [
      'Database version extracted',
      'Table/column names enumerated via information_schema',
      'Authentication bypassed via SQL injection',
      'Multiple injection points confirmed',
      'Database-specific syntax exploited (Oracle DUAL, MySQL #, MSSQL xp_cmdshell)',
      'WAF bypass technique confirmed (encoding, case variation, comment injection)',
    ],
    notEvidence: [
      'HTTP 200 status code alone',
      'Generic application error without SQL details',
      'Response length difference without content analysis',
      'Single quote causing error (might just be input validation)',
      'ORDER BY causing error without confirmed column enumeration',
      'Syntax error without data extraction or structure revelation',
    ],
    minConfidence: 80,
  },

  'xss': {
    required: [
      'Script execution in browser context (alert, console.log, DOM manipulation)',
      'Payload reflected in executable context (unescaped, not in attribute without quotes)',
      'Context-aware payload execution (HTML/attribute/JS context identified)',
      'DOM-based XSS with source-to-sink flow identified (location/URL to innerHTML/eval)',
      'Browser verification URL demonstrating execution',
    ],
    supporting: [
      'CSP bypass demonstrated',
      'Stored XSS triggers on page load',
      'Event handler fires with proof',
      'Cookie/session data exfiltrated',
      'Filter bypass technique identified (encoding, case mutation, nested tags)',
      'Alternative event handlers/tags confirmed (svg, body, details, marquee)',
    ],
    notEvidence: [
      'Payload reflected but HTML-encoded',
      'Payload in JavaScript string (escaped)',
      'Reflection in HTML comment',
      'HTTP 200 with payload in response body',
      'Payload in JSON response without DOM context',
      'Reflection in non-executable context (attribute value in quotes without event)',
    ],
    minConfidence: 75,
  },

  'idor': {
    required: [
      'Access to another user\'s data with proof (different user ID, different data content)',
      'Modification of another user\'s resource (verified change)',
      'Privilege escalation to admin/higher role with proof',
      'Comparison showing own data vs other user\'s data',
      'Platform misconfiguration bypass (X-Original-URL header, HTTP method manipulation)',
      'Multi-step process bypass (access control skipped on later steps)',
    ],
    supporting: [
      'Sequential ID enumeration successful',
      'Horizontal privilege escalation (user A accessing user B)',
      'Vertical privilege escalation (user to admin)',
      'Bulk data extraction possible',
      'URL-matching bypass (case sensitivity, trailing slash, file extension)',
      'Referer-based access control bypass',
      'Parameter-based role manipulation (?admin=true, ?role=1)',
    ],
    notEvidence: [
      'HTTP 200 on resource request (might be own resource)',
      'Same data returned for different IDs',
      'Access to public resources',
      'Error message mentioning authorization',
      '401/403 without bypass attempt (access control working)',
    ],
    minConfidence: 85,
  },

  'command-injection': {
    required: [
      'Command output visible in response (id, whoami, hostname, uname)',
      'File created/modified by injected command (with verification)',
      'Time delay from sleep/timeout/ping (with control comparison - baseline vs injected)',
      'Out-of-band callback (DNS, HTTP) triggered by injected command with unique identifier',
      'Blind injection confirmed via output redirection to web-accessible path',
    ],
    supporting: [
      'Multiple commands executed successfully',
      'Reverse shell established',
      'File system access demonstrated',
      'Environment variables leaked',
      'Multiple separator techniques validated (;, |, &&, ||, newline, backticks)',
      'Cross-platform payload confirmed (Unix and Windows)',
    ],
    notEvidence: [
      'Error message mentioning command',
      'Application crash without output',
      'HTTP 500 status alone',
      'Timeout without control comparison',
      'Command not found error (might just be input reaching shell)',
    ],
    minConfidence: 90,
  },

  'lfi': {
    required: [
      'Actual file content retrieved (e.g., root:x:0:0 for /etc/passwd)',
      'PHP source code via php://filter wrapper (base64 decoded)',
      'Sensitive config file contents (database credentials, API keys)',
      'Content validation against known file format',
      'Filter bypass technique exploited (encoding, nested sequences, null byte)',
      'PHP wrapper exploitation (php://filter, php://input, data://)',
    ],
    supporting: [
      'Multiple files read successfully',
      'Path traversal depth determined',
      'Filter bypass technique identified',
      'Log poisoning possible',
      'Nested sequence bypass confirmed (....// surviving filter)',
      'Encoding bypass confirmed (URL, double URL, UTF-8)',
    ],
    notEvidence: [
      'HTTP 200 without file content',
      'Error message mentioning file path',
      'Redirect or empty response',
      'File not found error (might just be wrong path)',
      'Path traversal sequence in error without file content',
    ],
    minConfidence: 85,
  },

  'ssrf': {
    required: [
      'Internal service response content retrieved',
      'Cloud metadata accessed (AWS/GCP/Azure instance data, credentials)',
      'DNS callback to controlled server (with unique identifier)',
      'Port scan results showing internal connectivity',
      'Blacklist/whitelist bypass technique confirmed (IP encoding, URL parsing)',
      'Open redirection chain exploited for internal access',
    ],
    supporting: [
      'Internal network topology revealed',
      'Credentials from metadata service',
      'Internal service banners',
      'Protocol smuggling successful (gopher://, dict://, file://)',
      'IP representation bypass (decimal, hex, octal, shortened)',
      'URL parser discrepancy exploited (credentials, fragments, DNS hierarchy)',
    ],
    notEvidence: [
      'Request made but no response analysis',
      'Different error message (might just be blocking)',
      'Timeout without confirmation',
      'HTTP 200 without internal data',
      'External URL fetch working (not SSRF unless internal access)',
    ],
    minConfidence: 80,
  },

  'crypto': {
    required: [
      'Decryption of ciphertext without key',
      'Forged signature/token accepted by application',
      'Padding oracle timing difference demonstrated (statistical significance)',
      'Ciphertext manipulation producing valid output',
    ],
    supporting: [
      'Key recovery (partial or full)',
      'IV reuse exploitation',
      'Block cipher mode weakness exploited',
      'Session fixation via crypto weakness',
    ],
    notEvidence: [
      'Weak algorithm identified but not exploited',
      'Theoretical attack without POC',
      'Error message about crypto',
      'Different ciphertext lengths',
    ],
    minConfidence: 85,
  },

  'cve': {
    required: [
      'Specific CVE exploit executed successfully',
      'Version-specific behavior confirmed matching CVE description',
      'Exploit output matches CVE expected impact',
    ],
    supporting: [
      'Version fingerprint matches vulnerable version exactly',
      'Exploit code adapted successfully from public POC',
      'Multiple CVEs confirmed on same target',
    ],
    notEvidence: [
      'Version might be vulnerable (unconfirmed)',
      'CVE exists for software but not confirmed exploitable',
      'Similar behavior without version confirmation',
    ],
    minConfidence: 85,
  },

  'generic': {
    required: [
      'Vulnerability-specific POC demonstrates exploitable condition',
      'Clear evidence of security impact (data access, code execution, etc.)',
    ],
    supporting: [
      'Multiple instances found',
      'Automation possible',
      'Chain with other vulnerabilities',
    ],
    notEvidence: [
      'Suspicious behavior without exploitation',
      'Potential vulnerability without POC',
      'Information disclosure without sensitive data',
    ],
    minConfidence: 75,
  },
};

/**
 * Input schema for validate_evidence tool
 */
export const ValidateEvidenceSchema = z.object({
  evidence: z.string().describe('Description of evidence collected'),
  confidence: z.number().min(0).max(100).describe('Your confidence level (0-100)'),
  requiredCriteriaMet: z.array(z.string()).describe(
    'Which required criteria from the evidence criteria your evidence satisfies'
  ),
  supportingCriteriaMet: z.array(z.string()).optional().describe(
    'Which supporting criteria your evidence satisfies'
  ),
});

export type ValidateEvidenceInput = z.infer<typeof ValidateEvidenceSchema>;

/**
 * Result of evidence validation
 */
export interface ValidateEvidenceResult {
  valid: boolean;
  reason: string;
  minConfidence: number;
  yourConfidence: number;
  suggestions?: string[];
}

/**
 * Create the validate_evidence tool for a specific vulnerability class
 */
export function createValidateEvidenceTool(vulnClass: VulnerabilityClass) {
  const criteria = EVIDENCE_CRITERIA[vulnClass];

  return tool({
    description: `Validate that your evidence meets the criteria for ${vulnClass} vulnerabilities.

**REQUIRED before calling document_finding**

**Required evidence (at least one):**
${criteria.required.map((r, i) => `${i + 1}. ${r}`).join('\n')}

**NOT evidence:**
${criteria.notEvidence.map(n => `- ${n}`).join('\n')}

**Minimum confidence:** ${criteria.minConfidence}%`,
    inputSchema: ValidateEvidenceSchema,
    execute: async (params: ValidateEvidenceInput): Promise<ValidateEvidenceResult> => {
      const { evidence, confidence, requiredCriteriaMet, supportingCriteriaMet } = params;

      const issues: string[] = [];
      const suggestions: string[] = [];

      // Check confidence threshold
      if (confidence < criteria.minConfidence) {
        issues.push(
          `Confidence ${confidence}% is below minimum threshold ${criteria.minConfidence}%`
        );
        suggestions.push(
          `Gather more evidence to increase confidence to at least ${criteria.minConfidence}%`
        );
      }

      // Check required criteria
      if (!requiredCriteriaMet || requiredCriteriaMet.length === 0) {
        issues.push('No required criteria met');
        suggestions.push(
          `Your evidence must satisfy at least one of: ${criteria.required.join('; ')}`
        );
      }

      // Check for common "not evidence" patterns
      const evidenceLower = evidence.toLowerCase();
      for (const notEv of criteria.notEvidence) {
        const notEvLower = notEv.toLowerCase();
        // Simple keyword check
        const keywords = notEvLower.split(' ').filter(w => w.length > 4);
        const matchCount = keywords.filter(k => evidenceLower.includes(k)).length;
        if (matchCount >= 3) {
          suggestions.push(`Warning: Your evidence may fall under "${notEv}" - verify it's not a false positive`);
        }
      }

      const valid = confidence >= criteria.minConfidence && requiredCriteriaMet.length > 0;

      return {
        valid,
        reason: valid
          ? `Evidence meets criteria. Confidence ${confidence}% >= ${criteria.minConfidence}%. ${requiredCriteriaMet.length} required criteria met. You may document the finding.`
          : `Evidence insufficient: ${issues.join('. ')}`,
        minConfidence: criteria.minConfidence,
        yourConfidence: confidence,
        suggestions: suggestions.length > 0 ? suggestions : undefined,
      };
    },
  });
}

/**
 * Get evidence criteria prompt section for a vulnerability class
 */
export function getEvidenceCriteriaPrompt(vulnClass: VulnerabilityClass): string {
  const criteria = EVIDENCE_CRITERIA[vulnClass];

  return `
## STRICT Evidence Requirements for ${vulnClass.toUpperCase()}

**REQUIRED (at least one):**
${criteria.required.map((r, i) => `${i + 1}. ${r}`).join('\n')}

${criteria.supporting ? `**Supporting evidence (strengthens finding):**
${criteria.supporting.map(s => `- ${s}`).join('\n')}` : ''}

**NOT EVIDENCE:**
${criteria.notEvidence.map(n => `- ${n}`).join('\n')}

**Minimum confidence to document: ${criteria.minConfidence}%**

Before calling \`document_finding\`, you MUST:
1. Call \`validate_evidence\` with your evidence
2. Ensure it returns \`valid: true\`
3. Only then proceed to document the finding
`;
}
