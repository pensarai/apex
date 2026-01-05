/**
 * Vulnerability-specific prompt exports and mapping
 */

import { BASE_TESTING_PROMPT, OUTCOME_GUIDANCE_TEMPLATE } from './base';
import { SQLI_TESTING_PROMPT } from './sqli';
import { IDOR_TESTING_PROMPT } from './idor';
import { XSS_TESTING_PROMPT } from './xss';
import { COMMAND_INJECTION_TESTING_PROMPT } from './command-injection';
import { LFI_TESTING_PROMPT } from './lfi';
import { SSRF_TESTING_PROMPT } from './ssrf';
import { CRYPTO_TESTING_PROMPT } from './crypto';
import { CVE_TESTING_PROMPT } from './cve';
import { GENERIC_TESTING_PROMPT } from './generic';
import type { VulnerabilityClass } from '../types';

// Re-export individual prompts
export { BASE_TESTING_PROMPT, OUTCOME_GUIDANCE_TEMPLATE } from './base';
export { SQLI_TESTING_PROMPT } from './sqli';
export { IDOR_TESTING_PROMPT } from './idor';
export { XSS_TESTING_PROMPT } from './xss';
export { COMMAND_INJECTION_TESTING_PROMPT } from './command-injection';
export { LFI_TESTING_PROMPT } from './lfi';
export { SSRF_TESTING_PROMPT } from './ssrf';
export { CRYPTO_TESTING_PROMPT } from './crypto';
export { CVE_TESTING_PROMPT } from './cve';
export { GENERIC_TESTING_PROMPT } from './generic';

/**
 * Map vulnerability class to specialized testing prompt
 */
const VULNERABILITY_PROMPT_MAP: Record<VulnerabilityClass, string> = {
  'sqli': SQLI_TESTING_PROMPT,
  'idor': IDOR_TESTING_PROMPT,
  'xss': XSS_TESTING_PROMPT,
  'command-injection': COMMAND_INJECTION_TESTING_PROMPT,
  'lfi': LFI_TESTING_PROMPT,
  'ssrf': SSRF_TESTING_PROMPT,
  'crypto': CRYPTO_TESTING_PROMPT,
  'cve': CVE_TESTING_PROMPT,
  'generic': GENERIC_TESTING_PROMPT,
};

/**
 * Get the testing methodology prompt for a vulnerability class
 */
export function getVulnerabilityPrompt(vulnClass: VulnerabilityClass): string {
  return VULNERABILITY_PROMPT_MAP[vulnClass] || GENERIC_TESTING_PROMPT;
}

/**
 * Build complete system prompt for VulnerabilityTestAgent
 */
export function buildSystemPrompt(
  vulnClass: VulnerabilityClass,
  outcomeGuidance: string
): string {
  const vulnerabilityPrompt = getVulnerabilityPrompt(vulnClass);
  const outcomeSection = OUTCOME_GUIDANCE_TEMPLATE.replace(
    '{{OUTCOME_GUIDANCE}}',
    outcomeGuidance
  );

  return `${BASE_TESTING_PROMPT}

---

${vulnerabilityPrompt}

---

${outcomeSection}
`;
}

/**
 * Get human-readable name for vulnerability class
 */
export function getVulnerabilityClassName(vulnClass: VulnerabilityClass): string {
  const names: Record<VulnerabilityClass, string> = {
    'sqli': 'SQL/NoSQL Injection',
    'idor': 'IDOR/Authorization',
    'xss': 'Cross-Site Scripting (XSS)',
    'command-injection': 'Command Injection',
    'lfi': 'Local File Inclusion (LFI)',
    'ssrf': 'Server-Side Request Forgery (SSRF)',
    'crypto': 'Cryptographic Vulnerabilities',
    'cve': 'Known CVE Exploitation',
    'generic': 'Generic Vulnerabilities',
  };
  return names[vulnClass] || vulnClass;
}

/**
 * Infer vulnerability classes from an objective string
 */
export function inferVulnerabilityClasses(objective: string): VulnerabilityClass[] {
  const lower = objective.toLowerCase();
  const classes: VulnerabilityClass[] = [];

  // SQL/NoSQL Injection
  if (
    lower.includes('sql') ||
    lower.includes('injection') ||
    lower.includes('database') ||
    lower.includes('nosql') ||
    lower.includes('mongodb')
  ) {
    classes.push('sqli');
  }

  // IDOR/Authorization
  if (
    lower.includes('auth') ||
    lower.includes('idor') ||
    lower.includes('access') ||
    lower.includes('authorization') ||
    lower.includes('privilege') ||
    lower.includes('escalation')
  ) {
    classes.push('idor');
  }

  // XSS
  if (
    lower.includes('xss') ||
    lower.includes('script') ||
    lower.includes('cross-site') ||
    lower.includes('cross site')
  ) {
    classes.push('xss');
  }

  // Command Injection
  if (
    lower.includes('command') ||
    lower.includes('rce') ||
    lower.includes('shell') ||
    lower.includes('code execution')
  ) {
    classes.push('command-injection');
  }

  // LFI / Path Traversal
  if (
    lower.includes('lfi') ||
    lower.includes('local file') ||
    lower.includes('file inclusion') ||
    lower.includes('path traversal') ||
    lower.includes('directory traversal') ||
    lower.includes('file read') ||
    lower.includes('arbitrary file')
  ) {
    classes.push('lfi');
  }

  // SSRF (Server-Side Request Forgery)
  if (
    lower.includes('ssrf') ||
    lower.includes('server-side request') ||
    lower.includes('server side request') ||
    lower.includes('url parameter') ||
    lower.includes('url=') ||
    lower.includes('fetch url') ||
    lower.includes('internal service') ||
    lower.includes('internal network') ||
    lower.includes('metadata endpoint') ||
    lower.includes('cloud metadata') ||
    lower.includes('redirect parameter') ||
    lower.includes('callback url') ||
    lower.includes('webhook') ||
    lower.includes('url fetching') ||
    lower.includes('server-side fetch')
  ) {
    classes.push('ssrf');
  }

  // Generic (XXE, SSTI, CSRF)
  if (
    lower.includes('xxe') ||
    lower.includes('ssti') ||
    lower.includes('csrf') ||
    lower.includes('template injection') ||
    lower.includes('xml external')
  ) {
    classes.push('generic');
  }

  // Cryptographic vulnerabilities
  if (
    lower.includes('crypto') ||
    lower.includes('encrypt') ||
    lower.includes('decrypt') ||
    lower.includes('cipher') ||
    lower.includes('aes') ||
    lower.includes('cbc') ||
    lower.includes('ecb') ||
    lower.includes('padding oracle') ||
    lower.includes('bit-flip') ||
    lower.includes('bitflip') ||
    lower.includes('malleab') ||  // malleable, malleability
    lower.includes('forge') ||
    lower.includes('session cookie') ||
    lower.includes('weak encryption') ||
    lower.includes('iv reuse') ||
    lower.includes('nonce reuse')
  ) {
    classes.push('crypto');
  }

  // Known CVE Exploitation
  // Detect explicit CVE mentions and exploit-related keywords
  if (
    lower.includes('cve') ||
    lower.includes('known vulnerability') ||
    lower.includes('known exploit') ||
    lower.includes('nuclei') ||
    /cve-\d{4}-\d+/i.test(objective)  // CVE ID pattern (e.g., CVE-2021-41773)
  ) {
    classes.push('cve');
  }

  // If no specific classes detected, return all for comprehensive testing
  if (classes.length === 0) {
    return ['sqli', 'idor', 'xss', 'command-injection', 'lfi', 'ssrf', 'crypto', 'cve', 'generic'];
  }

  return classes;
}
