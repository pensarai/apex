import type { VulnerabilityClass } from "./types";

export interface VerificationGuidance {
  highSignal: string[];    // Proves exploitation
  mediumSignal: string[];  // Strong evidence
  lowSignal: string[];     // Indicates vulnerability only
  failureIndicators: string[];
  principles: string[];
}

export const VERIFICATION_GUIDANCE: Record<string, VerificationGuidance> = {
  sql_injection: {
    highSignal: [
      "Extracted data visible in response (usernames, passwords, table contents)",
      "UNION SELECT results showing database columns",
      "Successful authentication bypass with SQL payload",
      "Out-of-band data exfiltration confirmed (DNS, HTTP callback with data)",
    ],
    mediumSignal: [
      "Consistent time delay on SLEEP/WAITFOR (>5s difference from baseline)",
      "Boolean-based response difference (true vs false conditions)",
      "Stacked query execution confirmed",
    ],
    lowSignal: [
      "SQL error messages in response",
      "Stack traces revealing database driver",
      "Query syntax reflected in error",
    ],
    failureIndicators: [
      "Parameterized query in error message",
      "Input sanitization visible (escaped quotes)",
      "WAF blocking response (403, challenge page)",
      "Type casting error (input converted to int)",
    ],
    principles: [
      "Data exfiltration > timing delays > error messages",
      "Error messages detect; extracted data proves exploitation",
    ],
  },

  nosql_injection: {
    highSignal: [
      "Extracted documents/records visible in response",
      "Authentication bypass confirmed (logged in as another user)",
      "Operator injection returning unintended data ($ne, $gt, $where)",
    ],
    mediumSignal: [
      "Boolean-based response differences with NoSQL operators",
      "JavaScript execution in $where clause (timing differences)",
      "Array injection changing query logic",
    ],
    lowSignal: [
      "MongoDB/NoSQL error messages",
      "JSON parsing errors with injected operators",
    ],
    failureIndicators: [
      "Input type validation (expecting string, got object)",
      "Schema validation errors",
      "Operator stripping visible",
    ],
    principles: [
      "Document extraction proves exploitation",
      "Operator injection with visible data change is high signal",
    ],
  },

  xss: {
    highSignal: [
      "JavaScript execution confirmed (alert fired, callback received)",
      "Cookie/session data exfiltrated to attacker server",
      "DOM manipulation observed (element created, content changed)",
      "Event handler executed (onerror, onload triggered)",
    ],
    mediumSignal: [
      "Payload rendered in executable context (inside script tag, event handler)",
      "CSP bypass achieved",
      "Encoding bypassed and payload unescaped in DOM",
    ],
    lowSignal: [
      "Payload reflected in response",
      "Payload stored and displayed",
      "Special characters not encoded",
    ],
    failureIndicators: [
      "HTML entity encoding applied (&lt; &gt;)",
      "CSP blocking inline scripts",
      "Sanitization removing script tags",
      "HttpOnly flag preventing cookie access",
    ],
    principles: [
      "Script execution > executable context > reflection",
      "Reflected payload without execution is detection, not exploitation",
    ],
  },

  command_injection: {
    highSignal: [
      "Command output visible in response (ls, whoami, id output)",
      "File created/modified on server (confirmed via subsequent request)",
      "Reverse shell connection established",
      "Out-of-band callback received (DNS, HTTP with command output)",
    ],
    mediumSignal: [
      "Time-based delay with sleep command (>5s difference)",
      "Different response when command succeeds vs fails",
      "Error messages showing shell interpretation",
    ],
    lowSignal: [
      "Shell metacharacters not escaped in error",
      "Command syntax visible in error message",
    ],
    failureIndicators: [
      "Input validation rejecting metacharacters",
      "Allowlist filtering commands",
      "Sandboxed execution environment",
      "Shell escaping applied",
    ],
    principles: [
      "Command output proves execution; timing is strong evidence",
      "Error messages only indicate potential, not exploitation",
    ],
  },

  ssti: {
    highSignal: [
      "Template expression evaluated ({{7*7}} = 49 in response)",
      "Server-side code execution (file read, command execution via template)",
      "Object traversal accessing sensitive data",
    ],
    mediumSignal: [
      "Template engine identified via specific syntax",
      "Different behavior with valid vs invalid template syntax",
      "Error messages revealing template context",
    ],
    lowSignal: [
      "Template syntax reflected without evaluation",
      "Generic template error messages",
    ],
    failureIndicators: [
      "Template syntax escaped/encoded",
      "Sandbox preventing dangerous operations",
      "Template engine not processing user input",
    ],
    principles: [
      "Expression evaluation proves SSTI; code execution proves RCE",
      "Template reflection without evaluation is not exploitable",
    ],
  },

  path_traversal: {
    highSignal: [
      "Sensitive file contents retrieved (/etc/passwd, web.config, .env)",
      "Application source code accessed",
      "File outside webroot read successfully",
    ],
    mediumSignal: [
      "Directory listing obtained",
      "Different error for existing vs non-existing files",
      "Path canonicalization bypass confirmed",
    ],
    lowSignal: [
      "Path traversal sequences visible in error",
      "File not found error with traversed path",
    ],
    failureIndicators: [
      "Path normalization removing ../",
      "Chroot/jail restricting access",
      "Allowlist of permitted files",
      "Realpath validation",
    ],
    principles: [
      "File content retrieval proves exploitation",
      "Error with traversed path only indicates potential vulnerability",
    ],
  },

  ssrf: {
    highSignal: [
      "Internal service response returned (metadata API, internal API)",
      "Out-of-band callback received from server",
      "Cloud metadata accessed (169.254.169.254)",
      "Internal port scan results visible",
    ],
    mediumSignal: [
      "Different response times for internal vs external hosts",
      "Error messages revealing internal network info",
      "Redirect followed to internal resource",
    ],
    lowSignal: [
      "URL parameter accepted without immediate error",
      "Generic connection error",
    ],
    failureIndicators: [
      "URL allowlist validation",
      "IP address blocklist (private ranges blocked)",
      "Protocol restriction (http only)",
      "DNS rebinding protection",
    ],
    principles: [
      "Internal resource access proves SSRF",
      "OOB callback confirms server-side request capability",
    ],
  },

  idor: {
    highSignal: [
      "Other user's data accessed (PII, private documents)",
      "Unauthorized action performed on another user's resource",
      "Admin-only resource accessed with regular user",
    ],
    mediumSignal: [
      "Different response for valid vs invalid IDs (confirms enumeration)",
      "Consistent pattern of accessible sequential IDs",
    ],
    lowSignal: [
      "HTTP 200 returned for different ID",
      "Object ID visible in response",
    ],
    failureIndicators: [
      "Authorization check present (403 for other user's resource)",
      "Session-bound resource access",
      "Rate limiting on enumeration",
    ],
    principles: [
      "Accessing another user's data proves IDOR",
      "HTTP 200 alone does not prove unauthorized access",
    ],
  },

  authentication_bypass: {
    highSignal: [
      "Authenticated session obtained without valid credentials",
      "Admin/privileged access obtained",
      "Password reset for arbitrary user completed",
      "MFA bypassed successfully",
    ],
    mediumSignal: [
      "Session token issued without full authentication",
      "Role/privilege escalation visible",
      "Account takeover flow completed",
    ],
    lowSignal: [
      "Login endpoint accepts unexpected input",
      "Error message reveals authentication logic",
    ],
    failureIndicators: [
      "Strong authentication required",
      "Brute force protection active",
      "Token validation failing",
    ],
    principles: [
      "Obtaining unauthorized access proves bypass",
      "Unusual behavior without access is not exploitation",
    ],
  },

  jwt_vulnerabilities: {
    highSignal: [
      "Forged token accepted (none algorithm, weak key)",
      "Privilege escalation via token manipulation",
      "Algorithm confusion attack successful",
    ],
    mediumSignal: [
      "Signature not verified (modified payload accepted)",
      "Key confusion exploited",
      "Token with expired timestamp accepted",
    ],
    lowSignal: [
      "JWT structure exposed",
      "Weak algorithm detected (HS256 with guessable key)",
    ],
    failureIndicators: [
      "Signature validation failing",
      "Algorithm allowlist enforced",
      "Token expiry checked",
    ],
    principles: [
      "Forged token acceptance proves vulnerability",
      "Weak algorithm without key recovery is not exploitable",
    ],
  },

  deserialization: {
    highSignal: [
      "Remote code execution achieved via gadget chain",
      "Server-side object instantiation controlled",
      "Out-of-band callback from deserialization payload",
    ],
    mediumSignal: [
      "Exception revealing deserialization of controlled class",
      "Object type confusion achieved",
      "Denial of service via deserialization bomb",
    ],
    lowSignal: [
      "Serialized data accepted by endpoint",
      "Deserialization error messages",
    ],
    failureIndicators: [
      "Type allowlist enforced",
      "Signed/encrypted serialized data required",
      "Deserialization disabled",
    ],
    principles: [
      "Code execution proves exploitation",
      "Gadget chain completion with visible effect is required",
    ],
  },

  xxe: {
    highSignal: [
      "Local file contents exfiltrated via entity",
      "SSRF via external entity (internal resource accessed)",
      "Out-of-band data exfiltration (DNS, HTTP)",
    ],
    mediumSignal: [
      "External entity loaded (DTD fetch confirmed)",
      "Parameter entity processed",
      "Error-based file disclosure",
    ],
    lowSignal: [
      "XML parsed without entity expansion error",
      "DTD declaration accepted",
    ],
    failureIndicators: [
      "External entities disabled",
      "DTD processing disabled",
      "Entity expansion limits",
    ],
    principles: [
      "File or SSRF access proves XXE exploitation",
      "Entity parsing without data access is potential only",
    ],
  },

  crypto: {
    highSignal: [
      "Plaintext recovered from ciphertext",
      "Valid signature forged",
      "Key material extracted",
      "Encryption bypassed entirely",
    ],
    mediumSignal: [
      "Padding oracle confirmed (different errors for padding)",
      "Timing side-channel measurable",
      "Weak key/IV detected and exploitable",
    ],
    lowSignal: [
      "Weak algorithm identified",
      "Short key length detected",
    ],
    failureIndicators: [
      "Strong algorithms in use",
      "Proper key derivation",
      "Constant-time comparison",
    ],
    principles: [
      "Plaintext recovery or signature forgery proves exploitation",
      "Weak algorithm alone needs demonstrated impact",
    ],
  },

  business_logic: {
    highSignal: [
      "Unauthorized transaction completed",
      "Price/quantity manipulation achieved",
      "Access control bypassed via workflow abuse",
      "Race condition exploited with visible impact",
    ],
    mediumSignal: [
      "State manipulation possible",
      "Workflow steps skippable",
      "Inconsistent validation between steps",
    ],
    lowSignal: [
      "Unusual workflow accepted",
      "Edge case behavior observed",
    ],
    failureIndicators: [
      "Transaction validation at each step",
      "Idempotency keys preventing replay",
      "Strong state machine enforcement",
    ],
    principles: [
      "Tangible unauthorized outcome proves business logic flaw",
      "Unusual behavior needs demonstrated business impact",
    ],
  },

  generic: {
    highSignal: [
      "Unauthorized data access confirmed",
      "Code/command execution achieved",
      "Security control bypassed with impact",
    ],
    mediumSignal: [
      "Consistent anomalous behavior reproducible",
      "Security control weakness demonstrated",
    ],
    lowSignal: [
      "Unexpected error messages",
      "Information disclosure without sensitivity",
    ],
    failureIndicators: [
      "Security controls functioning",
      "Expected error handling",
      "Input validation working",
    ],
    principles: [
      "Demonstrated impact proves vulnerability",
      "Anomalous behavior needs concrete security impact",
    ],
  },
};

export function buildVerificationPrompt(vulnClass: string): string {
  const guidance = VERIFICATION_GUIDANCE[vulnClass];
  if (!guidance) {
    // Fall back to generic if unknown class
    return buildVerificationPrompt("generic");
  }

  return `
## Verification Criteria Guidance for ${vulnClass.replace(/_/g, " ").toUpperCase()}

Prioritize indicators by signal quality when writing verification criteria:

### HIGH Signal (proves exploitation) - PRIORITIZE THESE:
${guidance.highSignal.map(i => `- ${i}`).join('\n')}

### MEDIUM Signal (strong evidence):
${guidance.mediumSignal.map(i => `- ${i}`).join('\n')}

### LOW Signal (detection only - use sparingly):
${guidance.lowSignal.map(i => `- ${i}`).join('\n')}

### Failure Indicators (rules out vulnerability):
${guidance.failureIndicators.map(i => `- ${i}`).join('\n')}

**Key Principles**: ${guidance.principles.join(' | ')}

When writing verification criteria:
1. Prioritize HIGH signal indicators - they prove exploitation
2. Use MEDIUM signal when HIGH signal isn't achievable
3. LOW signal indicators only detect potential; use sparingly
4. Include failure indicators to identify false positives
`;
}
