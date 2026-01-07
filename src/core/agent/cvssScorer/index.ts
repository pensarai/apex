/**
 * CVSS 4.0 Scorer Subagent
 *
 * A specialized agent that analyzes vulnerability findings and their discovery context
 * to determine appropriate CVSS 4.0 metrics and calculate scores.
 *
 * This agent is spawned by the document_finding tool to provide standardized
 * severity scoring based on the CVSS 4.0 specification.
 */

import { z } from 'zod';
import { generateObjectResponse, type AIModel } from '../../ai';
import {
  calculateCVSS4Score,
  type CVSS4Metrics,
  type CVSS4Score,
} from '../../../lib/cvss';

// =============================================================================
// Types
// =============================================================================

export interface CVSSScorerInput {
  /** The finding to score */
  finding: {
    title: string;
    description: string;
    impact: string;
    evidence: string;
    endpoint: string;
    vulnerabilityClass?: string;
    remediation?: string;
  };
  /** Messages from the meta testing agent's conversation (for context) */
  agentMessages: any[];
}

export interface CVSSScorerResult {
  /** Numeric score (0.0-10.0) */
  score: number;
  /** Qualitative severity (NONE, LOW, MEDIUM, HIGH, CRITICAL) */
  severity: string;
  /** Full vector string (CVSS:4.0/AV:N/...) */
  vectorString: string;
  /** Individual metric values */
  metrics: CVSS4Metrics;
  /** Score type (CVSS-B, CVSS-BT, etc.) */
  scoreType: string;
  /** AI's reasoning for metric choices */
  reasoning: string;
}

// =============================================================================
// Schema for AI Output
// =============================================================================

const CVSSMetricsOutputSchema = z.object({
  metrics: z.object({
    // Base Metrics - Exploitability
    AV: z.enum(['N', 'A', 'L', 'P']).describe(
      'Attack Vector: N=Network (remotely exploitable), A=Adjacent network, L=Local access required, P=Physical access required'
    ),
    AC: z.enum(['L', 'H']).describe(
      'Attack Complexity: L=Low (no special conditions), H=High (requires specific conditions/bypassing)'
    ),
    AT: z.enum(['N', 'P']).describe(
      'Attack Requirements: N=None (works in most configs), P=Present (requires race conditions/specific setup)'
    ),
    PR: z.enum(['N', 'L', 'H']).describe(
      'Privileges Required: N=None (unauthenticated), L=Low (basic user), H=High (admin)'
    ),
    UI: z.enum(['N', 'P', 'A']).describe(
      'User Interaction: N=None, P=Passive (user visits page), A=Active (user must click/interact)'
    ),

    // Base Metrics - Vulnerable System Impact
    VC: z.enum(['H', 'L', 'N']).describe(
      'Confidentiality Impact on Vulnerable System: H=High (total loss), L=Low (partial), N=None'
    ),
    VI: z.enum(['H', 'L', 'N']).describe(
      'Integrity Impact on Vulnerable System: H=High (total loss), L=Low (partial), N=None'
    ),
    VA: z.enum(['H', 'L', 'N']).describe(
      'Availability Impact on Vulnerable System: H=High (total loss), L=Low (partial), N=None'
    ),

    // Base Metrics - Subsequent System Impact
    SC: z.enum(['H', 'L', 'N']).describe(
      'Confidentiality Impact on Subsequent Systems: H=High, L=Low, N=None (no pivoting)'
    ),
    SI: z.enum(['H', 'L', 'N']).describe(
      'Integrity Impact on Subsequent Systems: H=High, L=Low, N=None'
    ),
    SA: z.enum(['H', 'L', 'N']).describe(
      'Availability Impact on Subsequent Systems: H=High, L=Low, N=None'
    ),

    // Threat Metric
    E: z.enum(['A', 'P', 'U']).describe(
      'Exploit Maturity: A=Attacked (working exploit exists), P=POC available, U=Unreported'
    ),
  }),
  reasoning: z.string().describe(
    'Brief explanation (2-3 sentences) of the key factors that influenced the metric choices'
  ),
});

type CVSSMetricsOutput = z.infer<typeof CVSSMetricsOutputSchema>;

// =============================================================================
// System Prompt
// =============================================================================

const CVSS_SCORER_SYSTEM_PROMPT = `You are a CVSS 4.0 scoring specialist. Your task is to analyze vulnerability findings and determine the appropriate CVSS 4.0 Base metrics.

## CVSS 4.0 Metrics Guide

### Attack Vector (AV)
- **N (Network)**: Remotely exploitable over the internet (web app vulns, network services)
- **A (Adjacent)**: Requires shared physical or logical network (same WiFi, VLAN)
- **L (Local)**: Requires local access or user interaction to deliver payload
- **P (Physical)**: Requires physical hardware access

### Attack Complexity (AC)
- **L (Low)**: No special preparation needed, works reliably
- **H (High)**: Requires race conditions, bypassing defenses, or specific configurations

### Attack Requirements (AT)
- **N (None)**: Works under normal conditions
- **P (Present)**: Requires specific deployment conditions (race window, man-in-the-middle position)

### Privileges Required (PR)
- **N (None)**: Unauthenticated attack
- **L (Low)**: Requires basic user-level privileges
- **H (High)**: Requires administrative/root privileges

### User Interaction (UI)
- **N (None)**: No user action required
- **P (Passive)**: User visits a page, opens a file, or is on a vulnerable session
- **A (Active)**: User must click a link, dismiss warnings, or actively interact

### Confidentiality Impact (VC - Vulnerable System, SC - Subsequent Systems)
- **H (High)**: Complete loss of confidentiality (full data access, credential theft)
- **L (Low)**: Limited data exposure (some info leak but not critical)
- **N (None)**: No confidentiality impact

### Integrity Impact (VI - Vulnerable System, SI - Subsequent Systems)
- **H (High)**: Complete loss of integrity (arbitrary modification, code execution)
- **L (Low)**: Limited modification capability
- **N (None)**: No integrity impact

### Availability Impact (VA - Vulnerable System, SA - Subsequent Systems)
- **H (High)**: Complete denial of service
- **L (Low)**: Reduced performance or intermittent availability
- **N (None)**: No availability impact

### Exploit Maturity (E)
- **A (Attacked)**: Working exploit exists (POC confirmed vulnerability)
- **P (POC)**: Proof-of-concept code exists but may not be weaponized
- **U (Unreported)**: No known public exploit

## Vulnerability Class Guidelines

### SQL Injection (sqli)
- Typically: AV:N, AC:L, AT:N, PR varies, UI:N
- VC:H (data access), VI:H (data modification), VA:L-H (depending on impact)
- SC/SI/SA: Usually N unless database is shared

### Cross-Site Scripting (xss)
- Reflected: AV:N, AC:L, AT:N, PR:N, UI:A (user must click)
- Stored: AV:N, AC:L, AT:N, PR varies, UI:P (user visits page)
- VC:L (session theft), VI:L (DOM modification), VA:N
- SC/SI/SA: Usually N (client-side only)

### Command Injection / RCE
- Typically: AV:N, AC:L, AT:N, PR varies, UI:N
- VC:H, VI:H, VA:H (complete system compromise)
- SC/SI/SA: Potentially H if can pivot

### IDOR / Access Control
- Typically: AV:N, AC:L, AT:N, PR:L (needs some access), UI:N
- Impact varies based on what data is accessed

### SSRF
- Typically: AV:N, AC:L, AT:N, PR varies, UI:N
- VC on vulnerable: L-N, SC on subsequent: H (internal network access)

### Path Traversal / LFI
- Typically: AV:N, AC:L, AT:N, PR varies, UI:N
- VC:H (file read), VI:N (unless write), VA:N

## Analysis Instructions

1. Read the finding description and evidence carefully
2. Consider the attack vector based on how the vulnerability was exploited
3. Assess complexity based on whether special conditions were needed
4. Determine privileges based on authentication requirements
5. Evaluate user interaction based on exploit mechanics
6. Assess impact on both the vulnerable system AND potential subsequent systems
7. Since a POC exists and confirmed the vulnerability, E should typically be 'A'

Always provide brief reasoning explaining your key decisions.`;

// =============================================================================
// Main Function
// =============================================================================

/**
 * Score a vulnerability finding with CVSS 4.0
 *
 * @param input - The finding data and conversation context
 * @param model - The AI model to use for scoring
 * @returns The CVSS 4.0 score with reasoning
 */
export async function scoreFindingWithCVSS(
  input: CVSSScorerInput,
  model: AIModel
): Promise<CVSSScorerResult> {
  const prompt = buildScoringPrompt(input);

  // Generate structured CVSS metrics using AI
  const assessment = await generateObjectResponse({
    model,
    schema: CVSSMetricsOutputSchema,
    prompt,
    system: CVSS_SCORER_SYSTEM_PROMPT,
  });

  // Calculate final score using the CVSS calculator
  const cvssResult = calculateCVSS4Score({
    ...assessment.metrics,
  });

  return {
    score: cvssResult.score,
    severity: cvssResult.severity,
    vectorString: cvssResult.vectorString,
    metrics: cvssResult.metrics,
    scoreType: cvssResult.scoreType,
    reasoning: assessment.reasoning,
  };
}

/**
 * Build the scoring prompt from finding data and context
 */
function buildScoringPrompt(input: CVSSScorerInput): string {
  const { finding, agentMessages } = input;

  let prompt = `# Vulnerability Finding to Score

## Finding Details

**Title:** ${finding.title}
**Vulnerability Class:** ${finding.vulnerabilityClass || 'Unknown'}
**Endpoint:** ${finding.endpoint}

### Description
${finding.description}

### Impact Assessment
${finding.impact}

### Evidence (POC Output)
\`\`\`
${finding.evidence}
\`\`\`

`;

  // Add context from agent conversation if available
  if (agentMessages && agentMessages.length > 0) {
    prompt += `## Discovery Context

The following is a summary of how this vulnerability was discovered (from the testing agent's conversation):

`;
    // Extract relevant context from messages
    const contextSummary = extractContextSummary(agentMessages);
    prompt += contextSummary;
  }

  prompt += `
## Task

Analyze this vulnerability finding and determine the appropriate CVSS 4.0 metrics.

Consider:
1. How the vulnerability is exploited (attack vector, complexity, requirements)
2. What privileges/authentication were needed
3. Whether user interaction is required
4. The actual impact demonstrated in the evidence
5. Potential for lateral movement or subsequent system compromise

Provide your metrics assessment and brief reasoning.
`;

  return prompt;
}

/**
 * Extract relevant context from agent conversation messages
 */
function extractContextSummary(messages: any[]): string {
  const contextParts: string[] = [];
  let foundToolCalls = 0;
  const maxToolCalls = 5; // Limit context size

  for (const message of messages) {
    if (foundToolCalls >= maxToolCalls) break;

    // Extract assistant reasoning
    if (message.role === 'assistant' && typeof message.content === 'string') {
      // Look for hypothesis/validation blocks
      const hypothesisMatch = message.content.match(/HYPOTHESIS:[\s\S]*?(?=VALIDATION:|$)/);
      const validationMatch = message.content.match(/VALIDATION:[\s\S]*?(?=HYPOTHESIS:|$)/);

      if (hypothesisMatch) {
        contextParts.push(`- ${hypothesisMatch[0].substring(0, 300)}...`);
      }
      if (validationMatch) {
        contextParts.push(`- ${validationMatch[0].substring(0, 300)}...`);
      }
    }

    // Extract tool call descriptions
    if (message.role === 'assistant' && Array.isArray(message.content)) {
      for (const part of message.content) {
        if (part.type === 'tool-call' && part.toolName) {
          const desc = part.input?.toolCallDescription || `Used ${part.toolName}`;
          contextParts.push(`- Tool: ${desc}`);
          foundToolCalls++;
        }
      }
    }
  }

  if (contextParts.length === 0) {
    return 'No additional context available from testing conversation.\n';
  }

  return contextParts.join('\n') + '\n';
}

// =============================================================================
// Default Model
// =============================================================================

/** Default model for CVSS scoring (fast and cost-effective) */
export const DEFAULT_CVSS_MODEL: AIModel = 'claude-4-5-haiku';
