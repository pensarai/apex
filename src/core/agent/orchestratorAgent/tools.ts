/**
 * Orchestrator Agent Tools
 *
 * Tools for the LLM-based orchestrator agent.
 */

import { tool } from 'ai';
import { z } from 'zod';
import { join } from 'path';
import { writeFileSync } from 'fs';
import type { Session } from '../../session';
import type { TestPlan, TestPlanEntry } from './types';

/**
 * Schema for test plan entries
 */
const TestPlanEntrySchema = z.object({
  target: z.string().describe('Target URL or endpoint to test'),
  objective: z.string().describe('Specific objective for this test'),
  vulnClass: z.enum([
    'sqli',
    'idor',
    'xss',
    'command-injection',
    'lfi',
    'ssrf',
    'crypto',
    'cve',
    'generic',
  ]).describe('Vulnerability class to test for'),
  authNeeded: z.boolean().describe('Whether authentication is required for this test'),
  authInfo: z.object({
    method: z.string().describe('Authentication method'),
    details: z.string().describe('How to authenticate'),
    credentials: z.string().optional().describe('Credentials if available'),
    cookies: z.string().optional().describe('Session cookies if available'),
    headers: z.string().optional().describe('Auth headers if available'),
  }).optional().describe('Authentication information if authNeeded is true'),
  priority: z.enum(['critical', 'high', 'medium', 'low']).describe('Priority level for this test'),
  rationale: z.string().describe('Explanation of why this vuln class applies to this target'),
});

/**
 * Create the test plan tool
 */
export function createTestPlanTool(session: Session.SessionInfo) {
  return tool({
    description: `Create the final test plan for penetration testing.

Call this after analyzing all attack surface data.
Each entry represents one (target, vulnClass) pair to test.

**Required for each entry:**
- target: The URL/endpoint to test
- objective: What to test for specifically
- vulnClass: Which vulnerability class (sqli, idor, xss, etc.)
- authNeeded: Whether auth is required (must be true or false, not undefined)
- authInfo: If authNeeded=true, provide auth details
- priority: critical, high, medium, or low
- rationale: WHY you think this vuln class applies (not just keywords)`,
    inputSchema: z.object({
      tests: z.array(TestPlanEntrySchema).describe('List of tests to run'),
      reasoning: z.string().describe('Overall reasoning for the test plan'),
    }),
    execute: async (plan: { tests: TestPlanEntry[]; reasoning: string }) => {
      const testPlan: TestPlan = {
        tests: plan.tests,
        reasoning: plan.reasoning,
        createdAt: new Date().toISOString(),
      };

      // Save test plan to session directory
      const planPath = join(session.rootPath, 'test-plan.json');
      writeFileSync(planPath, JSON.stringify(testPlan, null, 2));

      // Validate auth consistency
      const authIssues: string[] = [];
      for (const test of plan.tests) {
        if (test.authNeeded && !test.authInfo) {
          authIssues.push(`${test.target} (${test.vulnClass}): authNeeded=true but no authInfo provided`);
        }
      }

      // Group by priority
      const byPriority = {
        critical: plan.tests.filter(t => t.priority === 'critical').length,
        high: plan.tests.filter(t => t.priority === 'high').length,
        medium: plan.tests.filter(t => t.priority === 'medium').length,
        low: plan.tests.filter(t => t.priority === 'low').length,
      };

      // Group by vuln class
      const byVulnClass: Record<string, number> = {};
      for (const test of plan.tests) {
        byVulnClass[test.vulnClass] = (byVulnClass[test.vulnClass] || 0) + 1;
      }

      return {
        success: true,
        testsCount: plan.tests.length,
        savedTo: planPath,
        summary: {
          byPriority,
          byVulnClass,
          authRequired: plan.tests.filter(t => t.authNeeded).length,
        },
        warnings: authIssues.length > 0 ? authIssues : undefined,
        message: `Test plan created with ${plan.tests.length} tests (${byPriority.critical} critical, ${byPriority.high} high, ${byPriority.medium} medium, ${byPriority.low} low)`,
      };
    },
  });
}

/**
 * Create a tool for analyzing a specific target in detail
 */
export function createAnalyzeTargetTool() {
  return tool({
    description: `Analyze a specific target in more detail to determine vulnerability classes.

Use this if you need more information about a target before adding it to the test plan.`,
    inputSchema: z.object({
      target: z.string().describe('Target URL to analyze'),
      questions: z.array(z.string()).describe('Specific questions about this target'),
    }),
    execute: async (params: { target: string; questions: string[] }) => {
      // This is a helper tool for the agent to structure its thinking
      // In practice, the agent should use the attack surface results
      return {
        target: params.target,
        note: 'Use the attack surface results to answer these questions. This tool helps structure your analysis.',
        questions: params.questions,
      };
    },
  });
}
