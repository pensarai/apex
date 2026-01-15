/**
 * Example Agent Plugin: CORS Misconfiguration Tester
 * 
 * This plugin demonstrates how to create an agent plugin that
 * performs specialized security testing.
 */

import { z } from 'zod';
import {
  createAgentPlugin,
  type AgentInput,
  type AgentPluginContext,
  type AgentResult,
} from '../index';

/**
 * CORS test payloads
 */
const CORS_TEST_ORIGINS = [
  'https://evil.com',
  'https://attacker.com',
  'null',
  'https://example.com.evil.com',
  'https://exampleXcom', // Subdomain bypass attempt
];

/**
 * CORS test result
 */
interface CorsTestResult {
  origin: string;
  reflected: boolean;
  allowCredentials: boolean;
  allowedMethods: string[];
  allowedHeaders: string[];
  vulnerable: boolean;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  details: string;
}

/**
 * Test CORS configuration for a single origin
 */
async function testOrigin(
  url: string,
  origin: string,
  context: AgentPluginContext
): Promise<CorsTestResult> {
  context.log(`Testing CORS with origin: ${origin}`);

  const response = await fetch(url, {
    method: 'OPTIONS',
    headers: {
      Origin: origin,
      'Access-Control-Request-Method': 'GET',
      'Access-Control-Request-Headers': 'Content-Type, Authorization',
    },
  });

  const corsOrigin = response.headers.get('Access-Control-Allow-Origin');
  const corsCredentials = response.headers.get('Access-Control-Allow-Credentials');
  const corsMethods = response.headers.get('Access-Control-Allow-Methods');
  const corsHeaders = response.headers.get('Access-Control-Allow-Headers');

  const reflected = corsOrigin === origin || corsOrigin === '*';
  const allowCredentials = corsCredentials?.toLowerCase() === 'true';

  let vulnerable = false;
  let severity: CorsTestResult['severity'] = 'info';
  let details = '';

  // Check for vulnerabilities
  if (reflected && corsOrigin === '*') {
    vulnerable = true;
    severity = allowCredentials ? 'critical' : 'medium';
    details = 'Wildcard (*) origin allowed' + (allowCredentials ? ' with credentials' : '');
  } else if (reflected && origin !== 'null') {
    vulnerable = true;
    if (allowCredentials) {
      severity = 'critical';
      details = `Arbitrary origin ${origin} reflected with credentials allowed`;
    } else {
      severity = 'high';
      details = `Arbitrary origin ${origin} reflected`;
    }
  } else if (reflected && origin === 'null') {
    vulnerable = true;
    severity = allowCredentials ? 'high' : 'medium';
    details = 'Null origin allowed' + (allowCredentials ? ' with credentials' : '');
  }

  return {
    origin,
    reflected,
    allowCredentials,
    allowedMethods: corsMethods?.split(',').map(m => m.trim()) || [],
    allowedHeaders: corsHeaders?.split(',').map(h => h.trim()) || [],
    vulnerable,
    severity,
    details,
  };
}

/**
 * Run the CORS tester agent
 */
async function runCorsTester(
  input: AgentInput,
  context: AgentPluginContext
): Promise<AgentResult> {
  const { target, objective } = input;
  const customOrigins = input.params?.origins || [];
  const allOrigins = [...CORS_TEST_ORIGINS, ...customOrigins];

  context.log(`Starting CORS misconfiguration test on ${target}`);
  context.log(`Testing ${allOrigins.length} origin payloads`);

  const results: CorsTestResult[] = [];
  const findings: Array<{
    title: string;
    severity: string;
    description: string;
    evidence: string;
  }> = [];

  for (const origin of allOrigins) {
    try {
      const result = await testOrigin(target, origin, context);
      results.push(result);

      if (result.vulnerable) {
        findings.push({
          title: `CORS Misconfiguration - ${result.severity.toUpperCase()}`,
          severity: result.severity,
          description: result.details,
          evidence: `Origin: ${origin}, Reflected: ${result.reflected}, Credentials: ${result.allowCredentials}`,
        });

        // Document finding if document_finding tool is available
        if (context.tools.document_finding) {
          await context.tools.document_finding.execute({
            title: `CORS Misconfiguration`,
            vulnerability_type: 'cors_misconfiguration',
            severity: result.severity,
            description: result.details,
            evidence: JSON.stringify(result, null, 2),
            target,
          });
        }
      }
    } catch (error: any) {
      context.log(`Error testing origin ${origin}: ${error.message}`, 'error');
    }
  }

  // Generate summary
  const vulnerableCount = results.filter(r => r.vulnerable).length;
  const criticalCount = findings.filter(f => f.severity === 'critical').length;
  const highCount = findings.filter(f => f.severity === 'high').length;

  let summary = `CORS Misconfiguration Test Complete\n`;
  summary += `Target: ${target}\n`;
  summary += `Origins Tested: ${results.length}\n`;
  summary += `Vulnerable: ${vulnerableCount}\n`;
  summary += `Critical Findings: ${criticalCount}\n`;
  summary += `High Findings: ${highCount}\n`;

  if (findings.length > 0) {
    summary += `\nFindings:\n`;
    for (const finding of findings) {
      summary += `- [${finding.severity.toUpperCase()}] ${finding.title}: ${finding.description}\n`;
    }
  }

  return {
    success: true,
    findingsCount: findings.length,
    summary,
    data: {
      results,
      findings,
    },
  };
}

/**
 * CORS Tester Agent Plugin
 */
export const corsTesterPlugin = createAgentPlugin({
  metadata: {
    id: 'pensar-cors-tester',
    name: 'CORS Misconfiguration Tester',
    version: '1.0.0',
    description: 'Specialized agent for testing CORS misconfigurations',
    author: 'Pensar',
    tags: ['security', 'cors', 'web'],
  },
  agents: {
    cors_tester: {
      description: `Tests a target URL for CORS (Cross-Origin Resource Sharing) misconfigurations.
Checks for:
- Wildcard origins (*)
- Arbitrary origin reflection
- Null origin acceptance
- Credentials exposure
Returns findings with severity ratings.`,
      vulnerabilityClasses: ['cors_misconfiguration' as any],
      execute: runCorsTester,
    },
  },
});

export default corsTesterPlugin;
