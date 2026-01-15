/**
 * Example Tool Plugin: HTTP Header Security Scanner
 * 
 * This plugin demonstrates how to create a tool plugin that adds
 * custom security testing tools to Pensar.
 */

import { z } from 'zod';
import { createToolPlugin, type ToolPluginContext } from '../index';

/**
 * Security headers to check
 */
const SECURITY_HEADERS = {
  'Strict-Transport-Security': {
    description: 'HSTS - Forces HTTPS connections',
    recommended: 'max-age=31536000; includeSubDomains; preload',
    severity: 'medium',
  },
  'Content-Security-Policy': {
    description: 'CSP - Controls resource loading',
    recommended: "default-src 'self'",
    severity: 'high',
  },
  'X-Content-Type-Options': {
    description: 'Prevents MIME type sniffing',
    recommended: 'nosniff',
    severity: 'low',
  },
  'X-Frame-Options': {
    description: 'Prevents clickjacking',
    recommended: 'DENY',
    severity: 'medium',
  },
  'X-XSS-Protection': {
    description: 'XSS filter (legacy)',
    recommended: '1; mode=block',
    severity: 'low',
  },
  'Referrer-Policy': {
    description: 'Controls referrer information',
    recommended: 'strict-origin-when-cross-origin',
    severity: 'low',
  },
  'Permissions-Policy': {
    description: 'Controls browser features',
    recommended: 'geolocation=(), microphone=(), camera=()',
    severity: 'low',
  },
};

/**
 * Header scan result
 */
interface HeaderScanResult {
  url: string;
  timestamp: string;
  headers: Record<string, string>;
  missingHeaders: Array<{
    header: string;
    description: string;
    recommended: string;
    severity: string;
  }>;
  findings: Array<{
    header: string;
    issue: string;
    severity: string;
  }>;
  score: number;
}

/**
 * Perform the header scan
 */
async function scanHeaders(
  url: string,
  context: ToolPluginContext
): Promise<HeaderScanResult> {
  context.log(`Scanning headers for ${url}`);

  // Fetch the URL
  const response = await fetch(url, {
    method: 'HEAD',
    redirect: 'follow',
  });

  const headers: Record<string, string> = {};
  response.headers.forEach((value, key) => {
    headers[key.toLowerCase()] = value;
  });

  const missingHeaders: HeaderScanResult['missingHeaders'] = [];
  const findings: HeaderScanResult['findings'] = [];

  // Check for missing security headers
  for (const [header, info] of Object.entries(SECURITY_HEADERS)) {
    const headerLower = header.toLowerCase();
    if (!headers[headerLower]) {
      missingHeaders.push({
        header,
        description: info.description,
        recommended: info.recommended,
        severity: info.severity,
      });
    }
  }

  // Check for insecure header values
  if (headers['x-powered-by']) {
    findings.push({
      header: 'X-Powered-By',
      issue: `Information disclosure: ${headers['x-powered-by']}`,
      severity: 'low',
    });
  }

  if (headers['server']) {
    findings.push({
      header: 'Server',
      issue: `Server version disclosure: ${headers['server']}`,
      severity: 'info',
    });
  }

  // Check for weak CSP
  const csp = headers['content-security-policy'];
  if (csp) {
    if (csp.includes("'unsafe-inline'")) {
      findings.push({
        header: 'Content-Security-Policy',
        issue: "CSP contains 'unsafe-inline' which weakens XSS protection",
        severity: 'medium',
      });
    }
    if (csp.includes("'unsafe-eval'")) {
      findings.push({
        header: 'Content-Security-Policy',
        issue: "CSP contains 'unsafe-eval' which allows code execution",
        severity: 'medium',
      });
    }
  }

  // Calculate security score (0-100)
  const totalChecks = Object.keys(SECURITY_HEADERS).length;
  const presentHeaders = totalChecks - missingHeaders.length;
  const baseScore = (presentHeaders / totalChecks) * 100;
  const penaltyPerFinding = 5;
  const score = Math.max(0, baseScore - findings.length * penaltyPerFinding);

  return {
    url,
    timestamp: new Date().toISOString(),
    headers,
    missingHeaders,
    findings,
    score: Math.round(score),
  };
}

/**
 * Header Scanner Plugin
 */
export const headerScannerPlugin = createToolPlugin({
  metadata: {
    id: 'pensar-header-scanner',
    name: 'HTTP Header Security Scanner',
    version: '1.0.0',
    description: 'Scans HTTP headers for security misconfigurations',
    author: 'Pensar',
    tags: ['security', 'headers', 'reconnaissance'],
  },
  category: 'reconnaissance',
  tools: {
    /**
     * Scan HTTP security headers
     */
    scan_security_headers: {
      description: `Scan a URL for security-related HTTP headers. Checks for:
- Missing security headers (HSTS, CSP, X-Frame-Options, etc.)
- Information disclosure headers (X-Powered-By, Server)
- Weak CSP configurations
Returns a security score and list of findings.`,
      parameters: z.object({
        url: z.string().url().describe('The URL to scan'),
        follow_redirects: z.boolean().optional().describe('Follow redirects (default: true)'),
      }),
      execute: async (params, context) => {
        return scanHeaders(params.url, context);
      },
    },

    /**
     * Get recommended headers
     */
    get_recommended_headers: {
      description: 'Get a list of recommended security headers and their values',
      parameters: z.object({}),
      execute: async () => {
        return SECURITY_HEADERS;
      },
    },
  },
});

export default headerScannerPlugin;
