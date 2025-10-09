import { tool } from "ai";
import { z } from "zod";
import { exec } from "child_process";
import { promisify } from "util";
import { writeFileSync, appendFileSync } from "fs";
import { join } from "path";
import type { Session } from "./sessions";

const execAsync = promisify(exec);

/**
 * Execute shell command - Primary tool for penetration testing
 *
 * Use this for all command-line operations including:
 * - nmap scans
 * - curl/wget requests
 * - nikto web scans
 * - directory enumeration (gobuster, dirb, dirbuster)
 * - subdomain enumeration (sublist3r, amass)
 * - SSL/TLS testing (sslscan, testssl.sh)
 * - DNS lookups (dig, nslookup, host)
 * - Network tools (ping, traceroute, netcat)
 * - Web application testing (sqlmap, burp, zap)
 */
export const executeCommand = tool({
  name: "execute_command",
  description: `Execute a shell command for penetration testing activities.
  
COMMON COMMANDS FOR BLACK BOX TESTING:

RECONNAISSANCE:
- nmap -sV -sC <target>              # Service version detection + default scripts
- nmap -p- <target>                  # Scan all ports
- nmap -sU <target>                  # UDP scan
- nmap -A <target>                   # Aggressive scan (OS, version, scripts)
- dig <domain>                       # DNS lookup
- whois <domain>                     # Domain registration info
- host <domain>                      # DNS hostname lookup

WEB APPLICATION TESTING:
- curl -i <url>                      # HTTP request with headers
- curl -X POST -d "data" <url>       # POST request
- curl -H "Header: value" <url>      # Custom headers
- curl -L <url>                      # Follow redirects
- curl -k <url>                      # Ignore SSL errors
- nikto -h <host>                    # Web server scanner
- gobuster dir -u <url> -w <wordlist> # Directory enumeration
- gobuster dns -d <domain> -w <wordlist> # Subdomain enumeration
- ffuf -u <url>/FUZZ -w <wordlist>   # Web fuzzer

SSL/TLS TESTING:
- openssl s_client -connect <host>:<port> # SSL/TLS connection test
- nmap --script ssl-enum-ciphers -p 443 <host> # SSL cipher enumeration

NETWORK ANALYSIS:
- nc -zv <host> <port>               # Port connection test
- traceroute <host>                  # Network path tracing
- ping -c 4 <host>                   # ICMP connectivity test

OUTPUT HANDLING:
- Use 2>&1 to capture stderr
- Use timeout command for long-running scans
- Consider -oN for nmap output

IMPORTANT: Always analyze results and adjust your approach based on findings.`,
  inputSchema: z.object({
    command: z.string().describe("The shell command to execute"),
    timeout: z
      .number()
      .optional()
      .describe("Timeout in milliseconds (default: 30000)"),
  }),
  execute: async ({ command, timeout = 30000 }) => {
    try {
      const { stdout, stderr } = await execAsync(command, {
        timeout,
        maxBuffer: 10 * 1024 * 1024, // 10MB buffer
      });
      return {
        success: true,
        stdout: stdout || "(no output)",
        stderr: stderr || "",
        command,
      };
    } catch (error: any) {
      return {
        success: false,
        error: error.message,
        stdout: error.stdout || "",
        stderr: error.stderr || "",
        command,
      };
    }
  },
});

/**
 * HTTP request tool - Specialized for web application testing
 */
export const httpRequest = tool({
  name: "http_request",
  description: `Make HTTP requests with detailed response analysis for web application testing.

USAGE GUIDANCE:
- Always check response headers for security misconfigurations
- Look for: X-Frame-Options, X-XSS-Protection, CSP, HSTS, X-Content-Type-Options
- Analyze cookies for HttpOnly, Secure, SameSite flags
- Check for verbose error messages that leak information
- Test for common web vulnerabilities (SQL injection, XSS, IDOR)
- Monitor response times for blind injection attacks
- Test different HTTP methods (GET, POST, PUT, DELETE, PATCH, OPTIONS)
- Examine redirects and authentication flows

COMMON TESTING PATTERNS:
- Test with/without authentication
- Try different user agents
- Test for CORS misconfigurations
- Check for API endpoints (/api/, /v1/, /graphql)
- Look for admin panels (/admin, /administrator, /wp-admin)
- Test for backup files (.bak, .old, ~, .swp)`,
  inputSchema: z.object({
    url: z.string().describe("The URL to request"),
    method: z
      .enum(["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"])
      .default("GET"),
    headers: z
      .record(z.string(), z.string())
      .optional()
      .describe("HTTP headers as key-value pairs"),
    body: z.string().optional().describe("Request body (for POST, PUT, PATCH)"),
    followRedirects: z.boolean().default(true),
    timeout: z.number().default(10000),
  }),
  execute: async ({ url, method, headers, body, followRedirects, timeout }) => {
    try {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), timeout);

      const response = await fetch(url, {
        method,
        headers: headers || {},
        body: body || undefined,
        redirect: followRedirects ? "follow" : "manual",
        signal: controller.signal,
      });

      clearTimeout(timeoutId);

      const responseHeaders: Record<string, string> = {};
      response.headers.forEach((value, key) => {
        responseHeaders[key] = value;
      });

      let responseBody = "";
      try {
        responseBody = await response.text();
      } catch (e) {
        responseBody = "(unable to read response body)";
      }

      return {
        success: true,
        status: response.status,
        statusText: response.statusText,
        headers: responseHeaders,
        body: responseBody.substring(0, 50000), // Limit to 50KB
        url: response.url,
        redirected: response.redirected,
      };
    } catch (error: any) {
      return {
        success: false,
        error: error.message,
        url,
        method,
      };
    }
  },
});

/**
 * Analysis tool - Document findings and maintain testing state
 *
 * This function is created with a session context to save findings to disk
 */
function createDocumentFindingTool(session: Session) {
  return tool({
    name: "document_finding",
    description: `Document a security finding with severity, impact, and remediation guidance.

SEVERITY LEVELS:
- CRITICAL: Immediate risk of system compromise (RCE, auth bypass, SQL injection with data access)
- HIGH: Significant security risk (XSS, CSRF, sensitive data exposure, privilege escalation)
- MEDIUM: Security weakness that could be exploited (information disclosure, weak configs)
- LOW: Minor security concern (missing headers, verbose errors)
- INFORMATIONAL: No immediate risk but worth noting (technology versions, endpoints discovered)

FINDING STRUCTURE:
- Title: Clear, concise description
- Severity: Use CVSS if applicable
- Description: Detailed technical explanation
- Impact: Business and technical consequences
- Evidence: Commands run, responses received, proof of vulnerability
- Remediation: Specific, actionable steps to fix
- References: CVE, CWE, OWASP, or security advisories`,
    inputSchema: z.object({
      title: z.string().describe("Finding title"),
      severity: z.enum(["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"]),
      description: z.string().describe("Detailed description of the finding"),
      impact: z.string().describe("Potential impact if exploited"),
      evidence: z.string().describe("Evidence/proof of the vulnerability"),
      remediation: z.string().describe("Steps to fix the issue"),
      references: z
        .string()
        .optional()
        .describe("CVE, CWE, or related references"),
    }),
    execute: async (finding) => {
      try {
        const timestamp = new Date().toISOString();
        const findingWithMeta = {
          ...finding,
          timestamp,
          sessionId: session.id,
          target: session.target,
        };

        // Create a safe filename from the title
        const safeTitle = finding.title
          .toLowerCase()
          .replace(/[^a-z0-9]+/g, "-")
          .replace(/^-|-$/g, "")
          .substring(0, 50);

        const findingId = `${timestamp.split("T")[0]}-${safeTitle}`;
        const filename = `${findingId}.md`;
        const filepath = join(session.findingsPath, filename);

        // Create markdown document
        const markdown = `# ${finding.title}

**Severity:** ${finding.severity}  
**Target:** ${session.target}  
**Date:** ${timestamp}  
**Session:** ${session.id}

## Description

${finding.description}

## Impact

${finding.impact}

## Evidence

\`\`\`
${finding.evidence}
\`\`\`

## Remediation

${finding.remediation}

${finding.references ? `## References\n\n${finding.references}` : ""}

---

*This finding was automatically documented by the Pensar penetration testing agent.*
`;

        writeFileSync(filepath, markdown);

        // Also append to a summary file
        const summaryPath = join(session.rootPath, "findings-summary.md");
        const summaryEntry = `- [${finding.severity}] ${finding.title} - \`findings/${filename}\`\n`;

        try {
          appendFileSync(summaryPath, summaryEntry);
        } catch (e) {
          // File doesn't exist, create it with header
          const header = `# Findings Summary\n\n**Target:** ${session.target}  \n**Session:** ${session.id}\n\n## All Findings\n\n`;
          writeFileSync(summaryPath, header + summaryEntry);
        }

        return {
          success: true,
          finding: findingWithMeta,
          filepath,
          message: `Finding documented: [${finding.severity}] ${finding.title}`,
        };
      } catch (error: any) {
        return {
          success: false,
          error: error.message,
          message: `Failed to document finding: ${error.message}`,
        };
      }
    },
  });
}

/**
 * Scratchpad tool - Take notes during testing
 */
function createScratchpadTool(session: Session) {
  return tool({
    name: "scratchpad",
    description: `Write notes, observations, or temporary data to the scratchpad during testing.

Use this to:
- Keep track of interesting findings that need more investigation
- Note patterns or anomalies
- Store intermediate results
- Track your testing progress
- Document hypotheses

The scratchpad is session-specific and helps maintain context during long assessments.`,
    inputSchema: z.object({
      note: z.string().describe("The note or observation to record"),
      category: z
        .enum(["observation", "todo", "hypothesis", "result", "general"])
        .default("general"),
    }),
    execute: async ({ note, category }) => {
      try {
        const timestamp = new Date().toISOString();
        const scratchpadFile = join(session.scratchpadPath, "notes.md");

        const entry = `## ${category.toUpperCase()} - ${timestamp}\n\n${note}\n\n---\n\n`;

        try {
          appendFileSync(scratchpadFile, entry);
        } catch (e) {
          // File doesn't exist, create it with header
          const header = `# Scratchpad - Session ${session.id}\n\n**Target:** ${session.target}  \n**Objective:** ${session.objective}\n\n---\n\n`;
          writeFileSync(scratchpadFile, header + entry);
        }

        return {
          success: true,
          message: "Note added to scratchpad",
          timestamp,
        };
      } catch (error: any) {
        return {
          success: false,
          error: error.message,
        };
      }
    },
  });
}

/**
 * Port scan analyzer - Interpret nmap results
 */
export const analyzeScan = tool({
  name: "analyze_scan",
  description: `Analyze scan results and suggest next steps for penetration testing.

This tool helps interpret findings from:
- Port scans (nmap, masscan)
- Service enumeration
- Web server scans (nikto, dirb)
- SSL/TLS scans
- Subdomain enumeration

Provides guidance on:
- Which services to investigate further
- Known vulnerabilities for detected versions
- Common misconfigurations to test
- Recommended testing tools and techniques
- Attack surface prioritization`,
  inputSchema: z.object({
    scanType: z.enum([
      "port_scan",
      "service_enum",
      "web_scan",
      "ssl_scan",
      "other",
    ]),
    results: z.string().describe("The scan results to analyze"),
    target: z.string().describe("The target that was scanned"),
  }),
  execute: async ({ scanType, results, target }) => {
    // Parse and provide intelligent analysis
    const analysis = {
      scanType,
      target,
      timestamp: new Date().toISOString(),
      summary: "",
      openPorts: [] as string[],
      services: [] as string[],
      recommendations: [] as string[],
      potentialVulnerabilities: [] as string[],
    };

    // Simple parsing logic (can be enhanced)
    if (scanType === "port_scan") {
      const portMatches = results.match(/(\d+)\/tcp\s+open/g);
      if (portMatches) {
        analysis.openPorts = portMatches
          .map((m) => m.split("/")[0])
          .filter((p): p is string => p !== undefined);
        analysis.summary = `Found ${analysis.openPorts.length} open TCP ports`;

        // Add recommendations based on common ports
        if (
          analysis.openPorts.includes("80") ||
          analysis.openPorts.includes("443")
        ) {
          analysis.recommendations.push(
            "Run web application scans (nikto, gobuster)"
          );
        }
        if (analysis.openPorts.includes("22")) {
          analysis.recommendations.push(
            "Test SSH authentication methods and banners"
          );
        }
        if (
          analysis.openPorts.includes("3306") ||
          analysis.openPorts.includes("5432")
        ) {
          analysis.recommendations.push(
            "Database port exposed - test for default credentials"
          );
        }
      }
    }

    return {
      success: true,
      analysis,
      nextSteps: analysis.recommendations,
    };
  },
});

// Export tools creator function that accepts a session
export function createPentestTools(session: Session) {
  return {
    execute_command: executeCommand,
    http_request: httpRequest,
    document_finding: createDocumentFindingTool(session),
    analyze_scan: analyzeScan,
    scratchpad: createScratchpadTool(session),
  };
}
