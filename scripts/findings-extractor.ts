/**
 * Findings Extractor
 * 
 * Utility to load and parse security findings from session artifacts.
 * Handles JSON serialization and severity categorization.
 */

import { existsSync, readdirSync, readFileSync } from "fs";
import path from "path";

export interface Finding {
  id: string;
  title: string;
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";
  description: string;
  impact: string;
  evidence: string;
  endpoint: string;
  pocPath: string;
  remediation: string;
  references?: string;
  timestamp: string;
  sessionId: string;
  target: string;
  vulnerabilityClass?: string;
  cvss?: {
    score: number;
    severity: string;
    vectorString: string;
  };
}

export interface FindingsSummary {
  total: number;
  bySeverity: {
    critical: number;
    high: number;
    medium: number;
    low: number;
  };
  findings: Finding[];
}

/**
 * Load all findings from session artifacts
 */
export function loadFindings(sessionPath: string): FindingsSummary {
  const findingsDir = path.join(sessionPath, "findings");
  
  const summary: FindingsSummary = {
    total: 0,
    bySeverity: {
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
    },
    findings: [],
  };

  // Check if findings directory exists
  if (!existsSync(findingsDir)) {
    return summary;
  }

  try {
    const files = readdirSync(findingsDir).filter((f) => f.endsWith(".json"));

    for (const file of files) {
      try {
        const filePath = path.join(findingsDir, file);
        const content = readFileSync(filePath, "utf-8");
        const finding = JSON.parse(content) as Finding;

        summary.findings.push(finding);
        summary.total++;

        // Count by severity
        const severityLower = finding.severity.toLowerCase() as keyof typeof summary.bySeverity;
        if (severityLower in summary.bySeverity) {
          summary.bySeverity[severityLower]++;
        }
      } catch (error) {
        console.warn(`Warning: Failed to parse finding ${file}:`, error instanceof Error ? error.message : String(error));
      }
    }
  } catch (error) {
    console.warn("Warning: Failed to read findings directory:", error instanceof Error ? error.message : String(error));
  }

  // Sort findings by severity (critical first)
  const severityOrder = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3 };
  summary.findings.sort(
    (a, b) =>
      severityOrder[a.severity as keyof typeof severityOrder] -
      severityOrder[b.severity as keyof typeof severityOrder],
  );

  return summary;
}

/**
 * Format findings for JSON output
 */
export function formatFindingsJSON(summary: FindingsSummary): object {
  return {
    total: summary.total,
    bySeverity: summary.bySeverity,
    findings: summary.findings.map((f) => ({
      id: f.id,
      title: f.title,
      severity: f.severity,
      description: f.description,
      impact: f.impact,
      evidence: f.evidence,
      endpoint: f.endpoint,
      remediation: f.remediation,
      references: f.references || undefined,
      vulnerabilityClass: f.vulnerabilityClass || undefined,
      cvss: f.cvss
        ? {
            score: f.cvss.score,
            severity: f.cvss.severity,
          }
        : undefined,
    })),
  };
}

/**
 * Format findings for text output
 */
export function formatFindingsText(summary: FindingsSummary): string {
  let output = "\n=== Security Findings Summary ===\n";
  output += `Total: ${summary.total} findings\n`;
  output += `- Critical: ${summary.bySeverity.critical}\n`;
  output += `- High:     ${summary.bySeverity.high}\n`;
  output += `- Medium:   ${summary.bySeverity.medium}\n`;
  output += `- Low:      ${summary.bySeverity.low}\n`;

  if (summary.findings.length > 0) {
    output += "\n=== Findings Details ===\n";
    for (const finding of summary.findings) {
      output += `\n[${finding.severity}] ${finding.title}\n`;
      output += `  ID: ${finding.id}\n`;
      output += `  Endpoint: ${finding.endpoint}\n`;
      output += `  Description: ${finding.description}\n`;
      if (finding.cvss) {
        output += `  CVSS Score: ${finding.cvss.score} (${finding.cvss.severity})\n`;
      }
    }
  }

  return output;
}
