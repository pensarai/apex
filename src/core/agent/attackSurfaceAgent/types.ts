import { readFileSync } from "fs";

/**
 * Type definitions for Attack Surface Analysis results
 * These types match the simplified answer tool schema
 */

export interface AttackSurfaceAnalysisResults {
  summary: AttackSurfaceSummary;
  discoveredAssets: string[];
  targets: PentestTarget[];
  keyFindings: string[];
}

export interface AttackSurfaceSummary {
  totalAssets: number;
  totalDomains: number;
  highValueTargets: number;
  analysisComplete: boolean;
}

export interface PentestTarget {
  target: string;
  objective: string;
  rationale: string;
  authenticationInfo?: {
    method: string;
    details: string;
    credentials?: string;
    cookies?: string;
    headers?: string;
  };
}

/**
 * Helper function to load attack surface results from a session
 */
export function loadAttackSurfaceResults(
  resultsPath: string
): AttackSurfaceAnalysisResults {
  const data = readFileSync(resultsPath, "utf-8");
  return JSON.parse(data) as AttackSurfaceAnalysisResults;
}

/**
 * Helper function to extract pentest targets from analysis results
 * Useful for orchestrator to spawn sub-agents
 */
export function extractPentestTargets(
  results: AttackSurfaceAnalysisResults
): Array<{ target: string; objective: string }> {
  return results.targets.map((target) => ({
    target: target.target,
    objective: target.objective,
  }));
}

/**
 * Parse discovered assets into structured data
 * Assets are stored as strings like "example.com - Web server (nginx) - Ports 80,443"
 */
export function parseDiscoveredAsset(asset: string): {
  identifier: string;
  description: string;
  details?: string;
} {
  const parts = asset.split(" - ");
  return {
    identifier: parts[0] || asset,
    description: parts[1] || "",
    details: parts[2],
  };
}

/**
 * Parse key findings
 * Findings are stored as strings like "[HIGH] Admin panel exposed - admin.example.com"
 */
export function parseKeyFinding(finding: string): {
  severity: string;
  description: string;
} {
  const severityMatch = finding.match(/^\[(CRITICAL|HIGH|MEDIUM|LOW)\]/);
  const severity: string = severityMatch?.[1] || "LOW";
  const description: string =
    finding.replace(/^\[(CRITICAL|HIGH|MEDIUM|LOW)\]\s*/, "") || finding;

  return { severity, description };
}

/**
 * Get high priority targets
 */
export function getHighPriorityKeywords(
  results: AttackSurfaceAnalysisResults
): string[] {
  return results.keyFindings
    .filter((f) => f.startsWith("[CRITICAL]") || f.startsWith("[HIGH]"))
    .map((f) => parseKeyFinding(f).description);
}
