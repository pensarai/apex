/**
 * Type definitions for Attack Surface Analysis results
 * These types match the answer tool schema and can be used by the orchestrator agent
 */

export interface AttackSurfaceAnalysisResults {
  summary: AttackSurfaceSummary;
  discoveredAssets: DiscoveredAssets;
  highValueTargets: HighValueTarget[];
  keyFindings: KeyFinding[];
  recommendations: Recommendations;
  metadata: AnalysisMetadata;
}

export interface AttackSurfaceSummary {
  totalAssets: number;
  totalDomains: number;
  totalIPs: number;
  totalServices: number;
  criticalExposures: number;
  highValueTargets: number;
  analysisComplete: boolean;
}

export interface DiscoveredAssets {
  domains: DiscoveredDomain[];
  ipAddresses: DiscoveredIP[];
  webApplications: DiscoveredWebApplication[];
  cloudResources?: DiscoveredCloudResource[];
  otherServices?: DiscoveredService[];
}

export interface DiscoveredDomain {
  domain: string;
  type: "main" | "subdomain" | "wildcard";
  ipAddresses: string[];
  services: string[];
  technologies?: string[];
  notes?: string;
}

export interface DiscoveredIP {
  ip: string;
  openPorts: number[];
  services: Array<{
    port: number;
    service: string;
    version?: string;
  }>;
  hostname?: string;
}

export interface DiscoveredWebApplication {
  url: string;
  status: number;
  server?: string;
  technologies: string[];
  endpoints: string[];
  securityHeaders?: {
    hasCSP: boolean;
    hasHSTS: boolean;
    hasXFrameOptions: boolean;
  };
}

export interface DiscoveredCloudResource {
  type: "s3" | "azure_blob" | "gcs" | "cloudfront" | "other";
  identifier: string;
  url?: string;
  accessible: boolean;
  notes?: string;
}

export interface DiscoveredService {
  type: string;
  location: string;
  version?: string;
  exposure: "public" | "restricted" | "unknown";
  notes?: string;
}

export interface HighValueTarget {
  target: string;
  priority: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";
  type:
    | "web_application"
    | "api_endpoint"
    | "admin_panel"
    | "authentication_system"
    | "database"
    | "dev_environment"
    | "legacy_system"
    | "exposed_service"
    | "cloud_resource"
    | "other";
  objective: string;
  rationale: string;
  discoveredVulnerabilities?: string[];
  estimatedRisk: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";
  suggestedTests: string[];
}

export interface KeyFinding {
  title: string;
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFORMATIONAL";
  category:
    | "exposed_service"
    | "misconfiguration"
    | "information_disclosure"
    | "weak_security_posture"
    | "asset_discovery"
    | "technology_identification"
    | "other";
  description: string;
  affected: string[];
  impact: string;
}

export interface Recommendations {
  immediateActions: string[];
  pentestingPriority: string[];
  assetReduction?: string[];
  furtherInvestigation?: string[];
}

export interface AnalysisMetadata {
  sessionId: string;
  analysisStartTime: string;
  analysisEndTime: string;
  targetScope: string;
  originalObjective: string;
  toolsUsed: string[];
  reportPath?: string;
}

/**
 * Helper function to load attack surface results from a session
 */
export function loadAttackSurfaceResults(
  resultsPath: string
): AttackSurfaceAnalysisResults {
  const fs = require("fs");
  const data = fs.readFileSync(resultsPath, "utf-8");
  return JSON.parse(data) as AttackSurfaceAnalysisResults;
}

/**
 * Helper function to extract pentest targets from analysis results
 * Useful for orchestrator to spawn sub-agents
 */
export function extractPentestTargets(
  results: AttackSurfaceAnalysisResults
): Array<{ target: string; objective: string }> {
  return results.highValueTargets
    .sort((a, b) => {
      // Sort by priority: CRITICAL > HIGH > MEDIUM > LOW
      const priorityOrder = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3 };
      return (
        priorityOrder[a.priority as keyof typeof priorityOrder] -
        priorityOrder[b.priority as keyof typeof priorityOrder]
      );
    })
    .map((target) => ({
      target: target.target,
      objective: target.objective,
    }));
}

/**
 * Helper function to filter high-priority targets
 */
export function getHighPriorityTargets(
  results: AttackSurfaceAnalysisResults
): HighValueTarget[] {
  return results.highValueTargets.filter(
    (t) => t.priority === "CRITICAL" || t.priority === "HIGH"
  );
}

/**
 * Helper function to get targets by type
 */
export function getTargetsByType(
  results: AttackSurfaceAnalysisResults,
  type: HighValueTarget["type"]
): HighValueTarget[] {
  return results.highValueTargets.filter((t) => t.type === type);
}

