/**
 * Type definitions for Benchmark Agent
 */

export interface PocRunSummary {
  total: number;
  passed: number;
  failed: number;
  skipped: number;
  results: Array<{
    pocFile: string;
    pocName: string;
    exitCode: number | null;
    success: boolean;
    duration: number;
    error?: string;
  }>;
}

export interface BenchmarkResults {
  repoPath: string;
  branch: string;
  targetUrl: string;
  sessionId: string;
  sessionPath: string;
  flagDetection: FlagDetectionResult;
  expectedFlag: string | null;
  pocRunSummary?: PocRunSummary;
  timestamp: string;
}

export interface FlagLocation {
  file: string;
  line: number;
  context: string;
}

export interface FlagDetectionResult {
  detected: boolean;
  flagValue: string | null;
  foundIn: string[];
  locations: FlagLocation[];
  searchLocations: string[];
  // Multi-flag support for PACEbench FullChain challenges
  multiFlag?: {
    total: number;
    found: number;
    details: Array<{
      name: string;
      expected: string;
      detected: boolean;
      foundIn?: string[];
    }>;
  };
}

export interface ExpectedFinding {
  title: string;
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | string;
  reason: string;
}

export interface ActualFinding {
  title: string;
  severity?: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | string;
  location: string;
  category?: string;
  description?: string;
  evidence?: string;
  recommendation?: string;
}

export interface ComparisonResult {
  totalExpected: number;
  totalActual: number;
  matched: MatchedFinding[];
  missed: Array<ExpectedFinding & { reason?: string }>;
  extra: Array<ActualFinding & { assessment?: string }>;
  accuracy: number;
  recall: number;
  precision: number;
}

export interface MatchedFinding {
  location: string;
  expectedTitle: string;
  actualTitle: string;
  matchReason: string;
}

export interface DevEnvironmentInfo {
  repoPath: string;
  branch: string;
  composeFile: string;
  targetUrl: string;
  started: boolean;
  containerId?: string;
}
