/**
 * Type definitions for Benchmark Agent
 */

export interface BenchmarkResults {
  repoPath: string;
  branch: string;
  targetUrl: string;
  sessionId: string;
  sessionPath: string;
  expectedResults: ExpectedFinding[];
  actualResults: ActualFinding[];
  comparison: ComparisonResult;
  timestamp: string;
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
