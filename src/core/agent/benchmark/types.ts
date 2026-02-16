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

export interface TokenMetrics {
  inputTokens: number;
  outputTokens: number;
  totalTokens: number;
  estimatedCostUsd: number;
  durationMs: number;
  // Cache breakdown
  cacheReadTokens?: number;
  cacheWriteTokens?: number;
  noCacheInputTokens?: number; // inputTokens - cacheRead - cacheWrite
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
  tokenMetrics?: TokenMetrics;
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

/**
 * APEX benchmark results extend standard benchmark results with comparison metrics
 */
export interface APEXBenchmarkResults extends BenchmarkResults {
  /** Vulnerability comparison results from comparison agent */
  comparison?: ComparisonResult;
  /** Number of expected vulnerabilities in expected_results */
  expectedVulnerabilities: number;
  /** Number of vulnerabilities detected by pentest */
  detectedVulnerabilities: number;
  /** Vulnerability type for this benchmark (e.g., SSRF, XSS, SQLi) */
  vulnType?: string;
}

/**
 * Summary of an APEX benchmark run (batch)
 */
export interface APEXBenchmarkSummary {
  timestamp: string;
  repoUrl: string;
  model: string;
  totalBenchmarks: number;
  completed: number;
  failed: number;
  aggregateMetrics: {
    avgAccuracy: number;
    avgPrecision: number;
    avgRecall: number;
    totalInputTokens: number;
    totalOutputTokens: number;
    totalTokens: number;
    totalEstimatedCostUsd: number;
    totalDurationMs: number;
  };
  benchmarks: APEXBenchmarkEntry[];
  failedBenchmarks: string[];
}

/**
 * Entry for a single benchmark in the summary
 */
export interface APEXBenchmarkEntry {
  name: string;
  status: "success" | "failed";
  vulnType?: string;
  accuracy?: number;
  precision?: number;
  recall?: number;
  expectedVulns?: number;
  detectedVulns?: number;
  sessionPath?: string;
  tokenMetrics?: TokenMetrics;
  error?: string;
  errorCategory?: string;
}

/**
 * PACEbench task definition (from datasets.json)
 */
export interface PACETask {
  id: number;
  name: string;
  category: 'cve' | 'multihost' | 'fullchain' | 'defense';
  difficulty: 'easy' | 'medium' | 'hard';
  flagType: 'sql' | 'file' | 'mixed';
  description?: string;
  cveIds?: string[];
  dockerPath?: string;
}

/**
 * Result for a single PACEbench run
 */
export interface PACEBenchmarkResult {
  taskId: number;
  taskName: string;
  category: string;
  difficulty: string;
  status: 'success' | 'failed' | 'timeout' | 'error';
  flagsExpected: number;
  flagsFound: number;
  flagDetails: Array<{
    name: string;
    expected: string;
    found: boolean;
    foundIn?: string[];
  }>;
  duration: number;
  sessionPath: string;
  error?: string;
}

/**
 * Aggregated PACEbench report
 */
export interface PACEReport {
  timestamp: string;
  model: string;
  repoUrl: string;
  totalTasks: number;
  completed: number;
  failed: number;
  flagsCaptured: number;
  flagsTotal: number;
  captureRate: number;
  byCategory: {
    cve: { total: number; captured: number; rate: number };
    multihost: { total: number; captured: number; rate: number };
    fullchain: { total: number; captured: number; rate: number };
    defense: { total: number; captured: number; rate: number };
  };
  byDifficulty: {
    easy: { total: number; captured: number; rate: number };
    medium: { total: number; captured: number; rate: number };
    hard: { total: number; captured: number; rate: number };
  };
  tasks: PACEBenchmarkResult[];
}

/**
 * Entry for a single PACE benchmark in the summary
 */
export interface PACEBenchmarkEntry {
  taskId: number;
  taskName: string;
  category: string;
  difficulty: string;
  status: 'success' | 'failed' | 'timeout' | 'error';
  flagsExpected: number;
  flagsFound: number;
  captureRate: number;
  duration: number;
  sessionPath?: string;
  error?: string;
  errorCategory?: string;
}
