import type { AIModel } from "../ai";
import type { ComparisonResult } from "../agents/specialized/benchmark";

export type { ComparisonResult } from "../agents/specialized/benchmark";

export interface BenchmarkMetadata {
  id: string;
  name: string;
  description: string;
  difficulty: number;
  tags: string[];
  winCondition: { type: string; flagPattern: string; location?: string };
  services: Record<string, { port: number; role: string }>;
}

export interface BenchmarkSuiteConfig {
  repoUrl: string;
  repoDir?: string;
  branches: string[];
  model: AIModel;
  comparisonModel?: AIModel;
  outputDir: string;
  mode: "local" | "daytona";
  timeoutMinutes: number;
  daytonaBatchSize: number;
  cleanupTempDirs: boolean;
}

export interface TokenMetrics {
  inputTokens: number;
  outputTokens: number;
  totalTokens: number;
  cacheReadTokens: number;
  cacheWriteTokens: number;
  noCacheInputTokens: number;
  estimatedCostUsd: number;
  estimatedCostWithoutCacheUsd: number;
  durationMs: number;
}

export interface BenchmarkRunResult {
  branch: string;
  metadata: BenchmarkMetadata | null;
  status: "success" | "failed" | "timeout" | "skipped";
  flagDetected: boolean;
  flagValue: string | null;
  findingsCount: number;
  comparisonResult: ComparisonResult | null;
  tokenMetrics: TokenMetrics | null;
  sessionPath: string;
  duration: number;
  error?: string;
}

export interface BenchmarkSuiteResult {
  results: BenchmarkRunResult[];
  summary: BenchmarkSuiteSummary;
  timestamp: string;
  model: AIModel;
  repoUrl: string;
}

export interface BenchmarkSuiteSummary {
  total: number;
  passed: number;
  failed: number;
  timedOut: number;
  flagCaptureRate: number;
  vulnDetectionRate: number;
  avgPrecision: number;
  avgRecall: number;
  totalDurationMinutes: number;
  totalInputTokens: number;
  totalOutputTokens: number;
  totalCacheReadTokens: number;
  totalCacheWriteTokens: number;
  totalEstimatedCostUsd: number;
  totalEstimatedCostWithoutCacheUsd: number;
  cacheHitRate: number;
}
