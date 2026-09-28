import type { ComparisonResult } from "../agents/specialized/benchmark";
import type { AIModel } from "../ai";
import type { CostBenchGateway, ReferenceTokenRates } from "./gatewayCost";

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
  runComparison?: boolean;
  costTracking?: {
    gateway: CostBenchGateway;
    referenceRates: ReferenceTokenRates;
    maxProviderCostUsd: number;
  };
}

export interface TokenMetrics {
  inputTokens: number;
  outputTokens: number;
  totalTokens: number;
  cacheReadTokens: number;
  cacheWriteTokens: number;
  noCacheInputTokens: number;
  providerCostUsd: number | null;
  referenceCostUsd: number | null;
  referenceCostWithoutCacheUsd: number | null;
  routes: string[];
  servedModels: string[];
  byok: boolean | undefined;
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
  totalProviderCostUsd: number | null;
  totalReferenceCostUsd: number | null;
  totalReferenceCostWithoutCacheUsd: number | null;
  cacheHitRate: number;
}
