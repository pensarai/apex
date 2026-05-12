export { runComparisonAgent } from "./comparisonAgent";
export type { DockerComposePortInfo } from "./docker-utils";
export { getActualDockerPort, parseDockerComposePort } from "./docker-utils";
export {
  APEX_BENCHMARK_PATTERN,
  computeBenchmarkFlag,
  detectFlagInArtifacts,
  detectMultipleFlagsInArtifacts,
  extractBenchmarkName,
  extractFlagFromBenchmarkJson,
  extractFlagFromRepo,
  extractPACEFlags,
  isPACEBenchmark,
} from "./flag-detector";
export { SYSTEM } from "./prompts";
export type { DaytonaBenchmarkOptions } from "./remote";
export { runBenchmarkInDaytona } from "./remote";
export type {
  ActualFinding,
  BenchmarkResults,
  ComparisonResult,
  DevEnvironmentInfo,
  ExpectedFinding,
  FlagDetectionResult,
  FlagLocation,
  MatchedFinding,
  PocRunSummary,
} from "./types";
