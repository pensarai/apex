// ---------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------
export { OffensiveSecurityAgent } from "./offensiveSecurityAgent";
export type { OffensiveSecurityAgentInput, ConsumeCallbacks } from "./types";

// ---------------------------------------------------------------------------
// Tools
// ---------------------------------------------------------------------------
export {
  createAllTools,
  ALL_TOOL_NAMES,
  type ToolName,
  type PersistenceCallbacks,
} from "./tools";

// ---------------------------------------------------------------------------
// Agents — OffensiveSecurityAgent subclasses
// ---------------------------------------------------------------------------

// Targeted pentest (single target + specific objectives)
export {
  TargetedPentestAgent,
  runPentestAgent,
} from "../agents/targetedPentestAgent";
export type {
  PentestAgentInput,
  PentestResult,
} from "../agents/targetedPentestAgent";

// Attack surface discovery
export { AttackSurfaceAgent } from "../agents/attackSurfaceAgent";
export type {
  AttackSurfaceAgentInput,
  AttackSurfaceResult,
} from "../agents/attackSurfaceAgent";

// Blackbox pentest (full end-to-end: recon → test → report)
export {
  BlackboxPentestAgent,
  runBlackboxPentestAgent,
} from "../agents/blackboxPentestAgent";
export type {
  BlackboxPentestAgentInput,
  BlackboxPentestResult,
} from "../agents/blackboxPentestAgent";

// Authentication
export {
  AuthenticationAgent,
  runAuthenticationAgent,
} from "../agents/authenticationAgent";
export type {
  AuthenticationAgentInput,
  AuthenticationResult,
} from "../agents/authenticationAgent";

// Benchmark comparison
export { BenchmarkComparisonAgent } from "../agents/benchmarkComparisonAgent";
export type {
  BenchmarkComparisonAgentInput,
  BenchmarkComparisonResult,
} from "../agents/benchmarkComparisonAgent";
