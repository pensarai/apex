// ---------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------
export { OffensiveSecurityAgent } from "../agents/offensiveAgent";
export type {
  OffensiveSecurityAgentInput,
  ConsumeCallbacks,
} from "../agents/offensiveAgent/types";

// ---------------------------------------------------------------------------
// Tools
// ---------------------------------------------------------------------------
export {
  createAllTools,
  ALL_TOOL_NAMES,
  type ToolName,
} from "../agents/offensiveAgent/tools";

// ---------------------------------------------------------------------------
// Agents — OffensiveSecurityAgent subclasses
// ---------------------------------------------------------------------------

// Targeted pentest (single target + specific objectives)
export {
  TargetedPentestAgent,
  runPentestAgent,
} from "../agents/specialized/targetedPentest/agent";
export type {
  PentestAgentInput,
  PentestResult,
} from "../agents/specialized/targetedPentest/agent";

// Attack surface discovery
export { BlackboxAttackSurfaceAgent } from "../agents/specialized/attackSurface/blackboxAgent";
export type {
  AttackSurfaceAgentInput,
  AttackSurfaceResult,
} from "../agents/specialized/attackSurface/blackboxAgent";

// Blackbox pentest (full end-to-end: recon → test → report)
export { BlackboxPentestAgent } from "../agents/specialized/blackboxPentest/agent";
export type {
  BlackboxPentestAgentInput,
  BlackboxPentestResult,
} from "../agents/specialized/blackboxPentest/agent";

// Authentication
export {
  AuthenticationAgent,
  runAuthenticationAgent,
} from "../agents/specialized/authenticationAgent/agent";
export type {
  AuthenticationAgentInput,
  AuthenticationResult,
} from "../agents/specialized/authenticationAgent/agent";

// Benchmark comparison
export { BenchmarkComparisonAgent } from "../agents/specialized/benchmarkComparisonAgent";
export type {
  BenchmarkComparisonAgentInput,
  BenchmarkComparisonResult,
} from "../agents/specialized/benchmarkComparisonAgent";
