// ---------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------
export { OffensiveSecurityAgent } from "./offensiveSecurityAgent";
export type { OffensiveSecurityAgentInput, ConsumeCallbacks } from "./types";

// ---------------------------------------------------------------------------
// Tools
// ---------------------------------------------------------------------------
export { createAllTools, ALL_TOOL_NAMES, type ToolName } from "./tools";

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
export { BlackboxAttackSurfaceAgent } from "../agents/attackSurface/blackboxAgent";
export type {
  AttackSurfaceAgentInput,
  AttackSurfaceResult,
} from "../agents/attackSurface/blackboxAgent";

// Blackbox pentest (full end-to-end: recon → test → report)
export { BlackboxPentestAgent } from "../agents/blackboxPentestAgent";
export type {
  BlackboxPentestAgentInput,
  BlackboxPentestResult,
} from "../agents/blackboxPentestAgent";

// Authentication
export {
  AuthenticationAgent,
  runAuthenticationAgent,
} from "../agents/authenticationAgent/agent";
export type {
  AuthenticationAgentInput,
  AuthenticationResult,
} from "../agents/authenticationAgent/agent";

// Benchmark comparison
export { BenchmarkComparisonAgent } from "../agents/benchmarkComparisonAgent";
export type {
  BenchmarkComparisonAgentInput,
  BenchmarkComparisonResult,
} from "../agents/benchmarkComparisonAgent";
