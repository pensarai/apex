// ---------------------------------------------------------------------------
// Core streaming types
// ---------------------------------------------------------------------------
export { AgentRun } from "./agentRun";
export type { AgentEvent, AgentEventOfType } from "../agents/offSecAgent/eventBus";

// ---------------------------------------------------------------------------
// Agent runners — all return AgentRun<T>
// ---------------------------------------------------------------------------
export { runAttackSurfaceAgent, type AttackSurfaceInput } from "./attackSurface";
export { runAuthenticationAgent } from "./authentication";
export { runBenchmarkComparisonAgent } from "./benchmark";
export { runPentestAgent } from "./blackboxPentest";
export { runTargetedPentestAgent } from "./targetedPentest";
export * from "./operator";

// ---------------------------------------------------------------------------
// Result types — returned by agent runners via .result
// ---------------------------------------------------------------------------
export type { AttackSurfaceResult } from "../agents/specialized/attackSurface/blackboxAgent";
export type { WhiteboxAttackSurfaceResult } from "../agents/specialized/whiteboxAttackSurface";
export type { AuthenticationResult } from "../agents/specialized/authenticationAgent/agent";
export type { PentestResult } from "../agents/specialized/pentest/agent";
export type { PentestWorkflowResult } from "../workflows/pentest";
export type { BenchmarkComparisonResult } from "../agents/specialized/benchmarkComparisonAgent";

// ---------------------------------------------------------------------------
// Input types — accepted by agent runners
// ---------------------------------------------------------------------------
export type { PentestAgentInput } from "../agents/specialized/pentest/agent";
export type { AttackSurfaceAgentInput } from "../agents/specialized/attackSurface/blackboxAgent";
export type { AuthenticationAgentInput } from "../agents/specialized/authenticationAgent/agent";
export type { BenchmarkComparisonAgentInput } from "../agents/specialized/benchmarkComparisonAgent";

// ---------------------------------------------------------------------------
// Domain types — used by consumers for data transformation and business logic
// ---------------------------------------------------------------------------

// Attack surface
export type {
  DocumentedAssetRecord,
  AssetType,
  RiskLevel,
  AttackSurfaceReport,
  PentestTarget,
  AttackSurfaceSummary,
} from "../agents/specialized/attackSurface/schemas";

// Findings
export {
  ApexFindingObject,
  type Finding,
} from "../agents/offSecAgent/types";

// Authentication
export type {
  AuthCredentials,
  AuthenticationSubagentInput,
  AuthenticationSubagentResult,
  AuthFlowHints,
  AuthMethod,
} from "../agents/specialized/authenticationAgent/types";

// AI model
export type { AIModel } from "../ai";
export type { AIAuthConfig } from "../ai/utils";
