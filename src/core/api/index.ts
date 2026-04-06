// ---- AgentRun ----
export { AgentRun } from "./agentRun";

// ---- Agent runners ----
export * from "./attackSurface";
export * from "./authentication";
export * from "./benchmark";
export * from "./blackboxPentest";
export * from "./targetedPentest";
export * from "./threatModel";
export * from "./patching";
export * from "./environment";
export { runOffensiveSecurityAgent, type RunAgentResult } from "./offesecAgent";

// ---- Event types ----
// AgentEventBus class is NOT exported — it's an internal implementation
// detail. Consumers interact with events via AgentRun<T> (Phase 3).
export type {
  AgentEventName,
  AgentEvent,
  AgentEventOf,
} from "../eventBus";

// ---- Domain types — findings ----
export { ApexFindingObject } from "../agents/offSecAgent/types";
export type { Finding } from "../agents/offSecAgent/types";

// ---- Domain types — attack surface ----
export type {
  DocumentedAppRecord,
  DocumentedEndpointRecord,
  AppType,
  EndpointType,
  RiskLevel,
  AttackSurfaceReport,
  AttackSurfaceSummary,
  PentestTarget,
} from "../agents/specialized/attackSurface/schemas";

// ---- Domain types — authentication ----
export type {
  AuthCredentials,
  AuthFlowHints,
  AuthMethod,
  AuthBarrier,
  AuthenticationSubagentInput,
  AuthenticationSubagentResult,
} from "../agents/specialized/authenticationAgent/types";
export type { AuthenticationResult } from "../agents/specialized/authenticationAgent/agent";

// ---- Agent input/result types ----
export type { PentestAgentInput } from "../agents/specialized/pentest/agent";
export type { PentestResult } from "../agents/specialized/pentest/agent";
export type {
  AttackSurfaceAgentInput,
  AttackSurfaceResult,
} from "../agents/specialized/attackSurface/blackboxAgent";
export type { WhiteboxAttackSurfaceResult } from "../agents/specialized/whiteboxAttackSurface";
// Note: EnvironmentResult is already re-exported via ./environment
export type {
  PentestWorkflowInput,
  PentestWorkflowResult,
} from "../workflows/pentest";

// ---- AI types ----
export type { AIModel } from "../ai";
export type { AIAuthConfig } from "../ai/utils";

// ---- Session types ----
export type { SessionInfo, SessionConfig } from "../session";
