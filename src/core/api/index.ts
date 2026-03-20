export * from "./attackSurface";
export * from "./authentication";
export * from "./benchmark";
export * from "./blackboxPentest";
export * from "./targetedPentest";
export * from "./patching";
export * from "./environment";

// Threat model
export { runThreatModelAgent, type ThreatModelInput } from "./threatModel";

// Threat model types
export type {
  ThreatModelResult,
  ThreatModelAgentResult,
  ApplicationContext,
  ApplicationIdentity,
  ApplicationFeature,
  ApplicationTrustBoundary,
  AttackerProfile,
  AttackPath,
  SystemArchitecture,
  Component,
  TrustBoundary,
  DataFlow,
  DeploymentContext,
  SecurityControl,
  SecurityControlsResult,
} from "../agents/specialized/threatModel/types";
