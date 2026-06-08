// Public API of the agentic red-team module.
//
// Tests AI agents / LLM apps for prompt injection (direct + indirect), tool
// abuse, data exfiltration, and agent-to-agent handoff abuse. The deterministic
// `case -> adapter -> canary oracle -> finding` pipeline anchors success on
// out-of-band canary signals rather than model judgement.

export {
  type CreateAdapterOptions,
  type CreateSessionInput,
  createTargetAdapter,
  type TargetAdapter,
} from "./adapters";
export type { CanaryProvider } from "./canary";
export { LocalCanaryServer, NullCanary } from "./canary";
export { allCases, selectCases } from "./cases";
export {
  type AgenticAdapterConfig,
  type AgenticConfig,
  AgenticConfigObject,
} from "./config";
export { type AgenticJudge, scoreCase } from "./oracle";
export { renderPlaybook } from "./playbook";
export { type RunCaseOptions, runCase } from "./runner";
export {
  type AgenticToolDeps,
  type AgenticTools,
  buildAgenticTools,
  type ProbeRecord,
} from "./tools";
export type {
  AgenticTranscript,
  CanaryHit,
  CaseResult,
  CaseStatus,
  Category,
  Channel,
  JudgeVerdict,
  RedTeamCase,
  RunReport,
  Severity,
  SuccessCriteria,
} from "./types";
