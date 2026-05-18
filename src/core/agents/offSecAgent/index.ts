// ---------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------

export type { AgentEventMap } from "../../eventBus";
// ---------------------------------------------------------------------------
// Event Bus
// ---------------------------------------------------------------------------
export { AgentEventBus } from "../../eventBus";
export { OffensiveSecurityAgent } from "./offensiveSecurityAgent";
// ---------------------------------------------------------------------------
// System prompts
// ---------------------------------------------------------------------------
export {
  BASE_SYSTEM_PROMPT,
  type BaseSystemPromptOptions,
  buildBaseSystemPrompt,
  buildProvidedFilesSection,
  buildSessionWorkspaceSection,
} from "./prompt";
// ---------------------------------------------------------------------------
// Tools — re-exported via the tools barrel.
// ---------------------------------------------------------------------------
export * from "./tools";
export type {
  CheckpointInput,
  InitRecord,
  StateCheckpoint,
  StepRecord,
  StepTraceWriterOpts,
  ToolOutputType,
  TraceRecord,
} from "./trace";
// ---------------------------------------------------------------------------
// Trace
// ---------------------------------------------------------------------------
export { StepTraceWriter } from "./trace";
export {
  type AgentMode,
  ApexFindingObject,
  type CommandCancelHandle,
  type CreateAgentInput,
  type Finding,
  type OffensiveSecurityAgentInput,
  type SpecializedAgentInput,
} from "./types";
