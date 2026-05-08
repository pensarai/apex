// ---------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------
export { OffensiveSecurityAgent } from "./offensiveSecurityAgent";
export {
  type OffensiveSecurityAgentInput,
  type CreateAgentInput,
  type SpecializedAgentInput,
  type AgentMode,
  type Finding,
  type CommandCancelHandle,
} from "./types";

// ---------------------------------------------------------------------------
// Event Bus
// ---------------------------------------------------------------------------
export { AgentEventBus } from "../../eventBus";
export type { AgentEventMap } from "../../eventBus";

// ---------------------------------------------------------------------------
// Trace
// ---------------------------------------------------------------------------
export type {
  StepRecord,
  StateCheckpoint,
  InitRecord,
  CheckpointInput,
  TraceRecord,
  ToolOutputType,
  StepTraceWriterOpts,
} from "./trace";

// ---------------------------------------------------------------------------
// System prompts
// ---------------------------------------------------------------------------
export {
  buildBaseSystemPrompt,
  buildSessionWorkspaceSection,
  BASE_SYSTEM_PROMPT,
  type BaseSystemPromptOptions,
} from "./prompt";

// ---------------------------------------------------------------------------
// Tools — re-exported via the tools barrel.
// ---------------------------------------------------------------------------
export * from "./tools";
