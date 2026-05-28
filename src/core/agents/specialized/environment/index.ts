// Stable external import path. External consumers depend on this barrel.
// Tracked for migration into the public API in #726 — do not delete or
// restructure until those consumers are moved off the deep import.
export { EnvironmentAgent } from "./agent";
export {
  buildEnvironmentPrompt,
  buildEnvironmentSystemPrompt,
  ENVIRONMENT_SYSTEM_PROMPT,
} from "./prompts";
export type {
  DevEnvironmentConfig,
  EnvironmentAgentInput,
  EnvironmentResult,
  EnvironmentVariable,
} from "./types";
export { EnvironmentResultSchema } from "./types";
