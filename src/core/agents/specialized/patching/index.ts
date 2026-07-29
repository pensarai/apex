// Stable external import path. External consumers depend on this barrel.
// Tracked for migration into the public API in #726 — do not delete or
// restructure until those consumers are moved off the deep import.
export {
  PATCHING_ACTIVE_TOOLS,
  PatchingAgent,
  readAgentsMd,
} from "./agent";
export {
  buildPatchingPrompt,
  buildSystemPrompt,
  PATCHING_SYSTEM_PROMPT,
  PROJECT_INSTRUCTIONS_TAG,
} from "./prompts";
export type {
  PatchingAgentInput,
  PatchResult,
  VulnerabilityDetails,
} from "./types";
export { PatchResultSchema } from "./types";
