// Stable external import path. External consumers depend on this barrel.
// Tracked for migration into the public API in #726 — do not delete or
// restructure until those consumers are moved off the deep import.
export { PatchingAgent } from "./agent";
export {
  buildPatchingPrompt,
  buildSystemPrompt,
  PATCHING_SYSTEM_PROMPT,
} from "./prompts";
export type {
  PatchingAgentInput,
  PatchResult,
  VulnerabilityDetails,
} from "./types";
export { PatchResultSchema } from "./types";
