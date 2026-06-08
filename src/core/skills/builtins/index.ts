import type { BuiltInSkill } from "../types";
import { agenticSkill } from "./agentic";
import { pentestSkill } from "./pentest";
import { threatModelSkill } from "./threatModel";

export { buildAgenticPrompt } from "./agentic";
export { buildPentestPrompt } from "./pentest";
export { buildThreatModelPrompt } from "./threatModel";

/**
 * Code-defined skills bundled with the application.
 *
 * Built-in skills are loaded into the SkillsRegistry before filesystem skills,
 * so they take precedence on slug collision (first-write-wins).
 *
 * To add a built-in skill, push a BuiltInSkill object into this array.
 */
export const BUILTIN_SKILLS: BuiltInSkill[] = [
  pentestSkill,
  agenticSkill,
  threatModelSkill,
];
