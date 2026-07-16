import type { BuiltInSkill } from "../types";
import { agentRedTeamSkill } from "./agentRedTeam";
import { pentestSkill } from "./pentest";
import { promptInjectionSkill } from "./promptInjection";
import { threatModelSkill } from "./threatModel";

export { buildPentestPrompt } from "./pentest";
export { promptInjectionSkill } from "./promptInjection";
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
  agentRedTeamSkill,
  pentestSkill,
  threatModelSkill,
  promptInjectionSkill,
];
