import type { BuiltInSkill } from "../types";
import { threatModelSkill } from "./threatModel";
import { oobDetectionSkill } from "./oobDetection";

/**
 * Code-defined skills bundled with the application.
 *
 * Built-in skills are loaded into the SkillsRegistry before filesystem skills,
 * so they take precedence on slug collision (first-write-wins).
 *
 * To add a built-in skill, push a BuiltInSkill object into this array.
 */
export const BUILTIN_SKILLS: BuiltInSkill[] = [
  threatModelSkill,
  oobDetectionSkill,
];
