import { SkillsRegistry } from "./registry";

export type {
  BuiltInSkill,
  SkillEntry,
  SkillManifest,
  SkillScript,
  SkillSource,
} from "./types";
export { SkillsRegistry } from "./registry";

/** Create a new SkillsRegistry instance. */
export function createSkillsRegistry(): SkillsRegistry {
  return new SkillsRegistry();
}
