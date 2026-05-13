import { SkillsRegistry } from "./registry";

export { SkillsRegistry } from "./registry";
export type {
  BuiltInSkill,
  SkillEntry,
  SkillManifest,
  SkillScript,
  SkillSource,
} from "./types";

/** Create a new SkillsRegistry instance. */
export function createSkillsRegistry(): SkillsRegistry {
  return new SkillsRegistry();
}
