import { SkillsRegistry } from "./registry";

export { parseSkillMd } from "./parser";
export { SkillsRegistry } from "./registry";
export { scanSkillRoots } from "./scanner";
export type {
  BuiltInSkill,
  SkillEntry,
  SkillManifest,
  SkillScript,
  SkillSource,
} from "./types";
export { slugify } from "./utils";

/** Create a new SkillsRegistry instance. */
export function createSkillsRegistry(): SkillsRegistry {
  return new SkillsRegistry();
}
