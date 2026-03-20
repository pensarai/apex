import { SkillsRegistry } from "./registry";

export type {
  SkillEntry,
  SkillManifest,
  SkillScript,
  SkillSource,
} from "./types";
export { SkillsRegistry } from "./registry";
export { parseSkillMd } from "./parser";
export { scanSkillRoots } from "./scanner";
export { slugify } from "./utils";

/** Create a new SkillsRegistry instance. */
export function createSkillsRegistry(): SkillsRegistry {
  return new SkillsRegistry();
}
