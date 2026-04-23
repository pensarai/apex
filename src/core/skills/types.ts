// ---------------------------------------------------------------------------
// skills.sh-compatible types
// ---------------------------------------------------------------------------

/** Where a skill was discovered from */
export type SkillSource = "project" | "user" | "builtin";

/** Parsed SKILL.md frontmatter */
export interface SkillManifest {
  name: string;
  description: string;
  version?: string;
  tags?: string[];
  triggers?: string[];
  inputs?: Array<{ name: string; description?: string; required?: boolean }>;
  outputs?: Array<{ name: string; description?: string }>;
}

/** A script discovered in the skill's `scripts/` subdirectory */
export interface SkillScript {
  name: string;
  path: string;
  description?: string;
}

/** Unified skill entry used by the registry */
export interface SkillEntry {
  slug: string;
  source: SkillSource;
  /** Path to SKILL.md */
  filePath: string;
  /** Parent directory for directory-based skills */
  dirPath?: string;
  manifest: SkillManifest;
  /** Scripts from the `scripts/` subdirectory */
  scripts: SkillScript[];
  lastModified?: number;
}

/** A code-defined skill bundled with the application */
export interface BuiltInSkill {
  slug: string;
  manifest: SkillManifest;
  instructions: string;
}
