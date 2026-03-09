export interface Skill {
  /** Unique slug used as the slash-command name (e.g. "sql-injection") */
  name: string;
  /** Short human-readable description shown in autocomplete */
  description: string;
  /** The prompt / workflow content injected when the skill is invoked */
  content: string;
}

/**
 * Frontmatter extracted from a skill markdown file.
 * The remainder of the file becomes `content`.
 */
export interface SkillFrontmatter {
  name?: string;
  description?: string;
}

// ---------------------------------------------------------------------------
// skills.sh-compatible types
// ---------------------------------------------------------------------------

/** Where a skill was discovered from */
export type SkillSource = "legacy" | "directory";

/** Parsed SKILL.md frontmatter (richer than legacy SkillFrontmatter) */
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
  /** Path to SKILL.md or legacy .md file */
  filePath: string;
  /** Parent directory for directory-based skills */
  dirPath?: string;
  manifest: SkillManifest;
  enabled: boolean;
  /** Body of SKILL.md — the actual instructions */
  instructions: string;
  /** Scripts from the `scripts/` subdirectory */
  scripts: SkillScript[];
  lastModified?: number;
}
