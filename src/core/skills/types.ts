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
