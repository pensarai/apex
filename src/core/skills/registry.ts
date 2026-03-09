import type { Skill, SkillEntry } from "./types";
import { scanSkillRoots } from "./scanner";

/**
 * Central registry for all discovered skills (legacy + directory-based).
 *
 * Provides activation/deactivation lifecycle, catalog generation for
 * system prompts, and backward-compatible conversion to the legacy Skill type.
 */
export class SkillsRegistry {
  private skills = new Map<string, SkillEntry>();
  private activeSkills = new Set<string>();
  private projectRoot?: string;

  // -- Init ------------------------------------------------------------------

  async load(opts?: { projectRoot?: string }): Promise<void> {
    if (opts?.projectRoot !== undefined) {
      this.projectRoot = opts.projectRoot;
    }
    await this.refresh();
  }

  async refresh(): Promise<void> {
    const entries = await scanSkillRoots({ projectRoot: this.projectRoot });
    const newMap = new Map<string, SkillEntry>();
    for (const entry of entries) {
      newMap.set(entry.slug, entry);
    }
    this.skills = newMap;

    // Prune active skills that no longer exist
    for (const slug of this.activeSkills) {
      if (!this.skills.has(slug)) {
        this.activeSkills.delete(slug);
      }
    }
  }

  // -- Query -----------------------------------------------------------------

  list(): SkillEntry[] {
    return Array.from(this.skills.values());
  }

  listEnabled(): SkillEntry[] {
    return Array.from(this.skills.values()).filter((e) => e.enabled);
  }

  get(slug: string): SkillEntry | undefined {
    return this.skills.get(slug);
  }

  getActive(): SkillEntry[] {
    return Array.from(this.activeSkills)
      .map((slug) => this.skills.get(slug))
      .filter((e): e is SkillEntry => e !== undefined);
  }

  // -- Activation ------------------------------------------------------------

  activate(slug: string): SkillEntry {
    const entry = this.skills.get(slug);
    if (!entry) {
      throw new Error(`Skill "${slug}" not found`);
    }
    if (!entry.enabled) {
      throw new Error(`Skill "${slug}" is disabled`);
    }
    this.activeSkills.add(slug);
    return entry;
  }

  deactivate(slug: string): void {
    this.activeSkills.delete(slug);
  }

  isActive(slug: string): boolean {
    return this.activeSkills.has(slug);
  }

  /**
   * Bulk-activate skills by slug (e.g. from persisted operator state).
   * Skips any slugs that don't exist or are disabled.
   */
  restoreActive(slugs: string[]): void {
    for (const slug of slugs) {
      const entry = this.skills.get(slug);
      if (entry?.enabled) {
        this.activeSkills.add(slug);
      }
    }
  }

  // -- Enable/disable --------------------------------------------------------

  enable(slug: string): void {
    const entry = this.skills.get(slug);
    if (entry) entry.enabled = true;
  }

  disable(slug: string): void {
    const entry = this.skills.get(slug);
    if (entry) {
      entry.enabled = false;
      this.activeSkills.delete(slug);
    }
  }

  // -- Catalog for system prompt ---------------------------------------------

  /**
   * Build a compact catalog string suitable for inclusion in the system prompt.
   * Shows name, tags, and description for progressive disclosure.
   */
  buildCatalog(opts?: { maxEntries?: number }): string {
    const enabled = this.listEnabled();
    if (enabled.length === 0) return "";

    const max = opts?.maxEntries ?? enabled.length;
    const entries = enabled.slice(0, max);

    const lines = ["# Available Skills", ""];
    for (const entry of entries) {
      const tags =
        entry.manifest.tags && entry.manifest.tags.length > 0
          ? ` (${entry.manifest.tags.join(", ")})`
          : "";
      lines.push(`- **${entry.slug}**${tags} — ${entry.manifest.description}`);
    }

    if (enabled.length > max) {
      lines.push(
        `\n...and ${enabled.length - max} more. Use \`list_skills\` to see all.`,
      );
    }

    lines.push(
      "",
      "To activate a skill, use the `use_skill` tool with the skill slug.",
    );
    return lines.join("\n");
  }

  // -- Backward compat -------------------------------------------------------

  /**
   * Convert all entries to the legacy Skill[] format for existing consumers.
   */
  toLegacySkills(): Skill[] {
    return Array.from(this.skills.values()).map((entry) => ({
      name: entry.manifest.name || entry.slug,
      description: entry.manifest.description,
      content: entry.instructions,
    }));
  }
}
