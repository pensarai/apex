import fs from "node:fs/promises";
import { BUILTIN_SKILLS } from "./builtins";
import { parseSkillMd } from "./parser";
import { scanSkillRoots } from "./scanner";
import type { SkillEntry } from "./types";

/**
 * Central registry for all discovered skills.
 *
 * Provides catalog generation for system prompts and on-demand
 * content loading via `readSkillContent()`.
 */
export class SkillsRegistry {
  private skills = new Map<string, SkillEntry>();
  private projectRoot?: string;

  // -- Init ------------------------------------------------------------------

  async load(opts?: { projectRoot?: string }): Promise<void> {
    if (opts?.projectRoot !== undefined) {
      this.projectRoot = opts.projectRoot;
    }
    await this.refresh();
  }

  async refresh(): Promise<void> {
    const newMap = new Map<string, SkillEntry>();

    // 1. Load built-in skills first — they take precedence on slug collision
    for (const builtin of BUILTIN_SKILLS) {
      newMap.set(builtin.slug, {
        slug: builtin.slug,
        source: "builtin",
        filePath: "",
        manifest: builtin.manifest,
        scripts: [],
      });
    }

    // 2. Scan filesystem skills — first-write-wins guard in scanner + here
    const entries = await scanSkillRoots({ projectRoot: this.projectRoot });
    for (const entry of entries) {
      if (!newMap.has(entry.slug)) {
        newMap.set(entry.slug, entry);
      }
    }

    this.skills = newMap;
  }

  // -- Query -----------------------------------------------------------------

  list(): SkillEntry[] {
    return Array.from(this.skills.values());
  }

  get(slug: string): SkillEntry | undefined {
    return this.skills.get(slug);
  }

  // -- Content loading -------------------------------------------------------

  /**
   * Read a skill's full instructions from disk on demand.
   * Used by the `read_skill` tool at runtime.
   */
  async readSkillContent(
    slug: string,
  ): Promise<{ name: string; content: string }> {
    const entry = this.skills.get(slug);
    if (!entry) throw new Error(`Skill "${slug}" not found`);

    if (entry.source === "builtin") {
      const builtin = BUILTIN_SKILLS.find((b) => b.slug === slug);
      if (!builtin) throw new Error(`Built-in skill "${slug}" not found`);
      return { name: builtin.manifest.name, content: builtin.instructions };
    }

    const raw = await fs.readFile(entry.filePath, "utf-8");
    const { instructions } = parseSkillMd(raw);
    return { name: entry.manifest.name, content: instructions };
  }

  // -- Catalog for system prompt ---------------------------------------------

  /**
   * Build a compact catalog string suitable for inclusion in the system prompt.
   * Shows name, tags, and description for progressive disclosure.
   */
  buildCatalog(): string {
    const all = this.list();
    if (all.length === 0) return "";

    const lines = ["<available_skills>", ""];
    for (const entry of all) {
      const tags =
        entry.manifest.tags && entry.manifest.tags.length > 0
          ? ` (${entry.manifest.tags.join(", ")})`
          : "";
      lines.push(`- **${entry.slug}**${tags} — ${entry.manifest.description}`);
    }
    lines.push(
      "",
      "To load a skill's full instructions, use the `read_skill` tool with the skill name.",
      "</available_skills>",
    );
    return lines.join("\n");
  }
}
