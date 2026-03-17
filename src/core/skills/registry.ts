import fs from "fs/promises";
import type { SkillEntry } from "./types";
import { scanSkillRoots } from "./scanner";
import { parseSkillMd } from "./parser";

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
    const entries = await scanSkillRoots({ projectRoot: this.projectRoot });
    const newMap = new Map<string, SkillEntry>();
    for (const entry of entries) {
      newMap.set(entry.slug, entry);
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
  async readSkillContent(slug: string): Promise<{ name: string; content: string }> {
    const entry = this.skills.get(slug);
    if (!entry) throw new Error(`Skill "${slug}" not found`);
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
