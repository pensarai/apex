import path from "path";
import fs from "fs/promises";
import type { Skill, SkillFrontmatter } from "./types";
import { SkillsRegistry } from "./registry";
import { parseLegacySkillMd } from "./parser";
import { SKILLS_DIR, slugify } from "./utils";

export type { Skill, SkillFrontmatter };
export type {
  SkillEntry,
  SkillManifest,
  SkillScript,
  SkillSource,
} from "./types";
export { SkillsRegistry } from "./registry";
export { parseSkillMd, parseLegacySkillMd } from "./parser";
export { scanSkillRoots } from "./scanner";
export { slugify } from "./utils";

/** Create a new SkillsRegistry instance. */
export function createSkillsRegistry(): SkillsRegistry {
  return new SkillsRegistry();
}

/** Ensure the skills directory exists. */
async function ensureSkillsDir(): Promise<void> {
  await fs.mkdir(SKILLS_DIR, { recursive: true });
}

/** Serialize a skill into a markdown string with frontmatter. */
function serializeSkill(skill: Skill): string {
  const lines = [
    "---",
    `name: ${skill.name}`,
    `description: ${skill.description}`,
    "---",
    "",
    skill.content,
  ];
  return lines.join("\n");
}

/** Load all skills from ~/.pensar/skills/ */
export async function loadSkills(): Promise<Skill[]> {
  await ensureSkillsDir();

  let entries: string[];
  try {
    entries = await fs.readdir(SKILLS_DIR);
  } catch {
    return [];
  }

  const skills: Skill[] = [];

  for (const entry of entries) {
    if (!entry.endsWith(".md")) continue;

    const filePath = path.join(SKILLS_DIR, entry);
    try {
      const raw = await fs.readFile(filePath, "utf-8");
      const { name, description, content } = parseLegacySkillMd(raw);
      const slug = entry.replace(/\.md$/, "");

      skills.push({
        name: name || slug,
        description: description || "",
        content,
      });
    } catch {
      // Skip unreadable files
    }
  }

  skills.sort((a, b) => a.name.localeCompare(b.name));
  return skills;
}

/** Load a single skill by slug. */
export async function loadSkill(slug: string): Promise<Skill | null> {
  const filePath = path.join(SKILLS_DIR, `${slug}.md`);
  try {
    const raw = await fs.readFile(filePath, "utf-8");
    const { name, description, content } = parseLegacySkillMd(raw);
    return {
      name: name || slug,
      description: description || "",
      content,
    };
  } catch {
    return null;
  }
}

/** Save a skill to ~/.pensar/skills/{slug}.md */
export async function saveSkill(skill: Skill): Promise<string> {
  await ensureSkillsDir();
  const slug = slugify(skill.name);
  const filePath = path.join(SKILLS_DIR, `${slug}.md`);
  await fs.writeFile(filePath, serializeSkill(skill), "utf-8");
  return slug;
}

/** Delete a skill by slug. */
export async function deleteSkill(slug: string): Promise<boolean> {
  const filePath = path.join(SKILLS_DIR, `${slug}.md`);
  try {
    await fs.unlink(filePath);
    return true;
  } catch {
    return false;
  }
}

/** Check if a skill slug already exists. */
export async function skillExists(slug: string): Promise<boolean> {
  const filePath = path.join(SKILLS_DIR, `${slug}.md`);
  try {
    await fs.access(filePath);
    return true;
  } catch {
    return false;
  }
}
