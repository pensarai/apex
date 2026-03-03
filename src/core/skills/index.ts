import os from "os";
import path from "path";
import fs from "fs/promises";
import type { Skill, SkillFrontmatter } from "./types";

export type { Skill, SkillFrontmatter };

const SKILLS_DIR = path.join(os.homedir(), ".pensar", "skills");

/** Ensure the skills directory exists. */
async function ensureSkillsDir(): Promise<void> {
  await fs.mkdir(SKILLS_DIR, { recursive: true });
}

/**
 * Parse simple YAML-style frontmatter from a markdown string.
 * Returns the parsed key-value pairs and the body after the frontmatter.
 */
function parseFrontmatter(raw: string): {
  meta: SkillFrontmatter;
  body: string;
} {
  const trimmed = raw.trimStart();
  if (!trimmed.startsWith("---")) {
    return { meta: {}, body: raw };
  }

  const endIdx = trimmed.indexOf("---", 3);
  if (endIdx === -1) {
    return { meta: {}, body: raw };
  }

  const frontmatterBlock = trimmed.slice(3, endIdx).trim();
  const body = trimmed.slice(endIdx + 3).trim();
  const meta: Record<string, string> = {};

  for (const line of frontmatterBlock.split("\n")) {
    const colonIdx = line.indexOf(":");
    if (colonIdx === -1) continue;
    const key = line.slice(0, colonIdx).trim();
    const value = line.slice(colonIdx + 1).trim();
    meta[key] = value;
  }

  return { meta: meta as SkillFrontmatter, body };
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

/** Convert a display name to a filename-safe slug. */
export function slugify(name: string): string {
  return name
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "");
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
      const { meta, body } = parseFrontmatter(raw);
      const slug = entry.replace(/\.md$/, "");

      skills.push({
        name: meta.name || slug,
        description: meta.description || "",
        content: body,
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
    const { meta, body } = parseFrontmatter(raw);
    return {
      name: meta.name || slug,
      description: meta.description || "",
      content: body,
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
