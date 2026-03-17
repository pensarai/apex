import path from "path";
import fs from "fs/promises";
import type { Dirent } from "fs";
import type { SkillEntry, SkillScript, SkillSource } from "./types";
import { parseSkillMd } from "./parser";
import {
  SKILLS_DIR as GLOBAL_SKILLS_DIR,
  AGENTS_SKILLS_DIR,
  slugify,
} from "./utils";

/**
 * Scan all skill roots and return a deduplicated list of SkillEntry objects.
 *
 * Scan order (first-write-wins dedup — project skills take priority):
 *   1. Project: .skills/, .claude/skills/, skills/ → source: "project"
 *   2. User: ~/.agents/skills/ → source: "user"
 *   3. User: ~/.pensar/skills/ → source: "user" (directory-based only)
 */
export async function scanSkillRoots(opts?: {
  projectRoot?: string;
}): Promise<SkillEntry[]> {
  const entries = new Map<string, SkillEntry>();

  // 1. Project-level directories (first-wins, so scan these first)
  if (opts?.projectRoot) {
    const projectDirs = [
      path.join(opts.projectRoot, ".skills"),
      path.join(opts.projectRoot, ".claude", "skills"),
      path.join(opts.projectRoot, "skills"),
    ];
    for (const dir of projectDirs) {
      await scanDirectorySkills(dir, entries, "project");
    }
  }

  // 2. skills.sh CLI global install directory (~/.agents/skills/)
  await scanDirectorySkills(AGENTS_SKILLS_DIR, entries, "user");

  // 3. Pensar global skills directory (~/.pensar/skills/) — directory-based only
  await scanDirectorySkills(GLOBAL_SKILLS_DIR, entries, "user");

  return Array.from(entries.values());
}

/**
 * Scan a directory for skills.sh-style directory-based skills.
 * Looks for subdirectories containing SKILL.md.
 * Uses first-write-wins dedup — if a slug already exists, it is skipped.
 */
async function scanDirectorySkills(
  parentDir: string,
  entries: Map<string, SkillEntry>,
  source: SkillSource,
): Promise<void> {
  let dirEntries: Dirent[];
  try {
    dirEntries = await fs.readdir(parentDir, { withFileTypes: true });
  } catch {
    return;
  }

  // Parallel reads within a single directory
  await Promise.all(
    dirEntries
      .filter((d) => d.isDirectory())
      .map(async (dirent) => {
        const dirPath = path.join(parentDir, dirent.name);
        const skillMdPath = path.join(dirPath, "SKILL.md");
        try {
          const raw = await fs.readFile(skillMdPath, "utf-8");
          const { manifest } = parseSkillMd(raw);
          const slug = slugify(dirent.name);
          const scripts = await discoverScripts(dirPath);

          // First-write-wins dedup
          if (!entries.has(slug)) {
            entries.set(slug, {
              slug,
              source,
              filePath: skillMdPath,
              dirPath,
              manifest,
              scripts,
            });
          }
        } catch {
          // Skip directories without valid SKILL.md
        }
      }),
  );
}

/**
 * Enumerate script files in a skill's scripts/ subdirectory.
 */
async function discoverScripts(skillDir: string): Promise<SkillScript[]> {
  const scriptsDir = path.join(skillDir, "scripts");
  let dirEntries: Dirent[];
  try {
    dirEntries = await fs.readdir(scriptsDir, { withFileTypes: true });
  } catch {
    return [];
  }

  const scripts: SkillScript[] = [];
  for (const dirent of dirEntries) {
    if (!dirent.isFile()) continue;
    scripts.push({
      name: dirent.name,
      path: path.join(scriptsDir, dirent.name),
    });
  }
  return scripts;
}
