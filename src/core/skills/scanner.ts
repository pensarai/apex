import path from "path";
import fs from "fs/promises";
import type { Dirent } from "fs";
import type { SkillEntry, SkillScript } from "./types";
import { parseSkillMd, parseLegacySkillMd } from "./parser";
import {
  SKILLS_DIR as GLOBAL_SKILLS_DIR,
  AGENTS_SKILLS_DIR,
  slugify,
} from "./utils";

/**
 * Scan all skill roots and return a deduplicated list of SkillEntry objects.
 *
 * Scan order (later entries shadow earlier by slug):
 *   1. Global legacy flat files in ~/.pensar/skills/
 *   2. Global directory-based skills in ~/.pensar/skills/
 *   3. skills.sh CLI global installs in ~/.agents/skills/
 *   4. Project .skills directory
 *   5. Project .claude/skills directory
 *   6. Project skills directory
 */
export async function scanSkillRoots(opts?: {
  projectRoot?: string;
}): Promise<SkillEntry[]> {
  const entries = new Map<string, SkillEntry>();

  // 1 & 2. Pensar global skills: read directory once, split into legacy files + subdirs
  await scanGlobalSkillsDir(GLOBAL_SKILLS_DIR, entries);

  // 3. skills.sh CLI global install directory (~/.agents/skills/)
  await scanDirectorySkills(AGENTS_SKILLS_DIR, entries);

  // 4-6. Project-level directories (sequential to preserve shadowing order)
  if (opts?.projectRoot) {
    const projectDirs = [
      path.join(opts.projectRoot, ".skills"),
      path.join(opts.projectRoot, ".claude", "skills"),
      path.join(opts.projectRoot, "skills"),
    ];
    for (const dir of projectDirs) {
      await scanDirectorySkills(dir, entries);
    }
  }

  return Array.from(entries.values());
}

/**
 * Scan the global skills directory in a single readdir call.
 * Handles both legacy flat-file skills (*.md) and directory-based skills.
 * Legacy entries are inserted first, then directory-based entries shadow them.
 */
async function scanGlobalSkillsDir(
  dir: string,
  entries: Map<string, SkillEntry>,
): Promise<void> {
  let dirEntries: Dirent[];
  try {
    dirEntries = await fs.readdir(dir, { withFileTypes: true });
  } catch {
    return;
  }

  const legacyFiles = dirEntries.filter(
    (d) => !d.isDirectory() && d.name.endsWith(".md"),
  );
  const subDirs = dirEntries.filter((d) => d.isDirectory());

  // 1. Legacy flat files (parallel reads)
  await Promise.all(
    legacyFiles.map(async (dirent) => {
      const filePath = path.join(dir, dirent.name);
      try {
        const raw = await fs.readFile(filePath, "utf-8");
        const { name, description, content } = parseLegacySkillMd(raw);
        const slug = slugify(dirent.name.replace(/\.md$/, ""));

        entries.set(slug, {
          slug,
          source: "legacy",
          filePath,
          manifest: {
            name: name || slug,
            description: description || "",
          },
          enabled: true,
          instructions: content,
          scripts: [],
        });
      } catch {
        // Skip unreadable files
      }
    }),
  );

  // 2. Directory-based skills (parallel reads, shadow legacy by slug)
  await Promise.all(
    subDirs.map(async (dirent) => {
      const dirPath = path.join(dir, dirent.name);
      const skillMdPath = path.join(dirPath, "SKILL.md");
      try {
        const raw = await fs.readFile(skillMdPath, "utf-8");
        const { manifest, instructions } = parseSkillMd(raw);
        const slug = slugify(dirent.name);
        const scripts = await discoverScripts(dirPath);

        entries.set(slug, {
          slug,
          source: "directory",
          filePath: skillMdPath,
          dirPath,
          manifest,
          enabled: true,
          instructions,
          scripts,
        });
      } catch {
        // Skip directories without valid SKILL.md
      }
    }),
  );
}

/**
 * Scan a directory for skills.sh-style directory-based skills.
 * Looks for subdirectories containing SKILL.md.
 */
async function scanDirectorySkills(
  parentDir: string,
  entries: Map<string, SkillEntry>,
): Promise<void> {
  let dirEntries: Dirent[];
  try {
    dirEntries = await fs.readdir(parentDir, { withFileTypes: true });
  } catch {
    return;
  }

  // Parallel reads within a single directory (order doesn't matter for same-priority entries)
  await Promise.all(
    dirEntries
      .filter((d) => d.isDirectory())
      .map(async (dirent) => {
        const dirPath = path.join(parentDir, dirent.name);
        const skillMdPath = path.join(dirPath, "SKILL.md");
        try {
          const raw = await fs.readFile(skillMdPath, "utf-8");
          const { manifest, instructions } = parseSkillMd(raw);
          const slug = slugify(dirent.name);
          const scripts = await discoverScripts(dirPath);

          entries.set(slug, {
            slug,
            source: "directory",
            filePath: skillMdPath,
            dirPath,
            manifest,
            enabled: true,
            instructions,
            scripts,
          });
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
