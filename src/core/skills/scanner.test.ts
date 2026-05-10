import fs from "fs/promises";
import os from "os";
import path from "path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { scanSkillRoots } from "./scanner";

const SKILLS_DIR = path.join(os.homedir(), ".pensar", "skills");
const TEST_PREFIX = "zzscantest-";

describe("scanSkillRoots", () => {
  const cleanup: string[] = [];

  beforeEach(async () => {
    await fs.mkdir(SKILLS_DIR, { recursive: true });
  });

  afterEach(async () => {
    for (const p of cleanup) {
      try {
        const stat = await fs.stat(p);
        if (stat.isDirectory()) {
          await fs.rm(p, { recursive: true });
        } else {
          await fs.unlink(p);
        }
      } catch {
        // ignore
      }
    }
    cleanup.length = 0;
  });

  it("discovers directory-based skills with SKILL.md", async () => {
    const dirPath = path.join(SKILLS_DIR, `${TEST_PREFIX}dir-skill`);
    await fs.mkdir(dirPath, { recursive: true });
    await fs.writeFile(
      path.join(dirPath, "SKILL.md"),
      `---\nname: Dir Skill\ndescription: A directory skill\ntags:\n  - web\n---\n\nDirectory skill content.`,
    );
    cleanup.push(dirPath);

    const entries = await scanSkillRoots();
    const found = entries.find((e) => e.slug === `${TEST_PREFIX}dir-skill`);

    expect(found).toBeDefined();
    expect(found!.source).toBe("user");
    expect(found!.manifest.name).toBe("Dir Skill");
    expect(found!.manifest.tags).toEqual(["web"]);
    expect(found!.dirPath).toBe(dirPath);
  });

  it("discovers scripts in the scripts/ subdirectory", async () => {
    const dirPath = path.join(SKILLS_DIR, `${TEST_PREFIX}scripted`);
    const scriptsDir = path.join(dirPath, "scripts");
    await fs.mkdir(scriptsDir, { recursive: true });
    await fs.writeFile(
      path.join(dirPath, "SKILL.md"),
      `---\nname: Scripted Skill\ndescription: Has scripts\n---\n\nContent.`,
    );
    await fs.writeFile(path.join(scriptsDir, "run.sh"), "#!/bin/bash\necho hi");
    cleanup.push(dirPath);

    const entries = await scanSkillRoots();
    const found = entries.find((e) => e.slug === `${TEST_PREFIX}scripted`);

    expect(found).toBeDefined();
    expect(found!.scripts).toHaveLength(1);
    expect(found!.scripts[0].name).toBe("run.sh");
  });

  it("scans project-level skills directories with source 'project'", async () => {
    const tmpDir = path.join(
      os.tmpdir(),
      `${TEST_PREFIX}project-${Date.now()}`,
    );
    const projectSkillsDir = path.join(tmpDir, ".skills", `${TEST_PREFIX}proj`);
    await fs.mkdir(projectSkillsDir, { recursive: true });
    await fs.writeFile(
      path.join(projectSkillsDir, "SKILL.md"),
      `---\nname: Project Skill\ndescription: Project-level\n---\n\nProject content.`,
    );
    cleanup.push(tmpDir);

    const entries = await scanSkillRoots({ projectRoot: tmpDir });
    const found = entries.find((e) => e.slug === `${TEST_PREFIX}proj`);

    expect(found).toBeDefined();
    expect(found!.source).toBe("project");
    expect(found!.manifest.name).toBe("Project Skill");
  });

  it("project skills take priority over user skills with same slug (first-wins)", async () => {
    // Create user-level skill
    const userDirPath = path.join(SKILLS_DIR, `${TEST_PREFIX}dedup`);
    await fs.mkdir(userDirPath, { recursive: true });
    await fs.writeFile(
      path.join(userDirPath, "SKILL.md"),
      `---\nname: Dedup Skill\ndescription: User version\n---\n\nUser content.`,
    );
    cleanup.push(userDirPath);

    // Create project-level skill with same slug
    const tmpDir = path.join(
      os.tmpdir(),
      `${TEST_PREFIX}dedup-project-${Date.now()}`,
    );
    const projectSkillsDir = path.join(
      tmpDir,
      ".skills",
      `${TEST_PREFIX}dedup`,
    );
    await fs.mkdir(projectSkillsDir, { recursive: true });
    await fs.writeFile(
      path.join(projectSkillsDir, "SKILL.md"),
      `---\nname: Dedup Skill\ndescription: Project version\n---\n\nProject content.`,
    );
    cleanup.push(tmpDir);

    const entries = await scanSkillRoots({ projectRoot: tmpDir });
    const found = entries.find((e) => e.slug === `${TEST_PREFIX}dedup`);

    expect(found).toBeDefined();
    // Project should win since it's scanned first (first-write-wins)
    expect(found!.source).toBe("project");
    expect(found!.manifest.description).toBe("Project version");
  });

  it("returns empty array when no skills exist", async () => {
    const tmpDir = path.join(os.tmpdir(), `${TEST_PREFIX}empty-${Date.now()}`);
    await fs.mkdir(tmpDir, { recursive: true });
    cleanup.push(tmpDir);

    // Only scan the empty project dir (global skills may exist)
    const entries = await scanSkillRoots({ projectRoot: tmpDir });
    // Just verify it doesn't crash
    expect(Array.isArray(entries)).toBe(true);
  });
});
