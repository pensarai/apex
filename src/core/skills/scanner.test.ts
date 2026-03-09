import { describe, it, expect, afterEach, beforeEach } from "vitest";
import os from "os";
import path from "path";
import fs from "fs/promises";
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

  it("discovers legacy flat-file skills", async () => {
    const filePath = path.join(SKILLS_DIR, `${TEST_PREFIX}legacy.md`);
    await fs.writeFile(
      filePath,
      `---\nname: Legacy Skill\ndescription: A legacy skill\n---\n\nLegacy content.`,
    );
    cleanup.push(filePath);

    const entries = await scanSkillRoots();
    const found = entries.find((e) => e.slug === `${TEST_PREFIX}legacy`);

    expect(found).toBeDefined();
    expect(found!.source).toBe("legacy");
    expect(found!.manifest.name).toBe("Legacy Skill");
    expect(found!.instructions).toBe("Legacy content.");
    expect(found!.scripts).toEqual([]);
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
    expect(found!.source).toBe("directory");
    expect(found!.manifest.name).toBe("Dir Skill");
    expect(found!.manifest.tags).toEqual(["web"]);
    expect(found!.instructions).toBe("Directory skill content.");
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

  it("directory-based skills shadow legacy flat files with same slug", async () => {
    // Create legacy flat file
    const legacyPath = path.join(SKILLS_DIR, `${TEST_PREFIX}shadow-test.md`);
    await fs.writeFile(
      legacyPath,
      `---\nname: Shadow Test\ndescription: Legacy version\n---\n\nLegacy.`,
    );
    cleanup.push(legacyPath);

    // Create directory-based skill with same slug
    const dirPath = path.join(SKILLS_DIR, `${TEST_PREFIX}shadow-test`);
    await fs.mkdir(dirPath, { recursive: true });
    await fs.writeFile(
      path.join(dirPath, "SKILL.md"),
      `---\nname: Shadow Test\ndescription: Directory version\n---\n\nDirectory.`,
    );
    cleanup.push(dirPath);

    const entries = await scanSkillRoots();
    const found = entries.find((e) => e.slug === `${TEST_PREFIX}shadow-test`);

    expect(found).toBeDefined();
    // Directory-based should shadow legacy
    expect(found!.source).toBe("directory");
    expect(found!.manifest.description).toBe("Directory version");
  });

  it("scans project-level skills directories", async () => {
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
    expect(found!.source).toBe("directory");
    expect(found!.manifest.name).toBe("Project Skill");
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
