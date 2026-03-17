import { describe, it, expect, beforeEach, afterEach } from "vitest";
import os from "os";
import path from "path";
import fs from "fs/promises";
import { SkillsRegistry } from "./registry";

const SKILLS_DIR = path.join(os.homedir(), ".pensar", "skills");
const TEST_PREFIX = "zzregtest-";

describe("SkillsRegistry", () => {
  let registry: SkillsRegistry;
  const cleanup: string[] = [];

  beforeEach(async () => {
    registry = new SkillsRegistry();
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

  async function createDirSkill(
    slug: string,
    name: string,
    desc: string,
    tags?: string[],
  ) {
    const dirPath = path.join(SKILLS_DIR, slug);
    await fs.mkdir(dirPath, { recursive: true });
    const tagsYaml = tags
      ? `\ntags:\n${tags.map((t) => `  - ${t}`).join("\n")}`
      : "";
    await fs.writeFile(
      path.join(dirPath, "SKILL.md"),
      `---\nname: ${name}\ndescription: ${desc}${tagsYaml}\n---\n\nInstructions for ${name}.`,
    );
    cleanup.push(dirPath);
  }

  describe("load and list", () => {
    it("loads skills from disk", async () => {
      await createDirSkill(`${TEST_PREFIX}load-b`, "Load B", "Skill B");

      await registry.load();

      const all = registry.list();
      const slugs = all.map((e) => e.slug);
      expect(slugs).toContain(`${TEST_PREFIX}load-b`);
    });

    it("list returns all discovered skills", async () => {
      await createDirSkill(`${TEST_PREFIX}a`, "A", "Skill A");
      await createDirSkill(`${TEST_PREFIX}b`, "B", "Skill B");
      await registry.load();

      const all = registry.list();
      const slugs = all.map((e) => e.slug);
      expect(slugs).toContain(`${TEST_PREFIX}a`);
      expect(slugs).toContain(`${TEST_PREFIX}b`);
    });
  });

  describe("buildCatalog", () => {
    it("returns empty string when no skills", async () => {
      const emptyRegistry = new SkillsRegistry();
      expect(emptyRegistry.buildCatalog()).toBe("");
    });

    it("includes skill name, description, and tags in <available_skills> format", async () => {
      await createDirSkill(
        `${TEST_PREFIX}cat`,
        "Catalog Skill",
        "A cataloged skill",
        ["web", "api"],
      );
      await registry.load();

      const catalog = registry.buildCatalog();
      expect(catalog).toContain("<available_skills>");
      expect(catalog).toContain("</available_skills>");
      expect(catalog).toContain(`${TEST_PREFIX}cat`);
      expect(catalog).toContain("(web, api)");
      expect(catalog).toContain("A cataloged skill");
      expect(catalog).toContain("read_skill");
    });
  });

  describe("readSkillContent", () => {
    it("reads skill instructions from disk", async () => {
      await createDirSkill(
        `${TEST_PREFIX}read`,
        "Readable",
        "A readable skill",
      );
      await registry.load();

      const { name, content } = await registry.readSkillContent(
        `${TEST_PREFIX}read`,
      );
      expect(name).toBe("Readable");
      expect(content).toContain("Instructions for Readable.");
    });

    it("throws for unknown slug", async () => {
      await registry.load();
      await expect(
        registry.readSkillContent("no-such-skill"),
      ).rejects.toThrow("not found");
    });
  });

  describe("refresh", () => {
    it("picks up new skills on refresh", async () => {
      await registry.load();
      const before = registry.get(`${TEST_PREFIX}refresh`);
      expect(before).toBeUndefined();

      await createDirSkill(`${TEST_PREFIX}refresh`, "Refresh", "New");
      await registry.refresh();

      const after = registry.get(`${TEST_PREFIX}refresh`);
      expect(after).toBeDefined();
    });
  });
});
