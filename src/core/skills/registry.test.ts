import { describe, it, expect, beforeEach, afterEach } from "vitest";
import os from "os";
import path from "path";
import fs from "fs/promises";
import { SkillsRegistry } from "./registry";

const TEST_PREFIX = "zzregtest-";

describe("SkillsRegistry", () => {
  let registry: SkillsRegistry;
  let tmpRoot: string;
  let skillsDir: string;

  beforeEach(async () => {
    tmpRoot = await fs.mkdtemp(path.join(os.tmpdir(), "skills-reg-test-"));
    skillsDir = path.join(tmpRoot, ".skills");
    await fs.mkdir(skillsDir, { recursive: true });
    registry = new SkillsRegistry();
  });

  afterEach(async () => {
    await fs.rm(tmpRoot, { recursive: true, force: true });
  });

  async function createDirSkill(
    slug: string,
    name: string,
    desc: string,
    tags?: string[],
  ) {
    const dirPath = path.join(skillsDir, slug);
    await fs.mkdir(dirPath, { recursive: true });
    const tagsYaml = tags
      ? `\ntags:\n${tags.map((t) => `  - ${t}`).join("\n")}`
      : "";
    await fs.writeFile(
      path.join(dirPath, "SKILL.md"),
      `---\nname: ${name}\ndescription: ${desc}${tagsYaml}\n---\n\nInstructions for ${name}.`,
    );
  }

  describe("load and list", () => {
    it("loads skills from disk", async () => {
      await createDirSkill(`${TEST_PREFIX}load-b`, "Load B", "Skill B");

      await registry.load({ projectRoot: tmpRoot });

      const all = registry.list();
      const slugs = all.map((e) => e.slug);
      expect(slugs).toContain(`${TEST_PREFIX}load-b`);
    });

    it("list returns all discovered skills", async () => {
      await createDirSkill(`${TEST_PREFIX}a`, "A", "Skill A");
      await createDirSkill(`${TEST_PREFIX}b`, "B", "Skill B");
      await registry.load({ projectRoot: tmpRoot });

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
      await registry.load({ projectRoot: tmpRoot });

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
      await registry.load({ projectRoot: tmpRoot });

      const { name, content } = await registry.readSkillContent(
        `${TEST_PREFIX}read`,
      );
      expect(name).toBe("Readable");
      expect(content).toContain("Instructions for Readable.");
    });

    it("throws for unknown slug", async () => {
      await registry.load({ projectRoot: tmpRoot });
      await expect(
        registry.readSkillContent("no-such-skill"),
      ).rejects.toThrow("not found");
    });
  });

  describe("refresh", () => {
    it("picks up new skills on refresh", async () => {
      await registry.load({ projectRoot: tmpRoot });
      const before = registry.get(`${TEST_PREFIX}refresh`);
      expect(before).toBeUndefined();

      await createDirSkill(`${TEST_PREFIX}refresh`, "Refresh", "New");
      await registry.refresh();

      const after = registry.get(`${TEST_PREFIX}refresh`);
      expect(after).toBeDefined();
    });
  });
});
