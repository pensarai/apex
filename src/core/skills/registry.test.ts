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

  async function createLegacySkill(slug: string, name: string, desc: string) {
    const filePath = path.join(SKILLS_DIR, `${slug}.md`);
    await fs.writeFile(
      filePath,
      `---\nname: ${name}\ndescription: ${desc}\n---\n\nContent for ${name}.`,
    );
    cleanup.push(filePath);
  }

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
      await createLegacySkill(`${TEST_PREFIX}load-a`, "Load A", "Skill A");
      await createDirSkill(`${TEST_PREFIX}load-b`, "Load B", "Skill B");

      await registry.load();

      const all = registry.list();
      const slugs = all.map((e) => e.slug);
      expect(slugs).toContain(`${TEST_PREFIX}load-a`);
      expect(slugs).toContain(`${TEST_PREFIX}load-b`);
    });

    it("listEnabled returns only enabled skills", async () => {
      await createLegacySkill(
        `${TEST_PREFIX}enabled`,
        "Enabled",
        "An enabled skill",
      );
      await registry.load();

      expect(registry.listEnabled().length).toBeGreaterThan(0);

      registry.disable(`${TEST_PREFIX}enabled`);
      const enabled = registry.listEnabled();
      const slugs = enabled.map((e) => e.slug);
      expect(slugs).not.toContain(`${TEST_PREFIX}enabled`);
    });
  });

  describe("activate / deactivate", () => {
    it("activates and deactivates a skill", async () => {
      await createLegacySkill(`${TEST_PREFIX}act`, "Act", "To activate");
      await registry.load();

      expect(registry.isActive(`${TEST_PREFIX}act`)).toBe(false);

      const entry = registry.activate(`${TEST_PREFIX}act`);
      expect(entry.slug).toBe(`${TEST_PREFIX}act`);
      expect(registry.isActive(`${TEST_PREFIX}act`)).toBe(true);
      expect(registry.getActive()).toHaveLength(1);

      registry.deactivate(`${TEST_PREFIX}act`);
      expect(registry.isActive(`${TEST_PREFIX}act`)).toBe(false);
      expect(registry.getActive()).toHaveLength(0);
    });

    it("throws when activating non-existent skill", async () => {
      await registry.load();
      expect(() => registry.activate("no-such-skill")).toThrow("not found");
    });

    it("throws when activating disabled skill", async () => {
      await createLegacySkill(
        `${TEST_PREFIX}dis`,
        "Disabled",
        "Will be disabled",
      );
      await registry.load();
      registry.disable(`${TEST_PREFIX}dis`);

      expect(() => registry.activate(`${TEST_PREFIX}dis`)).toThrow("disabled");
    });

    it("restoreActive re-activates persisted slugs", async () => {
      await createLegacySkill(`${TEST_PREFIX}restore`, "Restore", "Restorable");
      await registry.load();

      registry.restoreActive([`${TEST_PREFIX}restore`, "nonexistent"]);
      expect(registry.isActive(`${TEST_PREFIX}restore`)).toBe(true);
      // nonexistent should be silently skipped
      expect(registry.getActive()).toHaveLength(1);
    });
  });

  describe("buildCatalog", () => {
    it("returns empty string when no skills", async () => {
      // Create a fresh registry without loading any skills
      const emptyRegistry = new SkillsRegistry();
      expect(emptyRegistry.buildCatalog()).toBe("");
    });

    it("includes skill name, description, and tags", async () => {
      await createDirSkill(
        `${TEST_PREFIX}cat`,
        "Catalog Skill",
        "A cataloged skill",
        ["web", "api"],
      );
      await registry.load();

      const catalog = registry.buildCatalog();
      expect(catalog).toContain("# Available Skills");
      expect(catalog).toContain(`${TEST_PREFIX}cat`);
      expect(catalog).toContain("(web, api)");
      expect(catalog).toContain("A cataloged skill");
      expect(catalog).toContain("use_skill");
    });

    it("respects maxEntries limit", async () => {
      await createLegacySkill(`${TEST_PREFIX}x1`, "X1", "First");
      await createLegacySkill(`${TEST_PREFIX}x2`, "X2", "Second");
      await registry.load();

      const catalog = registry.buildCatalog({ maxEntries: 1 });
      // Should show truncation message
      expect(catalog).toContain("more");
    });
  });

  describe("toLegacySkills", () => {
    it("converts entries to legacy Skill format", async () => {
      await createLegacySkill(
        `${TEST_PREFIX}legacy`,
        "Legacy Convert",
        "Description",
      );
      await registry.load();

      const legacy = registry.toLegacySkills();
      const found = legacy.find((s) => s.name === "Legacy Convert");
      expect(found).toBeDefined();
      expect(found!.description).toBe("Description");
      expect(found!.content).toContain("Content for Legacy Convert");
    });
  });

  describe("refresh", () => {
    it("picks up new skills on refresh", async () => {
      await registry.load();
      const before = registry.get(`${TEST_PREFIX}refresh`);
      expect(before).toBeUndefined();

      await createLegacySkill(`${TEST_PREFIX}refresh`, "Refresh", "New");
      await registry.refresh();

      const after = registry.get(`${TEST_PREFIX}refresh`);
      expect(after).toBeDefined();
    });

    it("prunes active skills that no longer exist on refresh", async () => {
      await createLegacySkill(
        `${TEST_PREFIX}prune`,
        "Prune",
        "Will be removed",
      );
      await registry.load();
      registry.activate(`${TEST_PREFIX}prune`);
      expect(registry.isActive(`${TEST_PREFIX}prune`)).toBe(true);

      // Delete the file
      await fs.unlink(path.join(SKILLS_DIR, `${TEST_PREFIX}prune.md`));
      await registry.refresh();

      expect(registry.isActive(`${TEST_PREFIX}prune`)).toBe(false);
    });
  });
});
