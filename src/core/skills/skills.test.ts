import { describe, it, expect, afterEach } from "vitest";
import os from "os";
import path from "path";
import fs from "fs/promises";
import {
  loadSkills,
  loadSkill,
  saveSkill,
  deleteSkill,
  skillExists,
  slugify,
} from "./index";

const SKILLS_DIR = path.join(os.homedir(), ".pensar", "skills");

describe("Skills Module", () => {
  const testSkillFiles: string[] = [];

  afterEach(async () => {
    for (const f of testSkillFiles) {
      try {
        await fs.unlink(f);
      } catch {
        // ignore
      }
    }
    testSkillFiles.length = 0;
  });

  describe("slugify", () => {
    it("converts a name to a slug", () => {
      expect(slugify("SQL Injection Test")).toBe("sql-injection-test");
    });

    it("strips leading/trailing dashes", () => {
      expect(slugify("--Hello World--")).toBe("hello-world");
    });

    it("replaces special characters", () => {
      expect(slugify("OWASP Top 10 (2025)")).toBe("owasp-top-10-2025");
    });

    it("handles empty string", () => {
      expect(slugify("")).toBe("");
    });
  });

  describe("saveSkill / loadSkill", () => {
    it("saves and loads a skill with frontmatter", async () => {
      const skill = {
        name: "test-save-load",
        description: "A test skill",
        content: "Do the thing.\nLine 2.",
      };
      const slug = await saveSkill(skill);
      testSkillFiles.push(path.join(SKILLS_DIR, `${slug}.md`));

      expect(slug).toBe("test-save-load");

      const loaded = await loadSkill(slug);
      expect(loaded).not.toBeNull();
      expect(loaded!.name).toBe("test-save-load");
      expect(loaded!.description).toBe("A test skill");
      expect(loaded!.content).toBe("Do the thing.\nLine 2.");
    });
  });

  describe("loadSkills", () => {
    it("returns all skills sorted by name", async () => {
      await saveSkill({
        name: "zzz-skill",
        description: "Z",
        content: "z content",
      });
      testSkillFiles.push(path.join(SKILLS_DIR, "zzz-skill.md"));

      await saveSkill({
        name: "aaa-skill",
        description: "A",
        content: "a content",
      });
      testSkillFiles.push(path.join(SKILLS_DIR, "aaa-skill.md"));

      const skills = await loadSkills();
      const names = skills.map((s) => s.name);
      expect(names).toContain("aaa-skill");
      expect(names).toContain("zzz-skill");

      const aIdx = names.indexOf("aaa-skill");
      const zIdx = names.indexOf("zzz-skill");
      expect(aIdx).toBeLessThan(zIdx);
    });
  });

  describe("skillExists", () => {
    it("returns true for existing skill", async () => {
      await saveSkill({
        name: "existence-check",
        description: "",
        content: "x",
      });
      testSkillFiles.push(path.join(SKILLS_DIR, "existence-check.md"));

      expect(await skillExists("existence-check")).toBe(true);
    });

    it("returns false for non-existing skill", async () => {
      expect(await skillExists("does-not-exist-123")).toBe(false);
    });
  });

  describe("deleteSkill", () => {
    it("deletes an existing skill", async () => {
      await saveSkill({
        name: "to-delete",
        description: "",
        content: "bye",
      });
      expect(await skillExists("to-delete")).toBe(true);

      const deleted = await deleteSkill("to-delete");
      expect(deleted).toBe(true);
      expect(await skillExists("to-delete")).toBe(false);
    });

    it("returns false for non-existing skill", async () => {
      const deleted = await deleteSkill("never-existed-456");
      expect(deleted).toBe(false);
    });
  });
});
