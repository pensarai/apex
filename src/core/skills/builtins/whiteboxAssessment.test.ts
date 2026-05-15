import { describe, expect, it } from "vitest";
import { SkillsRegistry } from "../registry";
import {
  whiteboxAssessmentSkill,
  whiteboxScriptsRoot,
} from "./whiteboxAssessment";

describe("whitebox-assessment built-in skill", () => {
  it("has the expected slug and tags", () => {
    expect(whiteboxAssessmentSkill.slug).toBe("whitebox-assessment");
    expect(whiteboxAssessmentSkill.manifest.tags).toEqual(
      expect.arrayContaining(["security", "sast", "whitebox"]),
    );
  });

  it("registers in the SkillsRegistry under source=builtin", async () => {
    const registry = new SkillsRegistry();
    await registry.load();

    const entry = registry.get("whitebox-assessment");
    expect(entry).toBeDefined();
    expect(entry?.source).toBe("builtin");
  });

  it("returns its instructions via readSkillContent", async () => {
    const registry = new SkillsRegistry();
    await registry.load();

    const { name, content } = await registry.readSkillContent(
      "whitebox-assessment",
    );
    expect(name).toBe("Whitebox Assessment");
    // Body should reference the core moves the playbook documents.
    expect(content).toMatch(/profile the codebase/i);
    expect(content).toMatch(/scanner/i);
    expect(content).toMatch(/whitebox-seed/);
    // Scripts root path should be baked into the body so the agent can
    // invoke recipe scripts via execute_command without guessing.
    expect(content).toContain(whiteboxScriptsRoot());
  });

  it("appears in the catalog string", async () => {
    const registry = new SkillsRegistry();
    await registry.load();

    const catalog = registry.buildCatalog();
    expect(catalog).toContain("whitebox-assessment");
    expect(catalog).toContain("Source-aware security assessment");
  });
});
