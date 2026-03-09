import { describe, it, expect } from "vitest";
import { parseSkillMd, parseLegacySkillMd } from "./parser";

describe("parseSkillMd", () => {
  it("parses a valid SKILL.md with full manifest", () => {
    const raw = `---
name: SQL Injection
description: Advanced SQL injection testing methodology
version: "1.2.0"
tags:
  - web
  - sqli
triggers:
  - sql
  - injection
inputs:
  - name: target_url
    description: The URL to test
    required: true
outputs:
  - name: findings
    description: Discovered SQL injection points
---

# SQL Injection Methodology

Step 1: Identify input parameters...`;

    const { manifest, instructions } = parseSkillMd(raw);

    expect(manifest.name).toBe("SQL Injection");
    expect(manifest.description).toBe(
      "Advanced SQL injection testing methodology",
    );
    expect(manifest.version).toBe("1.2.0");
    expect(manifest.tags).toEqual(["web", "sqli"]);
    expect(manifest.triggers).toEqual(["sql", "injection"]);
    expect(manifest.inputs).toEqual([
      {
        name: "target_url",
        description: "The URL to test",
        required: true,
      },
    ]);
    expect(manifest.outputs).toEqual([
      {
        name: "findings",
        description: "Discovered SQL injection points",
      },
    ]);
    expect(instructions).toContain("# SQL Injection Methodology");
    expect(instructions).toContain("Step 1: Identify input parameters...");
  });

  it("parses minimal SKILL.md with only required fields", () => {
    const raw = `---
name: Basic Skill
description: A simple skill
---

Do stuff.`;

    const { manifest, instructions } = parseSkillMd(raw);
    expect(manifest.name).toBe("Basic Skill");
    expect(manifest.description).toBe("A simple skill");
    expect(manifest.version).toBeUndefined();
    expect(manifest.tags).toBeUndefined();
    expect(instructions).toBe("Do stuff.");
  });

  it("throws when missing opening ---", () => {
    expect(() => parseSkillMd("name: test")).toThrow(
      "missing YAML frontmatter",
    );
  });

  it("throws when missing closing ---", () => {
    expect(() => parseSkillMd("---\nname: test\ndescription: foo\n")).toThrow(
      "missing closing ---",
    );
  });

  it("throws when name is missing", () => {
    expect(() => parseSkillMd("---\ndescription: test\n---\nbody")).toThrow(
      "missing required field: name",
    );
  });

  it("throws when description is missing", () => {
    expect(() => parseSkillMd("---\nname: test\n---\nbody")).toThrow(
      "missing required field: description",
    );
  });

  it("handles empty instructions body", () => {
    const raw = `---
name: Empty
description: No body
---`;

    const { manifest, instructions } = parseSkillMd(raw);
    expect(manifest.name).toBe("Empty");
    expect(instructions).toBe("");
  });

  it("filters non-string values from tags array", () => {
    const raw = `---
name: Test
description: Test skill
tags:
  - web
  - 123
---
body`;

    const { manifest } = parseSkillMd(raw);
    // 123 is parsed as a number by yaml, so it should be filtered
    expect(manifest.tags).toEqual(["web"]);
  });
});

describe("parseLegacySkillMd", () => {
  it("parses a legacy skill with frontmatter", () => {
    const raw = `---
name: SQL Injection Test
description: A test skill for SQL injection
---

Run the SQL injection tests.`;

    const { name, description, content } = parseLegacySkillMd(raw);
    expect(name).toBe("SQL Injection Test");
    expect(description).toBe("A test skill for SQL injection");
    expect(content).toBe("Run the SQL injection tests.");
  });

  it("returns empty metadata when no frontmatter", () => {
    const raw = "Just plain content.";
    const { name, description, content } = parseLegacySkillMd(raw);
    expect(name).toBe("");
    expect(description).toBe("");
    expect(content).toBe("Just plain content.");
  });

  it("returns empty metadata when frontmatter is unclosed", () => {
    const raw = "---\nname: test\nno closing";
    const { name, description, content } = parseLegacySkillMd(raw);
    expect(name).toBe("");
    expect(content).toBe(raw);
  });
});
