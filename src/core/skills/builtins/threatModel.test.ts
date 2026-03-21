import { describe, it, expect } from "vitest";
import { threatModelSkill } from "./threatModel";
import { THREAT_MODEL_INSTRUCTIONS } from "./threatModelInstructions";

describe("threatModelSkill", () => {
  it("has slug 'threat-model'", () => {
    expect(threatModelSkill.slug).toBe("threat-model");
  });

  it("has a name in the manifest", () => {
    expect(threatModelSkill.manifest.name).toBe("Threat Model");
  });

  it("has a non-empty description", () => {
    expect(threatModelSkill.manifest.description).toBeTruthy();
    expect(threatModelSkill.manifest.description.length).toBeGreaterThan(10);
  });

  it("has security-related tags", () => {
    expect(threatModelSkill.manifest.tags).toContain("security");
    expect(threatModelSkill.manifest.tags).toContain("threat-modeling");
  });

  it("defines an optional 'output' input", () => {
    const outputInput = threatModelSkill.manifest.inputs?.find(
      (i) => i.name === "output",
    );
    expect(outputInput).toBeDefined();
    expect(outputInput!.required).toBe(false);
  });

  it("uses THREAT_MODEL_INSTRUCTIONS as instructions", () => {
    expect(threatModelSkill.instructions).toBe(THREAT_MODEL_INSTRUCTIONS);
  });
});
