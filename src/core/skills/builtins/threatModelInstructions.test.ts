import { describe, it, expect } from "vitest";
import { THREAT_MODEL_INSTRUCTIONS } from "./threatModelInstructions";

describe("THREAT_MODEL_INSTRUCTIONS", () => {
  it("exports a non-empty string", () => {
    expect(typeof THREAT_MODEL_INSTRUCTIONS).toBe("string");
    expect(THREAT_MODEL_INSTRUCTIONS.length).toBeGreaterThan(100);
  });

  it("contains all eight analysis phases", () => {
    expect(THREAT_MODEL_INSTRUCTIONS).toContain(
      "Phase 1: Application Identity",
    );
    expect(THREAT_MODEL_INSTRUCTIONS).toContain(
      "Phase 2: Features & Capabilities",
    );
    expect(THREAT_MODEL_INSTRUCTIONS).toContain("Phase 3: Trust Boundaries");
    expect(THREAT_MODEL_INSTRUCTIONS).toContain("Phase 4: Attacker Profiles");
    expect(THREAT_MODEL_INSTRUCTIONS).toContain("Phase 5: Deployment Model");
    expect(THREAT_MODEL_INSTRUCTIONS).toContain("Phase 6: Security Controls");
    expect(THREAT_MODEL_INSTRUCTIONS).toContain("Phase 7: System Architecture");
    expect(THREAT_MODEL_INSTRUCTIONS).toContain("Phase 8: Attack Paths");
  });

  it("references the create_file tool for output", () => {
    expect(THREAT_MODEL_INSTRUCTIONS).toContain("create_file");
  });

  it("includes the output format section with key structural markers", () => {
    expect(THREAT_MODEL_INSTRUCTIONS).toContain("# Output Format");
    expect(THREAT_MODEL_INSTRUCTIONS).toContain("## Attack Paths");
    expect(THREAT_MODEL_INSTRUCTIONS).toContain("## Application Context");
    expect(THREAT_MODEL_INSTRUCTIONS).toContain("## Security Controls");
  });

  it("includes quality standards and anti-patterns", () => {
    expect(THREAT_MODEL_INSTRUCTIONS).toContain("# Quality Standards");
    expect(THREAT_MODEL_INSTRUCTIONS).toContain("# Anti-Patterns");
  });
});
