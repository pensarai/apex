import { describe, it, expect } from "vitest";
import { buildScoringPrompt, type CVSSScorerInput } from "./index";

function makeInput(overrides: Partial<CVSSScorerInput> = {}): CVSSScorerInput {
  return {
    finding: {
      title: "Test Vulnerability",
      description: "A test vulnerability description.",
      impact: "High impact on confidentiality.",
      evidence: "HTTP 200 OK with sensitive data.",
      endpoint: "https://target.com/api/test",
      vulnerabilityClass: "information-disclosure",
    },
    agentMessages: [],
    ...overrides,
  };
}

describe("buildScoringPrompt", () => {
  it("includes related findings section when relatedFindings is provided", () => {
    const input = makeInput({
      relatedFindings: [
        {
          title: "Missing Rate Limiting on Email API",
          severity: "CRITICAL",
          endpoint: "https://target.com/api/test",
          vulnerabilityClass: "missing-rate-limiting",
          score: 9.2,
        },
      ],
    });

    const prompt = buildScoringPrompt(input);

    expect(prompt).toContain("## Related Findings on Same Endpoint");
    expect(prompt).toContain("Missing Rate Limiting on Email API");
    expect(prompt).toContain("[CRITICAL 9.2]");
    expect(prompt).toContain("(class: missing-rate-limiting)");
  });

  it("does NOT include related findings section when relatedFindings is empty", () => {
    const input = makeInput({ relatedFindings: [] });
    const prompt = buildScoringPrompt(input);

    expect(prompt).not.toContain("## Related Findings on Same Endpoint");
  });

  it("does NOT include related findings section when relatedFindings is undefined", () => {
    const input = makeInput({ relatedFindings: undefined });
    const prompt = buildScoringPrompt(input);

    expect(prompt).not.toContain("## Related Findings on Same Endpoint");
  });

  it("formats multiple related findings with severity, title, and class", () => {
    const input = makeInput({
      relatedFindings: [
        {
          title: "Missing Rate Limiting",
          severity: "CRITICAL",
          endpoint: "https://target.com/api/test",
          vulnerabilityClass: "missing-rate-limiting",
          score: 9.2,
        },
        {
          title: "Information Disclosure via Error Messages",
          severity: "MEDIUM",
          endpoint: "https://target.com/api/test",
          vulnerabilityClass: "information-disclosure",
        },
      ],
    });

    const prompt = buildScoringPrompt(input);

    expect(prompt).toContain(
      '- [CRITICAL 9.2] "Missing Rate Limiting" (class: missing-rate-limiting)',
    );
    expect(prompt).toContain(
      '- [MEDIUM] "Information Disclosure via Error Messages" (class: information-disclosure)',
    );
  });

  it("uses 'unknown' for class when vulnerabilityClass is not provided", () => {
    const input = makeInput({
      relatedFindings: [
        {
          title: "Some Finding",
          severity: "HIGH",
          endpoint: "https://target.com/api/test",
        },
      ],
    });

    const prompt = buildScoringPrompt(input);

    expect(prompt).toContain('- [HIGH] "Some Finding" (class: unknown)');
  });

  it("always includes finding details regardless of related findings", () => {
    const input = makeInput({
      relatedFindings: [
        {
          title: "Related Finding",
          severity: "HIGH",
          endpoint: "https://target.com/api/test",
        },
      ],
    });

    const prompt = buildScoringPrompt(input);

    expect(prompt).toContain("**Title:** Test Vulnerability");
    expect(prompt).toContain("**Vulnerability Class:** information-disclosure");
    expect(prompt).toContain("**Endpoint:** https://target.com/api/test");
  });
});
