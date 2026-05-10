import { describe, expect, it } from "vitest";
import type { CweEntry } from "./types";
import { validateCweEntries } from "./validate";

describe("validateCweEntries", () => {
  it("enriches valid CWE IDs with canonical names", () => {
    const entries: CweEntry[] = [
      { id: "CWE-89", reasoning: "SQL injection via user input" },
      { id: "CWE-79", reasoning: "Reflected XSS in search param" },
    ];

    const result = validateCweEntries(entries);

    expect(result.validated).toHaveLength(2);
    expect(result.dropped).toHaveLength(0);
    expect(result.validated[0].id).toBe("CWE-89");
    expect(result.validated[0].name).toContain("SQL");
    expect(result.validated[0].reasoning).toBe("SQL injection via user input");
    expect(result.validated[1].id).toBe("CWE-79");
    expect(result.validated[1].name).toContain("Cross-site Scripting");
  });

  it("drops unknown CWE IDs", () => {
    const entries: CweEntry[] = [
      { id: "CWE-99999", reasoning: "Made up weakness" },
    ];

    const result = validateCweEntries(entries);

    expect(result.validated).toHaveLength(0);
    expect(result.dropped).toHaveLength(1);
    expect(result.dropped[0].id).toBe("CWE-99999");
    expect(result.dropped[0].reason).toContain("not found");
  });

  it("handles mix of valid and invalid entries", () => {
    const entries: CweEntry[] = [
      { id: "CWE-89", reasoning: "Valid SQLi" },
      { id: "CWE-99999", reasoning: "Hallucinated" },
      { id: "CWE-79", reasoning: "Valid XSS" },
    ];

    const result = validateCweEntries(entries);

    expect(result.validated).toHaveLength(2);
    expect(result.validated[0].id).toBe("CWE-89");
    expect(result.validated[1].id).toBe("CWE-79");
    expect(result.dropped).toHaveLength(1);
    expect(result.dropped[0].id).toBe("CWE-99999");
  });

  it("returns empty results for empty input", () => {
    const result = validateCweEntries([]);

    expect(result.validated).toHaveLength(0);
    expect(result.dropped).toHaveLength(0);
  });

  it("catches the CWE-135 hallucination from the bug report", () => {
    // Bug: LLM cited "CWE-135: Weakness in Cryptography" for clickjacking
    // CWE-135 is actually "Incorrect Calculation of Multi-Byte String Length"
    // The correct CWE for clickjacking is CWE-1021
    const entries: CweEntry[] = [
      { id: "CWE-135", reasoning: "Weakness in Cryptography" },
      { id: "CWE-1021", reasoning: "Clickjacking via missing X-Frame-Options" },
    ];

    const result = validateCweEntries(entries);

    // CWE-135 IS a valid CWE ID (it exists in the database), so it won't be dropped.
    // However, the canonical name will expose the mismatch:
    // The LLM said "Weakness in Cryptography" but the real name is about multi-byte strings.
    expect(result.validated).toHaveLength(2);
    const cwe135 = result.validated.find((c) => c.id === "CWE-135");
    expect(cwe135?.name).toBe(
      "Incorrect Calculation of Multi-Byte String Length",
    );
    expect(cwe135?.name).not.toContain("Cryptograph");

    // CWE-1021 is the correct one for clickjacking
    const cwe1021 = result.validated.find((c) => c.id === "CWE-1021");
    expect(cwe1021?.name).toContain("Rendered UI Layers or Frames");
  });

  it("drops entries with malformed IDs", () => {
    const entries: CweEntry[] = [
      { id: "cwe-89", reasoning: "lowercase" },
      { id: "CWE89", reasoning: "missing hyphen" },
      { id: "89", reasoning: "bare number" },
    ];

    const result = validateCweEntries(entries);

    expect(result.validated).toHaveLength(0);
    expect(result.dropped).toHaveLength(3);
    for (const d of result.dropped) {
      expect(d.reason).toContain("Could not parse");
    }
  });

  it("preserves original reasoning in validated entries", () => {
    const reasoning =
      "SQL injection through dynamic query in /api/search endpoint";
    const entries: CweEntry[] = [{ id: "CWE-89", reasoning }];

    const result = validateCweEntries(entries);

    expect(result.validated[0].reasoning).toBe(reasoning);
  });
});
