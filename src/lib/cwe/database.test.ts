import { describe, it, expect } from "vitest";
import { CWE_DATABASE, lookupCweName, isKnownCweId } from "./database";

describe("CWE_DATABASE", () => {
  it("contains a reasonable number of entries", () => {
    expect(CWE_DATABASE.size).toBeGreaterThanOrEqual(200);
  });

  it("includes all CWE IDs referenced in the CVSS scorer system prompt", () => {
    const scorerPromptCwes = [
      89, 564, 943, 79, 80, 87, 78, 77, 94, 95, 96, 639, 284, 862, 918, 22,
      23, 36, 611, 776, 1336, 352, 502, 601, 200, 209, 532, 287, 306, 327,
      328, 330,
    ];
    for (const id of scorerPromptCwes) {
      expect(CWE_DATABASE.has(id), `CWE-${id} should be in database`).toBe(
        true,
      );
    }
  });

  it("includes key OWASP Top 10 CWEs", () => {
    const owaspCwes = [
      79, // XSS
      89, // SQLi
      352, // CSRF
      434, // Unrestricted Upload
      502, // Deserialization
      611, // XXE
      798, // Hard-coded Credentials
      862, // Missing Authorization
      918, // SSRF
    ];
    for (const id of owaspCwes) {
      expect(CWE_DATABASE.has(id), `CWE-${id} should be in database`).toBe(
        true,
      );
    }
  });
});

describe("lookupCweName", () => {
  it("returns canonical name for known CWE", () => {
    const name = lookupCweName(89);
    expect(name).toContain("SQL");
  });

  it("returns undefined for unknown CWE ID", () => {
    expect(lookupCweName(99999)).toBeUndefined();
  });

  it("returns the exact CWE-135 name (hallucination test case)", () => {
    // CWE-135 is NOT about cryptography — it's about multi-byte string length
    const name = lookupCweName(135);
    expect(name).toBe("Incorrect Calculation of Multi-Byte String Length");
    expect(name).not.toContain("Cryptograph");
  });
});

describe("isKnownCweId", () => {
  it("returns true for known CWE", () => {
    expect(isKnownCweId(79)).toBe(true);
  });

  it("returns false for unknown CWE", () => {
    expect(isKnownCweId(99999)).toBe(false);
  });
});
