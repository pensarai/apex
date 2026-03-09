import { describe, it, expect } from "vitest";
import { CweEntrySchema } from "./types";

describe("CweEntrySchema", () => {
  it("accepts valid CWE entry", () => {
    const result = CweEntrySchema.safeParse({
      id: "CWE-89",
      reasoning: "SQL injection via unsanitized user input",
    });
    expect(result.success).toBe(true);
  });

  it("accepts CWE with large number", () => {
    const result = CweEntrySchema.safeParse({
      id: "CWE-1336",
      reasoning: "Server-side template injection",
    });
    expect(result.success).toBe(true);
  });

  it("rejects lowercase cwe prefix", () => {
    const result = CweEntrySchema.safeParse({
      id: "cwe-89",
      reasoning: "SQL injection",
    });
    expect(result.success).toBe(false);
  });

  it("rejects missing hyphen", () => {
    const result = CweEntrySchema.safeParse({
      id: "CWE89",
      reasoning: "SQL injection",
    });
    expect(result.success).toBe(false);
  });

  it("rejects space instead of hyphen", () => {
    const result = CweEntrySchema.safeParse({
      id: "CWE 89",
      reasoning: "SQL injection",
    });
    expect(result.success).toBe(false);
  });

  it("rejects bare number without prefix", () => {
    const result = CweEntrySchema.safeParse({
      id: "89",
      reasoning: "SQL injection",
    });
    expect(result.success).toBe(false);
  });

  it("rejects descriptive name instead of ID", () => {
    const result = CweEntrySchema.safeParse({
      id: "SQL Injection",
      reasoning: "SQL injection",
    });
    expect(result.success).toBe(false);
  });

  it("rejects CWE- without number", () => {
    const result = CweEntrySchema.safeParse({
      id: "CWE-",
      reasoning: "Missing number",
    });
    expect(result.success).toBe(false);
  });

  it("rejects CWE- with non-numeric suffix", () => {
    const result = CweEntrySchema.safeParse({
      id: "CWE-abc",
      reasoning: "Invalid",
    });
    expect(result.success).toBe(false);
  });

  it("rejects missing reasoning", () => {
    const result = CweEntrySchema.safeParse({
      id: "CWE-89",
    });
    expect(result.success).toBe(false);
  });

  it("rejects missing id", () => {
    const result = CweEntrySchema.safeParse({
      reasoning: "SQL injection",
    });
    expect(result.success).toBe(false);
  });
});
