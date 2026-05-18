import { describe, expect, it } from "vitest";
import type { CweEntry, ValidatedCweEntry } from "./types";
import {
  CweEntrySchema,
  hasCanonicalName,
  ValidatedCweEntrySchema,
} from "./types";

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

describe("ValidatedCweEntrySchema", () => {
  it("accepts a validated entry with name", () => {
    const result = ValidatedCweEntrySchema.safeParse({
      id: "CWE-89",
      name: "Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')",
      reasoning: "SQL injection via unsanitized user input",
    });
    expect(result.success).toBe(true);
  });

  it("rejects entry without name", () => {
    const result = ValidatedCweEntrySchema.safeParse({
      id: "CWE-89",
      reasoning: "SQL injection",
    });
    expect(result.success).toBe(false);
  });

  it("rejects entry with non-string name", () => {
    const result = ValidatedCweEntrySchema.safeParse({
      id: "CWE-89",
      name: 123,
      reasoning: "SQL injection",
    });
    expect(result.success).toBe(false);
  });
});

describe("hasCanonicalName", () => {
  it("returns true for ValidatedCweEntry", () => {
    const entry: ValidatedCweEntry = {
      id: "CWE-89",
      name: "SQL Injection",
      reasoning: "test",
    };
    expect(hasCanonicalName(entry)).toBe(true);
  });

  it("returns false for plain CweEntry", () => {
    const entry: CweEntry = {
      id: "CWE-89",
      reasoning: "test",
    };
    expect(hasCanonicalName(entry)).toBe(false);
  });
});
