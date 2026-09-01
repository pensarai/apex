import { describe, expect, it } from "vitest";
import { PentestReportFindingSchema } from "../../report/schemas";
import { DocumentFindingSchema } from "../../session/types";
import { ApexFindingObject } from "./types";

const baseFinding = {
  title: "SQL Injection in /api/products",
  severity: "HIGH",
  description: "The search parameter is vulnerable to SQL injection.",
  impact: "An attacker can extract database contents.",
  evidence: "sqlmap confirmed injection point.",
  endpoint: "https://example.com/api/products",
  pocPath: "pocs/poc_sqli.sh",
  remediation: "Use parameterized queries.",
};

const cwes = [
  { id: "CWE-89", reasoning: "SQL injection via unsanitized user input" },
  { id: "CWE-564", reasoning: "Hibernate-specific variant" },
];

const evidenceFiles = [
  {
    path: "findings/2026-03-26-sqli-evidence.txt",
    type: "raw-evidence" as const,
    description: "Full evidence output (25000 bytes)",
  },
  {
    path: "pocs/poc_sqli.sh.output.json",
    type: "poc-output" as const,
    description: "POC execution output for poc_sqli.sh",
  },
];

// ---------------------------------------------------------------------------
// ApexFindingObject
// ---------------------------------------------------------------------------

describe("ApexFindingObject", () => {
  it("accepts finding without cwes (backward compatible)", () => {
    const result = ApexFindingObject.safeParse(baseFinding);
    expect(result.success).toBe(true);
  });

  it("accepts finding with cwes", () => {
    const result = ApexFindingObject.safeParse({ ...baseFinding, cwes });
    expect(result.success).toBe(true);
    if (result.success) {
      expect(result.data.cwes).toEqual(cwes);
    }
  });

  it("rejects finding with invalid CWE id format", () => {
    const result = ApexFindingObject.safeParse({
      ...baseFinding,
      cwes: [{ id: "cwe89", reasoning: "bad format" }],
    });
    expect(result.success).toBe(false);
  });

  it("accepts finding with evidenceFiles", () => {
    const result = ApexFindingObject.safeParse({
      ...baseFinding,
      evidenceFiles,
    });
    expect(result.success).toBe(true);
    if (result.success) {
      expect(result.data.evidenceFiles).toEqual(evidenceFiles);
    }
  });

  it("accepts finding with an ordered attackPath", () => {
    const attackPath = [
      {
        applicationId: "app_web",
        applicationName: "Web App",
        host: "app.example.com",
        relationshipType: "calls",
      },
      {
        applicationName: "Admin API",
        host: "api.partner.test",
      },
    ];
    const result = PentestReportFindingSchema.safeParse({
      ...baseFinding,
      attackPath,
    });

    expect(result.success).toBe(true);
    if (result.success) expect(result.data.attackPath).toEqual(attackPath);
  });

  it("rejects finding with invalid evidence file type", () => {
    const result = ApexFindingObject.safeParse({
      ...baseFinding,
      evidenceFiles: [
        { path: "file.txt", type: "invalid-type", description: "bad" },
      ],
    });
    expect(result.success).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// DocumentFindingSchema
// ---------------------------------------------------------------------------

describe("DocumentFindingSchema", () => {
  it("accepts finding without cwes (backward compatible)", () => {
    const result = DocumentFindingSchema.safeParse(baseFinding);
    expect(result.success).toBe(true);
  });

  it("accepts finding with cwes", () => {
    const result = DocumentFindingSchema.safeParse({ ...baseFinding, cwes });
    expect(result.success).toBe(true);
    if (result.success) {
      expect(result.data.cwes).toEqual(cwes);
    }
  });

  it("rejects finding with invalid CWE id format", () => {
    const result = DocumentFindingSchema.safeParse({
      ...baseFinding,
      cwes: [{ id: "SQL Injection", reasoning: "not a CWE id" }],
    });
    expect(result.success).toBe(false);
  });

  it("accepts finding with evidenceFiles", () => {
    const result = DocumentFindingSchema.safeParse({
      ...baseFinding,
      evidenceFiles,
    });
    expect(result.success).toBe(true);
    if (result.success) {
      expect(result.data.evidenceFiles).toEqual(evidenceFiles);
    }
  });

  it("rejects finding with invalid evidence file type", () => {
    const result = DocumentFindingSchema.safeParse({
      ...baseFinding,
      evidenceFiles: [
        { path: "file.txt", type: "unknown", description: "bad" },
      ],
    });
    expect(result.success).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// PentestReportFindingSchema
// ---------------------------------------------------------------------------

describe("PentestReportFindingSchema", () => {
  it("accepts finding without cwes (backward compatible)", () => {
    const result = PentestReportFindingSchema.safeParse(baseFinding);
    expect(result.success).toBe(true);
  });

  it("accepts finding with cwes", () => {
    const result = PentestReportFindingSchema.safeParse({
      ...baseFinding,
      cwes,
    });
    expect(result.success).toBe(true);
    if (result.success) {
      expect(result.data.cwes).toEqual(cwes);
    }
  });

  it("rejects finding with invalid CWE id format", () => {
    const result = PentestReportFindingSchema.safeParse({
      ...baseFinding,
      cwes: [{ id: "CWE-", reasoning: "missing number" }],
    });
    expect(result.success).toBe(false);
  });

  it("accepts finding with evidenceFiles", () => {
    const result = PentestReportFindingSchema.safeParse({
      ...baseFinding,
      evidenceFiles,
    });
    expect(result.success).toBe(true);
    if (result.success) {
      expect(result.data.evidenceFiles).toEqual(evidenceFiles);
    }
  });

  it("rejects finding with invalid evidence file type", () => {
    const result = PentestReportFindingSchema.safeParse({
      ...baseFinding,
      evidenceFiles: [
        { path: "file.txt", type: "not-a-type", description: "bad" },
      ],
    });
    expect(result.success).toBe(false);
  });
});
