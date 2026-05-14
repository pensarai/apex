import { describe, expect, it } from "vitest";
import type { PentestReport } from "../schemas";
import { PentestReportSchema } from "../schemas";
import { renderJson } from "./json";

function makeSampleReport(): PentestReport {
  return {
    version: "1.0",
    metadata: {
      target: "https://example.com",
      model: "claude-sonnet-4-20250514",
      timestamp: "2026-02-26T10:00:00.000Z",
      sessionId: "sess-abc123",
      mode: "blackbox",
    },
    summary: {
      totalFindings: 1,
      bySeverity: { CRITICAL: 0, HIGH: 1, MEDIUM: 0, LOW: 0, INFORMATIONAL: 0 },
    },
    findings: [
      {
        title: "SQL Injection in Login Form",
        severity: "HIGH",
        description: "The login endpoint is vulnerable to SQL injection.",
        impact:
          "An attacker could bypass authentication and access all user data.",
        evidence: "POST /login with admin'--",
        endpoint: "/login",
        pocPath: "pocs/poc_sqli.sh",
        remediation: "Use parameterized queries.",
        references: "CWE-89",
      },
    ],
  };
}

describe("renderJson", () => {
  it("returns pretty-printed JSON", () => {
    const report = makeSampleReport();
    const output = renderJson(report);

    expect(output).toBe(JSON.stringify(report, null, 2));
  });

  it("round-trips through JSON.parse and validates with schema", () => {
    const report = makeSampleReport();
    const output = renderJson(report);
    const parsed = JSON.parse(output);
    const result = PentestReportSchema.safeParse(parsed);

    expect(result.success).toBe(true);
    if (result.success) {
      expect(result.data).toEqual(report);
    }
  });

  it("round-trips a report with no references", () => {
    const report = makeSampleReport();
    delete (report.findings[0] as Record<string, unknown>).references;
    const output = renderJson(report);
    const parsed = JSON.parse(output);
    const result = PentestReportSchema.safeParse(parsed);

    expect(result.success).toBe(true);
    if (result.success) {
      expect(result.data.findings[0].references).toBeUndefined();
    }
  });

  it("produces valid JSON string", () => {
    const report = makeSampleReport();
    const output = renderJson(report);

    expect(() => JSON.parse(output)).not.toThrow();
  });
});
