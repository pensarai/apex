import { describe, expect, it } from "vitest";
import { buildPentestReport, type ReportContext } from "./builder";
import { PentestReportSchema, REPORT_VERSION } from "./schemas";
import type { Finding } from "../agents/offSecAgent/types";

const defaultContext: ReportContext = {
  target: "https://example.com",
  model: "claude-opus-4-20250514",
  sessionId: "test-session-123",
  mode: "blackbox",
};

function makeFinding(overrides: Partial<Finding> = {}): Finding {
  return {
    title: "Test Finding",
    severity: "MEDIUM",
    description: "A test finding",
    impact: "Medium impact",
    evidence: "Found via testing",
    endpoint: "/api/test",
    pocPath: "/pocs/test.py",
    remediation: "Fix the thing",
    ...overrides,
  };
}

describe("buildPentestReport", () => {
  it("produces a valid report from sample findings", () => {
    const findings: Finding[] = [
      makeFinding({ title: "SQL Injection", severity: "CRITICAL" }),
      makeFinding({ title: "XSS", severity: "HIGH" }),
      makeFinding({ title: "Info Disclosure", severity: "LOW" }),
    ];

    const report = buildPentestReport(findings, defaultContext);
    const result = PentestReportSchema.safeParse(report);

    expect(result.success).toBe(true);
    expect(report.version).toBe(REPORT_VERSION);
    expect(report.metadata.target).toBe("https://example.com");
    expect(report.metadata.model).toBe("claude-opus-4-20250514");
    expect(report.metadata.sessionId).toBe("test-session-123");
    expect(report.metadata.mode).toBe("blackbox");
    expect(report.summary.totalFindings).toBe(3);
    expect(report.summary.bySeverity).toEqual({
      CRITICAL: 1,
      HIGH: 1,
      MEDIUM: 0,
      LOW: 1,
    });
    expect(report.findings).toHaveLength(3);
  });

  it("handles empty findings array with all zero counts", () => {
    const report = buildPentestReport([], defaultContext);
    const result = PentestReportSchema.safeParse(report);

    expect(result.success).toBe(true);
    expect(report.summary.totalFindings).toBe(0);
    expect(report.summary.bySeverity).toEqual({
      CRITICAL: 0,
      HIGH: 0,
      MEDIUM: 0,
      LOW: 0,
    });
    expect(report.findings).toHaveLength(0);
  });

  it("sorts findings by severity: CRITICAL > HIGH > MEDIUM > LOW", () => {
    const findings: Finding[] = [
      makeFinding({ title: "Low Issue", severity: "LOW" }),
      makeFinding({ title: "Critical Issue", severity: "CRITICAL" }),
      makeFinding({ title: "Medium Issue", severity: "MEDIUM" }),
      makeFinding({ title: "High Issue", severity: "HIGH" }),
    ];

    const report = buildPentestReport(findings, defaultContext);

    expect(report.findings[0].title).toBe("Critical Issue");
    expect(report.findings[1].title).toBe("High Issue");
    expect(report.findings[2].title).toBe("Medium Issue");
    expect(report.findings[3].title).toBe("Low Issue");
  });

  it("strips toolCallDescription from findings", () => {
    const findings: Finding[] = [
      makeFinding({
        title: "With Tool Call",
        toolCallDescription: "Used sqlmap to find injection",
      }),
    ];

    const report = buildPentestReport(findings, defaultContext);

    // The report finding should not have toolCallDescription
    expect(report.findings[0]).not.toHaveProperty("toolCallDescription");
    expect(report.findings[0].title).toBe("With Tool Call");
  });

  it("computes bySeverity counts correctly with multiple findings per severity", () => {
    const findings: Finding[] = [
      makeFinding({ title: "Critical 1", severity: "CRITICAL" }),
      makeFinding({ title: "Critical 2", severity: "CRITICAL" }),
      makeFinding({ title: "High 1", severity: "HIGH" }),
      makeFinding({ title: "Medium 1", severity: "MEDIUM" }),
      makeFinding({ title: "Medium 2", severity: "MEDIUM" }),
      makeFinding({ title: "Medium 3", severity: "MEDIUM" }),
      makeFinding({ title: "Low 1", severity: "LOW" }),
    ];

    const report = buildPentestReport(findings, defaultContext);

    expect(report.summary.totalFindings).toBe(7);
    expect(report.summary.bySeverity).toEqual({
      CRITICAL: 2,
      HIGH: 1,
      MEDIUM: 3,
      LOW: 1,
    });
  });

  it("includes cwes in report findings when present", () => {
    const findings: Finding[] = [
      makeFinding({
        title: "SQLi with CWEs",
        cwes: [
          {
            id: "CWE-89",
            reasoning: "SQL injection via unsanitized user input",
          },
        ],
      }),
    ];

    const report = buildPentestReport(findings, defaultContext);
    const result = PentestReportSchema.safeParse(report);

    expect(result.success).toBe(true);
    expect(report.findings[0].cwes).toHaveLength(1);
    expect(report.findings[0].cwes![0].id).toBe("CWE-89");
  });

  it("handles findings without cwes (backward compat)", () => {
    const findings: Finding[] = [makeFinding({ title: "No CWEs" })];

    const report = buildPentestReport(findings, defaultContext);
    const result = PentestReportSchema.safeParse(report);

    expect(result.success).toBe(true);
    expect(report.findings[0].cwes).toBeUndefined();
  });

  it("includes optional references when present", () => {
    const findings: Finding[] = [
      makeFinding({
        title: "With Refs",
        references: "https://owasp.org/top10",
      }),
      makeFinding({ title: "Without Refs" }),
    ];

    const report = buildPentestReport(findings, defaultContext);
    const result = PentestReportSchema.safeParse(report);

    expect(result.success).toBe(true);
    expect(report.findings[0].references).toBe("https://owasp.org/top10");
    expect(report.findings[1].references).toBeUndefined();
  });
});
