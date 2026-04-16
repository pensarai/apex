import { describe, expect, it } from "vitest";
import { renderMarkdown } from "./markdown";
import type { PentestReport } from "../schemas";

function makeSampleReport(
  overrides: Partial<PentestReport> = {},
): PentestReport {
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
      bySeverity: { CRITICAL: 0, HIGH: 1, MEDIUM: 0, LOW: 0 },
    },
    findings: [
      {
        title: "SQL Injection in Login Form",
        severity: "HIGH",
        description: "The login endpoint is vulnerable to SQL injection.",
        impact:
          "An attacker could bypass authentication and access all user data.",
        evidence:
          "POST /login HTTP/1.1\nusername=admin'--&password=x\n\nHTTP/1.1 200 OK",
        endpoint: "/login",
        pocPath: "pocs/poc_sqli.sh",
        remediation: "Use parameterized queries for all database interactions.",
        references: "CWE-89: SQL Injection",
      },
    ],
    ...overrides,
  };
}

describe("renderMarkdown", () => {
  it("produces output matching documentFinding.ts format for a single finding", () => {
    const report = makeSampleReport();
    const output = renderMarkdown(report);

    // The expected output matches the exact template from documentFinding.ts
    // Two trailing spaces on Severity/Target/Endpoint/Date lines for markdown line breaks
    const expected = [
      "# Pentest Report — https://example.com",
      "",
      "**Date:** 2026-02-26T10:00:00.000Z  ",
      "**Session:** sess-abc123  ",
      "**Model:** claude-sonnet-4-20250514  ",
      "**Mode:** blackbox",
      "",
      "**Findings:** 1",
      "",
      "# SQL Injection in Login Form",
      "",
      "**Severity:** HIGH  ",
      "**Target:** https://example.com  ",
      "**Endpoint:** /login  ",
      "**Date:** 2026-02-26T10:00:00.000Z  ",
      "**Session:** sess-abc123",
      "",
      "## Description",
      "",
      "The login endpoint is vulnerable to SQL injection.",
      "",
      "## Impact",
      "",
      "An attacker could bypass authentication and access all user data.",
      "",
      "## Evidence",
      "",
      "```",
      "POST /login HTTP/1.1",
      "username=admin'--&password=x",
      "",
      "HTTP/1.1 200 OK",
      "```",
      "",
      "## POC",
      "",
      "Path: `pocs/poc_sqli.sh`",
      "",
      "## Remediation",
      "",
      "Use parameterized queries for all database interactions.",
      "",
      "## References",
      "",
      "CWE-89: SQL Injection",
      "",
      "---",
      "",
      "*This finding was automatically documented by the Pensar penetration testing agent.*",
      "",
    ].join("\n");

    expect(output).toBe(expected);
  });

  it("omits References section when finding has no references", () => {
    const report = makeSampleReport({
      findings: [
        {
          title: "Missing Security Headers",
          severity: "LOW",
          description: "Several security headers are missing.",
          impact: "Reduced defense-in-depth posture.",
          evidence: "HTTP/1.1 200 OK\nContent-Type: text/html",
          endpoint: "/",
          pocPath: "pocs/poc_headers.sh",
          remediation: "Add X-Frame-Options, CSP, and HSTS headers.",
        },
      ],
      summary: {
        totalFindings: 1,
        bySeverity: { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 1 },
      },
    });
    const output = renderMarkdown(report);

    expect(output).not.toContain("## References");
    expect(output).toContain("## Remediation");
    expect(output).toContain("---");
    expect(output).toContain(
      "*This finding was automatically documented by the Pensar penetration testing agent.*",
    );
  });

  it("renders multiple findings separated correctly", () => {
    const report = makeSampleReport({
      findings: [
        {
          title: "Finding One",
          severity: "HIGH",
          description: "Desc one",
          impact: "Impact one",
          evidence: "Evidence one",
          endpoint: "/one",
          pocPath: "pocs/one.sh",
          remediation: "Fix one",
        },
        {
          title: "Finding Two",
          severity: "MEDIUM",
          description: "Desc two",
          impact: "Impact two",
          evidence: "Evidence two",
          endpoint: "/two",
          pocPath: "pocs/two.sh",
          remediation: "Fix two",
          references: "CWE-123",
        },
      ],
      summary: {
        totalFindings: 2,
        bySeverity: { CRITICAL: 0, HIGH: 1, MEDIUM: 1, LOW: 0 },
      },
    });
    const output = renderMarkdown(report);

    // Both findings rendered
    expect(output).toContain("# Finding One");
    expect(output).toContain("# Finding Two");

    // Each finding has its own separator and footer
    const footerCount = (
      output.match(
        /\*This finding was automatically documented by the Pensar penetration testing agent\.\*/g,
      ) || []
    ).length;
    expect(footerCount).toBe(2);

    const separatorCount = (output.match(/^---$/gm) || []).length;
    expect(separatorCount).toBe(2);
  });

  it("uses metadata from report for target, timestamp, and sessionId", () => {
    const report = makeSampleReport({
      metadata: {
        target: "https://custom-target.io",
        model: "test-model",
        timestamp: "2026-01-01T00:00:00.000Z",
        sessionId: "custom-session-id",
        mode: "whitebox",
      },
    });
    const output = renderMarkdown(report);

    expect(output).toContain("**Target:** https://custom-target.io  ");
    expect(output).toContain("**Date:** 2026-01-01T00:00:00.000Z  ");
    expect(output).toContain("**Session:** custom-session-id");
  });

  it("wraps evidence in fenced code blocks", () => {
    const report = makeSampleReport();
    const output = renderMarkdown(report);

    expect(output).toContain(
      "```\nPOST /login HTTP/1.1\nusername=admin'--&password=x\n\nHTTP/1.1 200 OK\n```",
    );
  });

  it("renders CWE Classification section when cwes are present", () => {
    const report = makeSampleReport({
      findings: [
        {
          title: "SQL Injection in Login Form",
          severity: "HIGH",
          description: "The login endpoint is vulnerable to SQL injection.",
          impact:
            "An attacker could bypass authentication and access all user data.",
          evidence: "POST /login HTTP/1.1\nusername=admin'--&password=x",
          endpoint: "/login",
          pocPath: "pocs/poc_sqli.sh",
          remediation: "Use parameterized queries.",
          cwes: [
            {
              id: "CWE-89",
              reasoning: "SQL injection via unsanitized user input",
            },
            {
              id: "CWE-564",
              reasoning: "Hibernate-specific SQL injection variant",
            },
          ],
        },
      ],
    });
    const output = renderMarkdown(report);

    expect(output).toContain("## CWE Classification");
    expect(output).toContain(
      "- **CWE-89** — SQL injection via unsanitized user input",
    );
    expect(output).toContain(
      "- **CWE-564** — Hibernate-specific SQL injection variant",
    );
  });

  it("renders canonical CWE name when present (validated entries)", () => {
    const report = makeSampleReport({
      findings: [
        {
          title: "SQL Injection in Login Form",
          severity: "HIGH",
          description: "SQL injection vulnerability.",
          impact: "Full database access.",
          evidence: "Evidence here",
          endpoint: "/login",
          pocPath: "pocs/poc_sqli.sh",
          remediation: "Use parameterized queries.",
          cwes: [
            {
              id: "CWE-89",
              name: "Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')",
              reasoning: "SQL injection via unsanitized user input",
            },
          ],
        },
      ],
    });
    const output = renderMarkdown(report);

    expect(output).toContain("## CWE Classification");
    expect(output).toContain(
      "- **CWE-89**: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') — SQL injection via unsanitized user input",
    );
  });

  it("omits CWE Classification section when cwes are absent", () => {
    const report = makeSampleReport();
    const output = renderMarkdown(report);

    expect(output).not.toContain("## CWE Classification");
  });

  it("renders Evidence Files section when evidenceFiles are present", () => {
    const report = makeSampleReport({
      findings: [
        {
          title: "SQL Injection",
          severity: "HIGH",
          description: "Desc",
          impact: "Impact",
          evidence: "Evidence text",
          endpoint: "/api",
          pocPath: "pocs/poc.sh",
          remediation: "Fix it",
          evidenceFiles: [
            {
              path: "findings/evidence.txt",
              type: "raw-evidence",
              description: "Full evidence output",
            },
            {
              path: "pocs/poc.sh.output.json",
              type: "poc-output",
              description: "POC execution output",
            },
          ],
        },
      ],
    });
    const output = renderMarkdown(report);

    expect(output).toContain("## Evidence Files");
    expect(output).toContain(
      "- **[raw-evidence]** `findings/evidence.txt` — Full evidence output",
    );
    expect(output).toContain(
      "- **[poc-output]** `pocs/poc.sh.output.json` — POC execution output",
    );
  });

  it("omits Evidence Files section when evidenceFiles are absent", () => {
    const report = makeSampleReport();
    const output = renderMarkdown(report);

    expect(output).not.toContain("## Evidence Files");
  });
});
