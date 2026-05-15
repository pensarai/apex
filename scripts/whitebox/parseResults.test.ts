/**
 * Unit tests for the per-scanner output parsers in parse-results.ts.
 *
 * Each test feeds a representative fixture payload (cribbed from the
 * scanners' real JSON shape) and asserts that the resulting normalized
 * ParseResult exposes the right fields. The goal is not full schema
 * coverage but to lock in:
 *   - file / line / ruleId / message / severity / cwe make it through
 *   - novel scanner output (extra keys, missing keys) is tolerated
 *   - NDJSON parsing for trufflehog works correctly
 */
import { describe, expect, it } from "vitest";
import { parseScannerOutput } from "./parse-results";

describe("parseScannerOutput", () => {
  it("parses semgrep output", () => {
    const raw = JSON.stringify({
      results: [
        {
          check_id: "python.lang.security.audit.dangerous-eval.dangerous-eval",
          path: "src/main.py",
          start: { line: 12 },
          end: { line: 12 },
          extra: {
            message: "Detected eval(); avoid arbitrary code execution",
            severity: "ERROR",
            metadata: { cwe: ["CWE-95"] },
          },
        },
      ],
    });
    const result = parseScannerOutput("semgrep", raw);
    expect(result.tool).toBe("semgrep");
    expect(result.findings).toHaveLength(1);
    const f = result.findings[0];
    expect(f.path).toBe("src/main.py");
    expect(f.startLine).toBe(12);
    expect(f.severity).toBe("high");
    expect(f.cwe).toEqual(["CWE-95"]);
    expect(f.ruleId).toContain("dangerous-eval");
  });

  it("parses gitleaks output", () => {
    const raw = JSON.stringify([
      {
        RuleID: "aws-access-token",
        Description: "AWS access key detected",
        File: "config/secrets.env",
        StartLine: 4,
        EndLine: 4,
      },
    ]);
    const result = parseScannerOutput("gitleaks", raw);
    expect(result.findings).toHaveLength(1);
    expect(result.findings[0].path).toBe("config/secrets.env");
    expect(result.findings[0].severity).toBe("high");
    expect(result.findings[0].ruleId).toBe("aws-access-token");
  });

  it("parses osv-scanner output", () => {
    const raw = JSON.stringify({
      results: [
        {
          source: { path: "package-lock.json", type: "lockfile" },
          packages: [
            {
              package: { name: "lodash", version: "4.17.20" },
              vulnerabilities: [
                {
                  id: "GHSA-35jh-r3h4-6jhm",
                  summary: "Prototype Pollution in lodash",
                  aliases: ["CVE-2020-8203"],
                },
              ],
            },
          ],
        },
      ],
    });
    const result = parseScannerOutput("osv-scanner", raw);
    expect(result.findings).toHaveLength(1);
    expect(result.findings[0].ruleId).toBe("GHSA-35jh-r3h4-6jhm");
    expect(result.findings[0].message).toContain("lodash");
    expect(result.findings[0].message).toContain("4.17.20");
  });

  it("parses trivy-fs output", () => {
    const raw = JSON.stringify({
      Results: [
        {
          Target: "package-lock.json",
          Vulnerabilities: [
            {
              VulnerabilityID: "CVE-2021-23337",
              PkgName: "lodash",
              InstalledVersion: "4.17.20",
              Severity: "HIGH",
              Title: "Command injection in lodash",
              CweIDs: ["CWE-78"],
            },
          ],
        },
      ],
    });
    const result = parseScannerOutput("trivy-fs", raw);
    expect(result.findings).toHaveLength(1);
    expect(result.findings[0].severity).toBe("high");
    expect(result.findings[0].cwe).toEqual(["CWE-78"]);
  });

  it("parses bandit output", () => {
    const raw = JSON.stringify({
      results: [
        {
          test_id: "B602",
          filename: "src/app.py",
          line_number: 42,
          issue_text: "subprocess call with shell=True identified",
          issue_severity: "HIGH",
          cwe: { id: "CWE-78" },
        },
      ],
    });
    const result = parseScannerOutput("bandit", raw);
    const f = result.findings[0];
    expect(f.ruleId).toBe("B602");
    expect(f.startLine).toBe(42);
    expect(f.severity).toBe("high");
    expect(f.cwe).toEqual(["CWE-78"]);
  });

  it("parses gosec output", () => {
    const raw = JSON.stringify({
      Issues: [
        {
          rule_id: "G304",
          file: "cmd/server/main.go",
          line: "73",
          details: "Potential file inclusion via variable",
          severity: "MEDIUM",
          cwe: { id: "22" },
        },
      ],
    });
    const result = parseScannerOutput("gosec", raw);
    const f = result.findings[0];
    expect(f.ruleId).toBe("G304");
    expect(f.severity).toBe("medium");
    expect(f.startLine).toBe(73);
    expect(f.cwe).toEqual(["CWE-22"]);
  });

  it("parses cargo-audit output", () => {
    const raw = JSON.stringify({
      vulnerabilities: {
        list: [
          {
            advisory: { id: "RUSTSEC-2021-0001", title: "Memory safety bug" },
            package: { name: "smallvec", version: "1.4.0" },
          },
        ],
      },
    });
    const result = parseScannerOutput("cargo-audit", raw);
    expect(result.findings[0].ruleId).toBe("RUSTSEC-2021-0001");
    expect(result.findings[0].message).toContain("smallvec");
  });

  it("parses pip-audit output", () => {
    const raw = JSON.stringify({
      dependencies: [
        {
          name: "requests",
          version: "2.20.0",
          vulns: [
            {
              id: "PYSEC-2021-101",
              description: "TLS verification bypass",
            },
          ],
        },
      ],
    });
    const result = parseScannerOutput("pip-audit", raw);
    expect(result.findings[0].ruleId).toBe("PYSEC-2021-101");
    expect(result.findings[0].message).toContain("requests");
  });

  it("parses npm-audit output", () => {
    const raw = JSON.stringify({
      vulnerabilities: {
        minimist: {
          severity: "high",
          via: [
            {
              source: 1234,
              title: "Prototype Pollution",
              severity: "high",
              cwe: ["CWE-1321"],
            },
          ],
        },
      },
    });
    const result = parseScannerOutput("npm-audit", raw);
    expect(result.findings).toHaveLength(1);
    expect(result.findings[0].severity).toBe("high");
    expect(result.findings[0].message).toContain("minimist");
    expect(result.findings[0].cwe).toEqual(["CWE-1321"]);
  });

  it("parses trufflehog NDJSON output", () => {
    const lines = [
      JSON.stringify({
        DetectorName: "AWS",
        Raw: "AKIAIOSFODNN7EXAMPLE",
        SourceMetadata: {
          Data: { Filesystem: { file: "config/aws.json", line: 7 } },
        },
      }),
      JSON.stringify({
        DetectorName: "GitHubToken",
        Raw: "ghp_xyz",
        SourceMetadata: {
          Data: { Filesystem: { file: ".env.local", line: 3 } },
        },
      }),
    ].join("\n");
    const result = parseScannerOutput("trufflehog", lines);
    expect(result.findings).toHaveLength(2);
    expect(result.findings[0].path).toBe("config/aws.json");
    expect(result.findings[0].startLine).toBe(7);
    expect(result.findings[1].ruleId).toBe("GitHubToken");
  });

  it("returns a parse-failure note when raw input is not valid JSON", () => {
    const result = parseScannerOutput("semgrep", "not json at all");
    expect(result.findings).toEqual([]);
    expect(result.notes[0]).toMatch(/Failed to parse/);
  });
});
