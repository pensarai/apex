import { describe, expect, it } from "vitest";
import { renderTriageMarkdown } from "./reportWriter";
import type { TriageResult } from "./types";

function makeResult(overrides: Partial<TriageResult> = {}): TriageResult {
  return {
    schemaVersion: 1,
    reportPath: "/tmp/report.md",
    target: "https://staging.example.com",
    generatedAt: "2026-05-11T12:00:00.000Z",
    report: {
      title: "Reflected XSS in search",
      reporterHandle: "researcher123",
      claimedSeverity: "HIGH",
      vulnerabilityClass: "Reflected XSS",
      affectedUrl: "https://staging.example.com/search",
      attackerModel: "unauthenticated",
      description: "Reflected XSS",
      impact: "Session theft",
      pocSteps: ["GET /search?q=<x>"],
      references: [
        "CWE-79: Improper Neutralization of Input During Web Page Generation",
        "OWASP Testing Guide: Cross Site Scripting",
      ],
    },
    scope: {
      inScope: true,
      hostInScope: true,
      policyInScope: true,
      hostScopeSource: "session-allowed-hosts",
      reason: "in scope",
    },
    duplicate: { duplicate: false, matchType: "none" },
    verification: {
      reproduced: true,
      evidence: "200 OK; payload reflected",
      observations: "first attempt succeeded",
    },
    claimVerification: {
      summary: "All required material claims were verified.",
      claims: [
        {
          id: "vulnerability-class",
          claim: "The behavior is a Reflected XSS vulnerability.",
          required: true,
          status: "verified",
          evidence: "payload reflected",
        },
        {
          id: "security-impact",
          claim: "The demonstrated security impact is: Session theft",
          required: true,
          status: "verified",
          evidence: "payload executes in browser context",
        },
      ],
    },
    cvss: {
      score: 8.2,
      severity: "HIGH",
      vectorString: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N",
      reasoning: "remote unauth",
    },
    threatModelAlignment: null,
    decision: {
      outcome: "accept",
      reason: "confirmed",
      rationale: "Reproduced against the live target; CVSS severity HIGH.",
      suggestedHackerOneState: "Triaged",
      draftReplyMessage:
        "@researcher123 — thanks for the report. We've reproduced the issue.",
    },
    remediation: {
      filesChanged: [
        {
          filePath: "src/routes/search.ts",
          changesDescription: "HTML-encode the q parameter before reflecting",
        },
      ],
      prTitle: "Fix: HTML-encode q in /search",
      prDescription: "Encodes reflected output to neutralise the XSS.",
    },
    ...overrides,
  };
}

describe("renderTriageMarkdown", () => {
  it("includes the decision header at the top", () => {
    const md = renderTriageMarkdown(makeResult());
    expect(md).toMatch(/^# Triage: Reflected XSS/);
    expect(md).toContain("`accept`");
    expect(md).toContain("`confirmed`");
  });

  it("embeds the remediation draft when present", () => {
    const md = renderTriageMarkdown(makeResult());
    expect(md).toContain("## Suggested remediation");
    expect(md).toContain("Fix: HTML-encode q in /search");
    expect(md).toContain("`src/routes/search.ts`");
  });

  it("omits the remediation section when null", () => {
    const md = renderTriageMarkdown(makeResult({ remediation: null }));
    expect(md).not.toContain("## Suggested remediation");
  });

  it("flags severity recalibration when claimed != recalibrated", () => {
    const md = renderTriageMarkdown(
      makeResult({
        report: {
          ...makeResult().report,
          claimedSeverity: "CRITICAL",
        },
        cvss: {
          score: 4.5,
          severity: "MEDIUM",
          vectorString: "...",
          reasoning: "...",
        },
      }),
    );
    expect(md).toContain("reporter claimed `CRITICAL`");
    expect(md).toContain("recalibrated to `MEDIUM`");
  });

  it("notes when verification was skipped", () => {
    const md = renderTriageMarkdown(
      makeResult({
        verification: null,
        claimVerification: null,
        cvss: null,
        decision: {
          outcome: "reject",
          reason: "out-of-scope",
          rationale: "Host not allowed",
          suggestedHackerOneState: "Not Applicable",
          draftReplyMessage: "Reporter — out of scope.",
        },
        remediation: null,
      }),
    );
    expect(md).toContain("_Verification was skipped._");
    expect(md).toContain("_Claim verification was skipped._");
    expect(md).toContain("_CVSS scoring was skipped");
  });

  it("renders claim verification statuses", () => {
    const md = renderTriageMarkdown(makeResult());
    expect(md).toContain("## Claim verification");
    expect(md).toContain("All required material claims were verified.");
    expect(md).toContain("`verified`");
    expect(md).toContain("payload reflected");
  });

  it("renders black-box remediation guidance without files changed", () => {
    const md = renderTriageMarkdown(
      makeResult({
        remediation: {
          filesChanged: [],
          prTitle: "Remediation guidance: Reflected XSS in search",
          prDescription: "Encode reflected output and add regression coverage.",
        },
      }),
    );
    expect(md).toContain("Remediation guidance: Reflected XSS in search");
    expect(md).toContain("No source files were changed");
    expect(md).not.toContain("### Files changed");
  });

  it("renders the suggested HackerOne action section with state + draft reply", () => {
    const md = renderTriageMarkdown(makeResult());
    expect(md).toContain("## Submission readiness");
    expect(md).toContain("Status: **Potentially submission-ready**");
    expect(md).toContain("## Suggested HackerOne action");
    expect(md).toContain("Transition to: **Triaged**");
    expect(md).toContain("### Draft reply to reporter");
    expect(md).toContain("> @researcher123");
  });

  it("renders the host scope source under scope check", () => {
    const md = renderTriageMarkdown(makeResult());
    expect(md).toContain("Host scope source: `session-allowed-hosts`");
  });

  it("renders report references and CWEs when present", () => {
    const md = renderTriageMarkdown(makeResult());
    expect(md).toContain("### CWE / References");
    expect(md).toContain(
      "CWE-79: Improper Neutralization of Input During Web Page Generation",
    );
    expect(md).toContain("OWASP Testing Guide: Cross Site Scripting");
  });

  it("warns that generic information disclosure needs concrete impact", () => {
    const md = renderTriageMarkdown(
      makeResult({
        report: {
          ...makeResult().report,
          title: "Verbose stack trace disclosure",
          vulnerabilityClass: "Information Disclosure",
          description:
            "The endpoint returns a stack trace with internal paths and package versions.",
          impact: "Reconnaissance value for attackers.",
          references: [
            "CWE-209: Generation of Error Message Containing Sensitive Information",
          ],
        },
        verification: {
          reproduced: true,
          evidence:
            "HTTP 500 includes /usr/src/app and express package version details.",
          observations: "Stack trace confirmed.",
        },
        cvss: {
          score: 5.3,
          severity: "MEDIUM",
          vectorString: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
          reasoning: "Implementation metadata disclosure.",
        },
      }),
    );

    expect(md).toContain(
      "Status: **Caution — submit only with a concrete impact chain**",
    );
    expect(md).toContain("generic information disclosure");
    expect(md).toContain("Do not rely on stack traces");
  });

  it("marks rejected reports as not submission-ready", () => {
    const md = renderTriageMarkdown(
      makeResult({
        decision: {
          outcome: "reject",
          reason: "informational",
          rationale: "No concrete security impact.",
          suggestedHackerOneState: "Informative",
          draftReplyMessage: "Thanks, but this is informational.",
        },
        remediation: null,
      }),
    );

    expect(md).toContain("Status: **Not submission-ready**");
    expect(md).toContain("triage outcome is `reject` / `informational`");
  });
});
