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
      references: [],
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
    cvss: {
      score: 8.2,
      severity: "HIGH",
      vectorString: "CVSS:4.0/AV:N/AC:L",
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
    expect(md).toContain("_CVSS scoring was skipped");
  });

  it("renders the suggested HackerOne action section with state + draft reply", () => {
    const md = renderTriageMarkdown(makeResult());
    expect(md).toContain("## Suggested HackerOne action");
    expect(md).toContain("Transition to: **Triaged**");
    expect(md).toContain("### Draft reply to reporter");
    expect(md).toContain("> @researcher123");
  });

  it("renders the host scope source under scope check", () => {
    const md = renderTriageMarkdown(makeResult());
    expect(md).toContain("Host scope source: `session-allowed-hosts`");
  });
});
