import { describe, expect, it } from "vitest";
import { deriveDecision, mapToHackerOneState } from "./decisionLogic";
import type {
  BountyReport,
  CvssSummary,
  DupCheckResult,
  LiveVerificationResult,
  ScopeCheckResult,
  ThreatModelAlignment,
} from "./types";

const SCOPE_PASS: ScopeCheckResult = {
  inScope: true,
  hostInScope: true,
  policyInScope: true,
  hostScopeSource: "session-allowed-hosts",
  reason: "in scope",
};
const SCOPE_FAIL: ScopeCheckResult = {
  inScope: false,
  hostInScope: false,
  policyInScope: false,
  hostScopeSource: "session-allowed-hosts",
  reason: "host 'evil.com' not in allowedHosts [example.com]",
};

const SAMPLE_REPORT: BountyReport = {
  title: "Reflected XSS in /search",
  reporterHandle: "researcher123",
  claimedSeverity: "HIGH",
  vulnerabilityClass: "Reflected XSS",
  affectedUrl: "https://staging.example.com/search",
  attackerModel: "unauthenticated",
  description: "Reflected XSS in q",
  impact: "Session theft",
  pocSteps: [],
  references: [],
};

const NO_DUP: DupCheckResult = { duplicate: false, matchType: "none" };
const DUP_EXACT: DupCheckResult = {
  duplicate: true,
  matchType: "exact",
  matchedTitle: "Reflected XSS in /search",
  matchedEndpoint: "https://example.com/search",
};

const REPRODUCED: LiveVerificationResult = {
  reproduced: true,
  evidence: "200 OK; response body reflected `<script>alert(1)</script>`",
  observations: "first attempt succeeded",
};
const NOT_REPRODUCED: LiveVerificationResult = {
  reproduced: false,
  evidence: "400 Bad Request on three reasonable variations",
  observations: "endpoint rejects the payload — looks patched",
};

const CVSS_HIGH: CvssSummary = {
  score: 8.2,
  severity: "HIGH",
  vectorString: "CVSS:4.0/AV:N/AC:L/...",
  reasoning: "remote, unauth, exfil",
};
const CVSS_NONE: CvssSummary = {
  score: 0,
  severity: "NONE",
  vectorString: "CVSS:4.0/AV:N/AC:L/...",
  reasoning: "no demonstrated impact",
};

const TM_ACCEPTED: ThreatModelAlignment = {
  aligned: true,
  mappedThreats: ["AP-007"],
  businessAcceptedRisk: true,
  notes: "engagement explicitly marks this as accepted risk",
};
const TM_NEUTRAL: ThreatModelAlignment = {
  aligned: true,
  mappedThreats: ["AP-007"],
  businessAcceptedRisk: false,
  notes: "maps onto AP-007",
};

describe("deriveDecision", () => {
  it("rejects out-of-scope before doing any other work", () => {
    const decision = deriveDecision({
      scope: SCOPE_FAIL,
      duplicate: NO_DUP,
      verification: REPRODUCED,
      cvss: CVSS_HIGH,
      threatModelAlignment: TM_NEUTRAL,
    });
    expect(decision.outcome).toBe("reject");
    expect(decision.reason).toBe("out-of-scope");
    expect(decision.rationale).toContain("not in allowedHosts");
  });

  it("rejects duplicate reports without looking at verification", () => {
    const decision = deriveDecision({
      scope: SCOPE_PASS,
      duplicate: DUP_EXACT,
      verification: null,
      cvss: null,
      threatModelAlignment: null,
    });
    expect(decision.outcome).toBe("reject");
    expect(decision.reason).toBe("duplicate");
    expect(decision.rationale).toContain("Reflected XSS in /search");
  });

  it("returns needs-info when verification did not run", () => {
    const decision = deriveDecision({
      scope: SCOPE_PASS,
      duplicate: NO_DUP,
      verification: null,
      cvss: null,
      threatModelAlignment: null,
    });
    expect(decision.outcome).toBe("needs-info");
    expect(decision.reason).toBe("missing-info");
  });

  it("rejects unreproducible reports", () => {
    const decision = deriveDecision({
      scope: SCOPE_PASS,
      duplicate: NO_DUP,
      verification: NOT_REPRODUCED,
      cvss: null,
      threatModelAlignment: null,
    });
    expect(decision.outcome).toBe("reject");
    expect(decision.reason).toBe("unreproducible");
    expect(decision.rationale).toContain("looks patched");
  });

  it("rejects reproduced findings that the threat model marks accepted", () => {
    const decision = deriveDecision({
      scope: SCOPE_PASS,
      duplicate: NO_DUP,
      verification: REPRODUCED,
      cvss: CVSS_HIGH,
      threatModelAlignment: TM_ACCEPTED,
    });
    expect(decision.outcome).toBe("reject");
    expect(decision.reason).toBe("business-accepted-risk");
  });

  it("rejects reproduced findings with CVSS score 0 / severity NONE as informational", () => {
    const decision = deriveDecision({
      scope: SCOPE_PASS,
      duplicate: NO_DUP,
      verification: REPRODUCED,
      cvss: CVSS_NONE,
      threatModelAlignment: TM_NEUTRAL,
    });
    expect(decision.outcome).toBe("reject");
    expect(decision.reason).toBe("informational");
  });

  it("accepts reproduced, in-scope, non-duplicate findings with impact", () => {
    const decision = deriveDecision({
      scope: SCOPE_PASS,
      duplicate: NO_DUP,
      verification: REPRODUCED,
      cvss: CVSS_HIGH,
      threatModelAlignment: TM_NEUTRAL,
    });
    expect(decision.outcome).toBe("accept");
    expect(decision.reason).toBe("confirmed");
    expect(decision.rationale).toContain("HIGH");
  });

  it("accepts even when threat-model alignment is missing", () => {
    const decision = deriveDecision({
      scope: SCOPE_PASS,
      duplicate: NO_DUP,
      verification: REPRODUCED,
      cvss: CVSS_HIGH,
      threatModelAlignment: null,
    });
    expect(decision.outcome).toBe("accept");
    expect(decision.reason).toBe("confirmed");
  });
});

describe("mapToHackerOneState", () => {
  it("maps every TriageReason onto a canonical H1 state", () => {
    expect(mapToHackerOneState("confirmed")).toBe("Triaged");
    expect(mapToHackerOneState("duplicate")).toBe("Duplicate");
    expect(mapToHackerOneState("out-of-scope")).toBe("Not Applicable");
    expect(mapToHackerOneState("unreproducible")).toBe("Not Applicable");
    expect(mapToHackerOneState("informational")).toBe("Informative");
    expect(mapToHackerOneState("business-accepted-risk")).toBe("Informative");
    expect(mapToHackerOneState("missing-info")).toBe("Needs More Info");
  });
});

describe("deriveDecision — H1 state + draft reply", () => {
  it("populates suggestedHackerOneState for an accept", () => {
    const d = deriveDecision({
      scope: SCOPE_PASS,
      duplicate: NO_DUP,
      verification: REPRODUCED,
      cvss: CVSS_HIGH,
      threatModelAlignment: TM_NEUTRAL,
      report: SAMPLE_REPORT,
    });
    expect(d.suggestedHackerOneState).toBe("Triaged");
    expect(d.draftReplyMessage).toContain("@researcher123");
    expect(d.draftReplyMessage).toContain("Reflected XSS in /search");
    expect(d.draftReplyMessage).toContain("HIGH severity");
  });

  it("populates the right state for a duplicate", () => {
    const d = deriveDecision({
      scope: SCOPE_PASS,
      duplicate: DUP_EXACT,
      verification: null,
      cvss: null,
      threatModelAlignment: null,
      report: SAMPLE_REPORT,
    });
    expect(d.suggestedHackerOneState).toBe("Duplicate");
    expect(d.draftReplyMessage).toContain("duplicate");
    expect(d.draftReplyMessage).toContain("Reflected XSS in /search");
  });

  it("populates the right state for out-of-scope", () => {
    const d = deriveDecision({
      scope: SCOPE_FAIL,
      duplicate: NO_DUP,
      verification: null,
      cvss: null,
      threatModelAlignment: null,
      report: SAMPLE_REPORT,
    });
    expect(d.suggestedHackerOneState).toBe("Not Applicable");
    expect(d.draftReplyMessage).toContain("out of scope");
  });

  it("populates the right state for unreproducible", () => {
    const d = deriveDecision({
      scope: SCOPE_PASS,
      duplicate: NO_DUP,
      verification: NOT_REPRODUCED,
      cvss: null,
      threatModelAlignment: null,
      report: SAMPLE_REPORT,
    });
    expect(d.suggestedHackerOneState).toBe("Not Applicable");
    expect(d.draftReplyMessage).toContain("unable to");
  });

  it("populates the right state for informational", () => {
    const d = deriveDecision({
      scope: SCOPE_PASS,
      duplicate: NO_DUP,
      verification: REPRODUCED,
      cvss: CVSS_NONE,
      threatModelAlignment: TM_NEUTRAL,
      report: SAMPLE_REPORT,
    });
    expect(d.suggestedHackerOneState).toBe("Informative");
  });

  it("populates the right state for business-accepted risk", () => {
    const d = deriveDecision({
      scope: SCOPE_PASS,
      duplicate: NO_DUP,
      verification: REPRODUCED,
      cvss: CVSS_HIGH,
      threatModelAlignment: TM_ACCEPTED,
      report: SAMPLE_REPORT,
    });
    expect(d.suggestedHackerOneState).toBe("Informative");
    expect(d.draftReplyMessage).toContain("accepted risk");
  });

  it("populates the right state for missing-info", () => {
    const d = deriveDecision({
      scope: SCOPE_PASS,
      duplicate: NO_DUP,
      verification: null,
      cvss: null,
      threatModelAlignment: null,
      report: SAMPLE_REPORT,
    });
    expect(d.suggestedHackerOneState).toBe("Needs More Info");
    expect(d.draftReplyMessage).toContain("additional details");
  });

  it("falls back to 'Hi' when no reporter handle is known", () => {
    const d = deriveDecision({
      scope: SCOPE_PASS,
      duplicate: NO_DUP,
      verification: REPRODUCED,
      cvss: CVSS_HIGH,
      threatModelAlignment: null,
      report: { ...SAMPLE_REPORT, reporterHandle: undefined },
    });
    expect(d.draftReplyMessage.startsWith("Hi —")).toBe(true);
  });
});
