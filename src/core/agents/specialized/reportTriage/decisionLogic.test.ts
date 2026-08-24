import { describe, expect, it } from "vitest";
import { buildMaterialClaims } from "./claimVerifier";
import { deriveDecision, mapToHackerOneState } from "./decisionLogic";
import type {
  BountyReport,
  ClaimVerificationResult,
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
  vectorString: "CVSS:3.0/AV:N/AC:L/...",
  reasoning: "remote, unauth, exfil",
};
const CVSS_NONE: CvssSummary = {
  score: 0,
  severity: "NONE",
  vectorString: "CVSS:3.0/AV:N/AC:L/...",
  reasoning: "no demonstrated impact",
};

const VERIFIED_CLAIMS: ClaimVerificationResult = {
  summary: "All required material claims were verified.",
  claims: [
    {
      id: "vulnerability-class",
      claim: "The behavior is a Reflected XSS vulnerability.",
      required: true,
      status: "verified",
      evidence: "payload reflected in executable context",
    },
    {
      id: "affected-location",
      claim: "The affected location is https://staging.example.com/search.",
      required: true,
      status: "verified",
      evidence: "request targeted /search",
    },
    {
      id: "attacker-model",
      claim: "The issue is exploitable by unauthenticated.",
      required: true,
      status: "verified",
      evidence: "no credentials were used",
    },
    {
      id: "security-impact",
      claim: "The demonstrated security impact is: Session theft",
      required: true,
      status: "verified",
      evidence: "script execution allows session theft",
    },
  ],
};

const PARTIAL_CLAIMS: ClaimVerificationResult = {
  summary: "The redirect was observed, but impact was not fully verified.",
  claims: [
    {
      ...VERIFIED_CLAIMS.claims[0],
      status: "partial",
      evidence: "evidence shows a redirect, but not the claimed impact",
    },
  ],
};

const VERIFIED_WITH_OPTIONAL_PARTIAL_CLAIMS: ClaimVerificationResult = {
  summary:
    "The core vulnerability is verified; one downstream impact detail is partial.",
  claims: [
    ...VERIFIED_CLAIMS.claims,
    {
      id: "claimed-impact-details",
      claim:
        "The evidence supports every downstream impact detail in the report.",
      required: false,
      status: "partial",
      evidence:
        "The core email disclosure is verified, but the regulatory impact is not proven.",
    },
    {
      id: "poc-steps",
      claim: "Every PoC variant in the report was reproduced.",
      required: false,
      status: "partial",
      evidence:
        "The primary PoC reproduced, but not every listed variant was retested.",
    },
  ],
};

const CONTRADICTED_CLAIMS: ClaimVerificationResult = {
  summary: "The affected location claim is contradicted.",
  claims: [
    {
      ...VERIFIED_CLAIMS.claims[1],
      status: "contradicted",
      evidence: "the endpoint returned 404 and no redirect/reflection occurred",
    },
  ],
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
      claimVerification: VERIFIED_CLAIMS,
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
      claimVerification: VERIFIED_CLAIMS,
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
      claimVerification: VERIFIED_CLAIMS,
      cvss: CVSS_HIGH,
      threatModelAlignment: TM_NEUTRAL,
    });
    expect(decision.outcome).toBe("accept");
    expect(decision.reason).toBe("confirmed");
    expect(decision.rationale).toContain("HIGH");
  });

  it("needs info when reproduced but material claims were not verified", () => {
    const decision = deriveDecision({
      scope: SCOPE_PASS,
      duplicate: NO_DUP,
      verification: REPRODUCED,
      claimVerification: null,
      cvss: CVSS_HIGH,
      threatModelAlignment: null,
    });
    expect(decision.outcome).toBe("needs-info");
    expect(decision.reason).toBe("missing-info");
    expect(decision.rationale).toContain("material report claims");
  });

  it("rejects as informational noise when a required claim is only partially verified", () => {
    const decision = deriveDecision({
      scope: SCOPE_PASS,
      duplicate: NO_DUP,
      verification: REPRODUCED,
      claimVerification: PARTIAL_CLAIMS,
      cvss: CVSS_HIGH,
      threatModelAlignment: null,
    });
    expect(decision.outcome).toBe("reject");
    expect(decision.reason).toBe("informational");
    expect(decision.rationale).toContain("noise/informational");
    expect(decision.rationale).toContain("vulnerability-class=partial");
  });

  it("does not reject verified findings because optional downstream claims are partial", () => {
    const decision = deriveDecision({
      scope: SCOPE_PASS,
      duplicate: NO_DUP,
      verification: REPRODUCED,
      claimVerification: VERIFIED_WITH_OPTIONAL_PARTIAL_CLAIMS,
      cvss: CVSS_HIGH,
      threatModelAlignment: null,
    });
    expect(decision.outcome).toBe("accept");
    expect(decision.reason).toBe("confirmed");
  });

  it("rejects generic metadata disclosure without demonstrated attacker harm", () => {
    const decision = deriveDecision({
      scope: SCOPE_PASS,
      duplicate: NO_DUP,
      verification: {
        reproduced: true,
        evidence:
          "HTTP 400 S3 InvalidArgument echoes an Authorization header containing an ASIA access key ID, signed headers, internal header names, and a request signature. The secret access key and session token value are not disclosed.",
        observations:
          "This provides reconnaissance value but no direct AWS access was demonstrated.",
      },
      claimVerification: VERIFIED_CLAIMS,
      cvss: CVSS_HIGH,
      threatModelAlignment: null,
      report: {
        ...SAMPLE_REPORT,
        title: "STS Access Key ID disclosed via S3 InvalidArgument",
        vulnerabilityClass:
          "Information Disclosure / Error Message Containing Sensitive Information",
        affectedUrl: "https://www.example.com/.well-known/security.txt",
        affectedComponent: "S3 error response",
        description:
          "The S3 error response exposes an access key ID, signed headers, internal headers, and AWS metadata.",
        impact:
          "The access key ID and internal header names provide infrastructure reconnaissance value.",
      },
    });

    expect(decision.outcome).toBe("reject");
    expect(decision.reason).toBe("informational");
    expect(decision.rationale).toContain("generic information disclosure");
    expect(decision.rationale).toContain("concrete harm");
  });

  it("does not reject information disclosure when secret abuse is demonstrated", () => {
    const decision = deriveDecision({
      scope: SCOPE_PASS,
      duplicate: NO_DUP,
      verification: {
        reproduced: true,
        evidence:
          "The response exposed an auth token. The auth token was used to access another user's private profile data.",
        observations:
          "Unauthorized data access was confirmed with the leaked token.",
      },
      claimVerification: VERIFIED_CLAIMS,
      cvss: CVSS_HIGH,
      threatModelAlignment: null,
      report: {
        ...SAMPLE_REPORT,
        title: "Auth token exposed in error response",
        vulnerabilityClass: "Information Disclosure",
        description:
          "Verbose error response returned an auth token and private user data.",
        impact:
          "The disclosed auth token was used for unauthorized data access.",
      },
    });

    expect(decision.outcome).toBe("accept");
    expect(decision.reason).toBe("confirmed");
  });

  it("rejects reproduced reports when a required claim is contradicted", () => {
    const decision = deriveDecision({
      scope: SCOPE_PASS,
      duplicate: NO_DUP,
      verification: REPRODUCED,
      claimVerification: CONTRADICTED_CLAIMS,
      cvss: CVSS_HIGH,
      threatModelAlignment: null,
    });
    expect(decision.outcome).toBe("reject");
    expect(decision.reason).toBe("unreproducible");
    expect(decision.rationale).toContain("affected-location=contradicted");
  });

  it("accepts even when threat-model alignment is missing", () => {
    const decision = deriveDecision({
      scope: SCOPE_PASS,
      duplicate: NO_DUP,
      verification: REPRODUCED,
      claimVerification: VERIFIED_CLAIMS,
      cvss: CVSS_HIGH,
      threatModelAlignment: null,
    });
    expect(decision.outcome).toBe("accept");
    expect(decision.reason).toBe("confirmed");
  });
});

describe("buildMaterialClaims", () => {
  it("requires only the minimum viable vulnerability and keeps downstream details optional", () => {
    const claims = buildMaterialClaims({
      ...SAMPLE_REPORT,
      affectedComponent: "search parameter",
      pocSteps: ["Send q=<script>alert(1)</script>"],
    });

    expect(
      claims.find((claim) => claim.id === "security-impact")?.required,
    ).toBe(true);
    expect(
      claims.find((claim) => claim.id === "claimed-impact-details")?.required,
    ).toBe(false);
    expect(
      claims.find((claim) => claim.id === "affected-component")?.required,
    ).toBe(false);
    expect(claims.find((claim) => claim.id === "poc-steps")?.required).toBe(
      false,
    );
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
      claimVerification: VERIFIED_CLAIMS,
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
      claimVerification: VERIFIED_CLAIMS,
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
      claimVerification: VERIFIED_CLAIMS,
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
      claimVerification: VERIFIED_CLAIMS,
      cvss: CVSS_HIGH,
      threatModelAlignment: null,
      report: { ...SAMPLE_REPORT, reporterHandle: undefined },
    });
    expect(d.draftReplyMessage.startsWith("Hi —")).toBe(true);
  });
});
