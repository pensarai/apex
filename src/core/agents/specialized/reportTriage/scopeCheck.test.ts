import { describe, expect, it } from "vitest";
import { checkScope } from "./scopeCheck";
import type { BountyReport, ProgramContext } from "./types";

function makeReport(overrides: Partial<BountyReport> = {}): BountyReport {
  return {
    title: "Reflected XSS in search endpoint",
    reporterHandle: "h4xor",
    claimedSeverity: "HIGH",
    vulnerabilityClass: "Reflected XSS",
    affectedUrl: "https://staging.example.com/search?q=test",
    affectedComponent: "search",
    attackerModel: "unauthenticated",
    description: "Reflected XSS in /search",
    impact: "Session hijack",
    pocSteps: [],
    pocCurl: undefined,
    references: [],
    ...overrides,
  };
}

const EMPTY_CONTEXT: ProgramContext = {
  scope: null,
  engagement: null,
  businessContext: null,
  threatModel: null,
  threatModelPath: null,
};

describe("checkScope (host layer — pure, no LLM call)", () => {
  // The host-layer check short-circuits when no policy files are present
  // AND the host is in scope, OR when the host is out of scope. Neither
  // path issues a network call, so the test is hermetic.

  it("passes when affected URL host is a subdomain of an allowedHost", async () => {
    const result = await checkScope({
      report: makeReport(),
      programContext: EMPTY_CONTEXT,
      allowedHosts: ["example.com"],
      model: "claude-sonnet-4-5",
    });
    expect(result.inScope).toBe(true);
    expect(result.hostInScope).toBe(true);
    expect(result.policyInScope).toBe(true);
    expect(result.hostScopeSource).toBe("session-allowed-hosts");
    expect(result.reason).toContain("no policy files");
  });

  it("rejects out-of-host reports before consulting policy", async () => {
    const result = await checkScope({
      report: makeReport({ affectedUrl: "https://evil.com/anything" }),
      programContext: { ...EMPTY_CONTEXT, scope: "anything goes" },
      allowedHosts: ["example.com"],
      model: "claude-sonnet-4-5",
    });
    expect(result.inScope).toBe(false);
    expect(result.hostInScope).toBe(false);
    expect(result.reason).toContain("not in allowedHosts");
  });

  it("treats path-only references as host-agnostic (defers to policy)", async () => {
    const result = await checkScope({
      report: makeReport({ affectedUrl: "/api/users/{id}" }),
      programContext: EMPTY_CONTEXT,
      allowedHosts: ["example.com"],
      model: "claude-sonnet-4-5",
    });
    // Host check passes (path-only); policy check skipped (no policy files).
    expect(result.inScope).toBe(true);
    expect(result.hostInScope).toBe(true);
  });

  it("passes everything when allowedHosts is empty (no scope configured)", async () => {
    const result = await checkScope({
      report: makeReport({ affectedUrl: "https://anything.test/foo" }),
      programContext: EMPTY_CONTEXT,
      allowedHosts: [],
      model: "claude-sonnet-4-5",
    });
    expect(result.inScope).toBe(true);
    expect(result.hostInScope).toBe(true);
    expect(result.hostScopeSource).toBe("none");
  });
});

describe("checkScope (structured_scopes take precedence over session)", () => {
  it("prefers H1 structured_scopes when present, even if session allowedHosts is narrower", async () => {
    // The program officially scopes `*.acme.com`. The session was created
    // for a single staging host. A report against api.acme.com should pass
    // the host check (program scope is authoritative) even though it's not
    // in session.allowedHosts.
    const result = await checkScope({
      report: makeReport({
        affectedUrl: "https://api.acme.com/v1/users/123",
        structuredScopes: [
          {
            assetIdentifier: "*.acme.com",
            assetType: "URL",
            eligibleForSubmission: true,
          },
        ],
      }),
      programContext: EMPTY_CONTEXT,
      allowedHosts: ["staging.acme.com"],
      model: "claude-sonnet-4-5",
    });
    expect(result.inScope).toBe(true);
    expect(result.hostInScope).toBe(true);
    expect(result.hostScopeSource).toBe("structured-scopes");
  });

  it("rejects when affected host is not in H1 structured_scopes", async () => {
    const result = await checkScope({
      report: makeReport({
        affectedUrl: "https://wrong.com/foo",
        structuredScopes: [
          {
            assetIdentifier: "*.acme.com",
            assetType: "URL",
            eligibleForSubmission: true,
          },
        ],
      }),
      programContext: EMPTY_CONTEXT,
      allowedHosts: ["staging.acme.com"],
      model: "claude-sonnet-4-5",
    });
    expect(result.inScope).toBe(false);
    expect(result.hostScopeSource).toBe("structured-scopes");
    expect(result.reason).toContain("structured_scopes");
  });

  it("ignores structured_scopes entries that aren't eligible for submission", async () => {
    const result = await checkScope({
      report: makeReport({
        affectedUrl: "https://api.acme.com/v1/users",
        structuredScopes: [
          {
            assetIdentifier: "*.acme.com",
            assetType: "URL",
            eligibleForSubmission: false, // out of scope per H1
          },
        ],
      }),
      programContext: EMPTY_CONTEXT,
      allowedHosts: ["api.acme.com"],
      model: "claude-sonnet-4-5",
    });
    // No eligible URL scopes → fall back to session.allowedHosts.
    expect(result.inScope).toBe(true);
    expect(result.hostScopeSource).toBe("session-allowed-hosts");
  });
});
