import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { Finding } from "../agents/offSecAgent/types";
import { generateObjectResponse } from "../ai";
import {
  classifyFromContent,
  extractTitleStem,
  extractVulnClass,
  FindingsRegistry,
  generateFingerprint,
  normalizeEndpoint,
} from "./registry";

vi.mock("fs", () => ({
  existsSync: vi.fn(),
  readdirSync: vi.fn(),
  readFileSync: vi.fn(),
}));

vi.mock("../ai", () => ({
  generateObjectResponse: vi.fn(),
}));

// ---------------------------------------------------------------------------
// Test fixture factory
// ---------------------------------------------------------------------------

function makeFinding(overrides: Partial<Finding> = {}): Finding {
  return {
    title: "Test Finding",
    severity: "MEDIUM",
    description: "A test vulnerability.",
    impact: "Test impact.",
    evidence: "Test evidence.",
    endpoint: "https://target.com/api/test",
    pocPath: "pocs/poc_test.sh",
    remediation: "Fix the thing.",
    ...overrides,
  };
}

// Pre-built fixtures modeled after real findings from ~/.pensar/sessions/
const sqlInjectionProducts = makeFinding({
  title: "SQL Injection in /api/products Search Parameter",
  severity: "CRITICAL",
  endpoint: "https://target.com/api/products",
  description:
    "The /api/products endpoint's search query parameter is vulnerable to SQL injection.",
  remediation: "Use parameterized queries.",
  references: "CWE-89, OWASP A03:2021",
  cwes: [
    {
      id: "CWE-89",
      reasoning:
        "Classic SQL injection via unsanitized user input in the search query parameter.",
    },
  ],
});

const sqlInjectionProductsId = makeFinding({
  title: "SQL Injection in /api/products Endpoint (GET id parameter)",
  severity: "CRITICAL",
  endpoint: "https://target.com/api/products",
  description:
    "The /api/products endpoint is vulnerable to SQL injection through the id GET parameter.",
  remediation: "Implement parameterized queries.",
  references: "CWE-89, OWASP A03:2021",
});

const sqlInjectionOrders = makeFinding({
  title: "SQL Injection in /api/orders Search Parameter",
  severity: "CRITICAL",
  endpoint: "https://target.com/api/orders",
  description:
    "The /api/orders endpoint search param is vulnerable to SQL injection.",
  remediation: "Use parameterized queries.",
});

const missingCspRoot = makeFinding({
  title: "Missing Content Security Policy (CSP) Header",
  severity: "HIGH",
  endpoint: "https://target.com/",
  description: "The application does not implement a CSP header.",
  remediation: "Implement a Content Security Policy header.",
});

const missingCspApi = makeFinding({
  title: "Missing Content Security Policy (CSP) Header",
  severity: "HIGH",
  endpoint: "https://target.com/api/users",
  description: "The API endpoint does not implement a CSP header.",
  remediation: "Implement a Content Security Policy header.",
});

const corsWildcard = makeFinding({
  title: "Misconfigured CORS Policy - Allows All Origins and Methods",
  severity: "HIGH",
  endpoint: "https://target.com/",
  description: "The API is configured with overly permissive CORS headers.",
  remediation: "Fix CORS configuration to whitelist specific origins.",
});

const corsOnApi = makeFinding({
  title: "Misconfigured CORS Policy - Allows All Origins and Methods",
  severity: "HIGH",
  endpoint: "https://target.com/api/orders",
  description: "The orders API allows all origins and methods.",
  remediation: "Fix CORS configuration.",
});

const reflectedXss = makeFinding({
  title: "Reflected XSS via Search Parameter",
  severity: "HIGH",
  endpoint: "https://target.com/search",
  description: "Reflected cross-site scripting in the search parameter.",
  remediation: "Sanitize user input and encode output.",
  cwes: [
    {
      id: "CWE-79",
      reasoning:
        "Reflected XSS via unsanitized search parameter injected into the response.",
    },
  ],
});

const storedXss = makeFinding({
  title: "Stored XSS in Profile Name Field",
  severity: "HIGH",
  endpoint: "https://target.com/api/profile",
  description: "Stored cross-site scripting in the profile name field.",
  remediation: "Sanitize stored user input and encode on render.",
});

const sentryExposure = makeFinding({
  title:
    "Information Disclosure: Sentry Public Key Exposed in Documentation Meta Tags",
  severity: "LOW",
  endpoint: "https://docs.target.com/overview",
  description: "Sentry error tracking public key is exposed in meta tags.",
  remediation: "Consider using CSP to restrict Sentry event submission.",
  references: "CWE-200",
  cwes: [
    {
      id: "CWE-200",
      reasoning:
        "Sentry public key exposed in HTML meta tags constitutes information disclosure.",
    },
  ],
});

// ---------------------------------------------------------------------------
// extractVulnClass
// ---------------------------------------------------------------------------

describe("extractVulnClass", () => {
  it("classifies SQL injection titles", () => {
    expect(extractVulnClass("SQL Injection in /api/products")).toBe(
      "sql-injection",
    );
    expect(extractVulnClass("Blind SQL Injection via search")).toBe(
      "sql-injection",
    );
  });

  it("classifies XSS titles (reflected and stored share the class)", () => {
    expect(extractVulnClass("Reflected XSS via Search")).toBe("xss");
    expect(extractVulnClass("Stored XSS in Profile")).toBe("xss");
    expect(extractVulnClass("Cross-Site Scripting in input field")).toBe("xss");
  });

  it("classifies missing CSP", () => {
    expect(
      extractVulnClass("Missing Content Security Policy (CSP) Header"),
    ).toBe("missing-csp");
    expect(extractVulnClass("Missing CSP on all endpoints")).toBe(
      "missing-csp",
    );
  });

  it("classifies CORS issues", () => {
    expect(extractVulnClass("Misconfigured CORS Policy")).toBe("cors");
    expect(
      extractVulnClass("Cross-Origin Resource Sharing Misconfiguration"),
    ).toBe("cors");
  });

  it("classifies IDOR", () => {
    expect(extractVulnClass("IDOR on User Profile Endpoint")).toBe("idor");
    expect(extractVulnClass("Insecure Direct Object Reference in orders")).toBe(
      "idor",
    );
  });

  it("classifies missing-authentication patterns", () => {
    expect(extractVulnClass("Missing Authentication on /api/admin")).toBe(
      "missing-authentication",
    );
    expect(extractVulnClass("No Authentication Required for API")).toBe(
      "missing-authentication",
    );
    expect(extractVulnClass("Unauthenticated Access to Admin Dashboard")).toBe(
      "missing-authentication",
    );
  });

  it("does not misclassify titles where 'no' is a substring before 'auth'", () => {
    expect(extractVulnClass("Known Auth Vulnerability")).toBe(
      "known-auth-vulnerability",
    );
    expect(extractVulnClass("Minor Auth Misconfiguration")).toBe(
      "minor-auth-misconfiguration",
    );
    expect(extractVulnClass("Canonical Auth Token Leak")).toBe(
      "canonical-auth-token-leak",
    );
  });

  it("classifies SSRF", () => {
    expect(extractVulnClass("Server-Side Request Forgery")).toBe("ssrf");
    expect(extractVulnClass("SSRF via image upload URL")).toBe("ssrf");
  });

  it("classifies RCE / command injection", () => {
    expect(extractVulnClass("Remote Code Execution via file upload")).toBe(
      "rce",
    );
    expect(extractVulnClass("Command Injection in ping utility")).toBe(
      "command-injection",
    );
  });

  it("classifies path traversal / LFI", () => {
    expect(extractVulnClass("Path Traversal in /api/files")).toBe(
      "path-traversal",
    );
    expect(extractVulnClass("Local File Inclusion via template")).toBe(
      "path-traversal",
    );
    expect(extractVulnClass("Directory Traversal on static assets")).toBe(
      "path-traversal",
    );
  });

  it("classifies information disclosure", () => {
    expect(extractVulnClass("Information Disclosure: Sentry Public Key")).toBe(
      "information-disclosure",
    );
    expect(extractVulnClass("Sensitive Data Exposure in error page")).toBe(
      "information-disclosure",
    );
  });

  it("classifies CSRF", () => {
    expect(
      extractVulnClass("Cross-Site Request Forgery on /api/settings"),
    ).toBe("csrf");
    expect(extractVulnClass("CSRF on form submission")).toBe("csrf");
  });

  it("classifies auth bypass and privilege escalation", () => {
    expect(extractVulnClass("Authentication Bypass via token reuse")).toBe(
      "auth-bypass",
    );
    expect(extractVulnClass("Privilege Escalation to admin role")).toBe(
      "privilege-escalation",
    );
  });

  it("classifies open redirect", () => {
    expect(extractVulnClass("Open Redirect on login callback")).toBe(
      "open-redirect",
    );
  });

  it("classifies missing security headers", () => {
    expect(extractVulnClass("Missing X-Frame-Options Header")).toBe(
      "missing-security-header",
    );
  });

  it("falls back to normalized title for unknown vuln types", () => {
    const cls = extractVulnClass("Unusual Custom Vulnerability Pattern");
    expect(cls).toBe("unusual-custom-vulnerability-pattern");
  });

  it("is case insensitive", () => {
    expect(extractVulnClass("SQL INJECTION IN /API")).toBe("sql-injection");
    expect(extractVulnClass("sql injection in /api")).toBe("sql-injection");
  });
});

// ---------------------------------------------------------------------------
// classifyFromContent
// ---------------------------------------------------------------------------

describe("classifyFromContent", () => {
  it("reclassifies idor to missing-authentication when description indicates no auth", () => {
    const finding = makeFinding({
      title: "IDOR on User Profile Endpoint",
      description:
        "The endpoint allows unauthenticated access to user profiles by iterating IDs.",
      evidence: "curl https://target.com/api/users/1 returns user data.",
    });
    expect(classifyFromContent(finding)).toBe("missing-authentication");
  });

  it("reclassifies idor to missing-authentication when evidence contains PR:N", () => {
    const finding = makeFinding({
      title: "IDOR on User Profile Endpoint",
      description: "User profiles can be accessed by changing the ID.",
      evidence: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N — no auth required.",
    });
    expect(classifyFromContent(finding)).toBe("missing-authentication");
  });

  it("reclassifies idor to missing-authentication when evidence contains PR=N", () => {
    const finding = makeFinding({
      title: "Insecure Direct Object Reference in orders",
      description: "Orders are accessible without authentication.",
      evidence: "Scored with PR=N since no credentials are needed.",
    });
    expect(classifyFromContent(finding)).toBe("missing-authentication");
  });

  it("keeps idor when description does not indicate missing auth", () => {
    const finding = makeFinding({
      title: "IDOR on User Profile Endpoint",
      description:
        "Authenticated users can access other users' profiles by changing the ID parameter.",
      evidence:
        "Logged in as user A, accessed user B profile by changing id=2.",
    });
    expect(classifyFromContent(finding)).toBe("idor");
  });

  it("does not alter non-idor classifications", () => {
    const finding = makeFinding({
      title: "SQL Injection in /api/products",
      description: "The endpoint has no authentication and is SQL injectable.",
    });
    expect(classifyFromContent(finding)).toBe("sql-injection");
  });
});

// ---------------------------------------------------------------------------
// extractTitleStem
// ---------------------------------------------------------------------------

describe("extractTitleStem", () => {
  it("strips endpoint paths from titles", () => {
    expect(
      extractTitleStem("SQL Injection in /api/products Search Parameter"),
    ).toBe("sql injection in search parameter");
  });

  it("produces the same stem for the same vuln on different endpoints", () => {
    const stem1 = extractTitleStem(
      "SQL Injection in /api/products Search Parameter",
    );
    const stem2 = extractTitleStem(
      "SQL Injection in /api/orders Search Parameter",
    );
    expect(stem1).toBe(stem2);
  });

  it("preserves titles without endpoint references", () => {
    expect(
      extractTitleStem("Missing Content Security Policy (CSP) Header"),
    ).toBe("missing content security policy csp header");
  });

  it("produces different stems for different XSS variants", () => {
    const reflected = extractTitleStem("Reflected XSS via Search Parameter");
    const stored = extractTitleStem("Stored XSS in Profile Name Field");
    expect(reflected).not.toBe(stored);
  });

  it("strips full URLs from titles", () => {
    expect(extractTitleStem("SSRF at https://target.com/api/fetch Found")).toBe(
      "ssrf at found",
    );
  });

  it("normalises whitespace and casing", () => {
    expect(extractTitleStem("  XSS   via   INPUT  ")).toBe("xss via input");
  });
});

// ---------------------------------------------------------------------------
// normalizeEndpoint
// ---------------------------------------------------------------------------

describe("normalizeEndpoint", () => {
  it("returns lowercase endpoints unchanged", () => {
    expect(normalizeEndpoint("https://target.com/api/products")).toBe(
      "https://target.com/api/products",
    );
  });

  it("strips trailing slashes", () => {
    expect(normalizeEndpoint("https://target.com/api/products/")).toBe(
      "https://target.com/api/products",
    );
  });

  it("strips query parameters", () => {
    expect(
      normalizeEndpoint("https://target.com/api/products?search=test"),
    ).toBe("https://target.com/api/products");
  });

  it("lowercases the URL", () => {
    expect(normalizeEndpoint("HTTPS://TARGET.COM/API/Products")).toBe(
      "https://target.com/api/products",
    );
  });

  it("leaves bare origin intact", () => {
    expect(normalizeEndpoint("https://target.com")).toBe("https://target.com");
  });

  it("strips fragment identifiers", () => {
    expect(normalizeEndpoint("https://target.com/page#section")).toBe(
      "https://target.com/page",
    );
  });

  it("preserves port numbers", () => {
    expect(normalizeEndpoint("https://target.com:8080/api")).toBe(
      "https://target.com:8080/api",
    );
  });

  it("handles combined query + fragment + trailing slash", () => {
    expect(normalizeEndpoint("https://target.com/api/?q=1#top")).toBe(
      "https://target.com/api",
    );
  });
});

// ---------------------------------------------------------------------------
// generateFingerprint
// ---------------------------------------------------------------------------

describe("generateFingerprint", () => {
  it("exactKey uses endpoint||vulnClass, appWideKey uses stem only", () => {
    const fp = generateFingerprint(sqlInjectionProducts);
    expect(fp.exactKey).toContain("||");
    expect(fp.appWideKey).not.toContain("||");
    expect(fp.appWideKey).toBe(extractTitleStem(sqlInjectionProducts.title));
  });

  it("same endpoint + same vuln class => same exactKey", () => {
    const fp1 = generateFingerprint(sqlInjectionProducts);
    const fp2 = generateFingerprint(sqlInjectionProductsId);
    expect(fp1.exactKey).toBe(fp2.exactKey);
  });

  it("different endpoints => different exactKeys", () => {
    const fp1 = generateFingerprint(sqlInjectionProducts);
    const fp2 = generateFingerprint(sqlInjectionOrders);
    expect(fp1.exactKey).not.toBe(fp2.exactKey);
  });

  it("same title stem => same appWideKey (application-wide dedup)", () => {
    const fp1 = generateFingerprint(missingCspRoot);
    const fp2 = generateFingerprint(missingCspApi);
    expect(fp1.appWideKey).toBe(fp2.appWideKey);
  });

  it("different title stems => different appWideKeys", () => {
    const fp1 = generateFingerprint(reflectedXss);
    const fp2 = generateFingerprint(storedXss);
    expect(fp1.appWideKey).not.toBe(fp2.appWideKey);
  });

  it("unknown vuln types still produce matching appWideKeys across endpoints", () => {
    const finding1 = makeFinding({
      title: "Unusual Custom Vulnerability on /api/users",
      endpoint: "https://target.com/api/users",
    });
    const finding2 = makeFinding({
      title: "Unusual Custom Vulnerability on /api/orders",
      endpoint: "https://target.com/api/orders",
    });
    const fp1 = generateFingerprint(finding1);
    const fp2 = generateFingerprint(finding2);
    expect(fp1.appWideKey).toBe(fp2.appWideKey);
    // exactKeys should differ (different endpoints)
    expect(fp1.exactKey).not.toBe(fp2.exactKey);
  });
});

// ---------------------------------------------------------------------------
// FindingsRegistry — exact endpoint + vuln class dedup
// ---------------------------------------------------------------------------

describe("FindingsRegistry", () => {
  describe("exact endpoint + vuln class dedup", () => {
    it("detects duplicate when same endpoint + same vuln class", async () => {
      const registry = new FindingsRegistry();
      await registry.register(sqlInjectionProducts);

      const check = registry.isDuplicate(sqlInjectionProductsId);
      expect(check.duplicate).toBe(true);
      expect(check.matchType).toBe("exact");
      expect(check.matchedFinding?.title).toBe(sqlInjectionProducts.title);
    });

    it("does not flag different vuln classes on the same endpoint", async () => {
      const registry = new FindingsRegistry();
      await registry.register(sqlInjectionProducts);

      const xssOnProducts = makeFinding({
        title: "Reflected XSS on /api/products",
        endpoint: "https://target.com/api/products",
      });
      const check = registry.isDuplicate(xssOnProducts);
      expect(check.duplicate).toBe(false);
    });

    it("does not flag different endpoints with different vuln classes", async () => {
      const registry = new FindingsRegistry();
      await registry.register(reflectedXss);

      const check = registry.isDuplicate(sentryExposure);
      expect(check.duplicate).toBe(false);
    });
  });

  // -------------------------------------------------------------------------
  // Application-wide dedup
  // -------------------------------------------------------------------------

  describe("application-wide dedup", () => {
    it("detects missing CSP on / then on /api/users as duplicate", async () => {
      const registry = new FindingsRegistry();
      await registry.register(missingCspRoot);

      const check = registry.isDuplicate(missingCspApi);
      expect(check.duplicate).toBe(true);
      expect(check.matchType).toBe("application-wide");
      expect(check.matchedFinding?.title).toBe(missingCspRoot.title);
    });

    it("detects CORS on / then similar CORS on /api/orders as duplicate", async () => {
      const registry = new FindingsRegistry();
      await registry.register(corsWildcard);

      const check = registry.isDuplicate(corsOnApi);
      expect(check.duplicate).toBe(true);
      expect(check.matchType).toBe("application-wide");
    });

    it("detects SQL injection on /api/products then /api/orders as duplicate (same stem)", async () => {
      const registry = new FindingsRegistry();
      await registry.register(sqlInjectionProducts);

      const check = registry.isDuplicate(sqlInjectionOrders);
      expect(check.duplicate).toBe(true);
      expect(check.matchType).toBe("application-wide");
    });

    it("does NOT flag reflected XSS and stored XSS as duplicates (different stems)", async () => {
      const registry = new FindingsRegistry();
      await registry.register(reflectedXss);

      const check = registry.isDuplicate(storedXss);
      expect(check.duplicate).toBe(false);
    });

    it("does NOT flag different vuln classes as duplicates across endpoints", async () => {
      const registry = new FindingsRegistry();
      await registry.register(missingCspRoot);

      const check = registry.isDuplicate(corsWildcard);
      expect(check.duplicate).toBe(false);
    });

    it("deduplicates unknown vuln types across endpoints via stem", async () => {
      const registry = new FindingsRegistry();
      await registry.register(
        makeFinding({
          title: "Unusual Custom Vulnerability on /api/users",
          endpoint: "https://target.com/api/users",
        }),
      );

      const check = registry.isDuplicate(
        makeFinding({
          title: "Unusual Custom Vulnerability on /api/orders",
          endpoint: "https://target.com/api/orders",
        }),
      );
      expect(check.duplicate).toBe(true);
      expect(check.matchType).toBe("application-wide");
    });
  });

  // -------------------------------------------------------------------------
  // Pre-loaded findings
  // -------------------------------------------------------------------------

  describe("pre-loaded findings", () => {
    it("indexes all pre-loaded findings", () => {
      const registry = FindingsRegistry.fromFindings([
        sqlInjectionProducts,
        missingCspRoot,
        corsWildcard,
      ]);

      expect(registry.size).toBe(3);
    });

    it("rejects duplicates of pre-loaded findings", () => {
      const registry = FindingsRegistry.fromFindings([
        sqlInjectionProducts,
        missingCspRoot,
      ]);

      const check = registry.isDuplicate(sqlInjectionProductsId);
      expect(check.duplicate).toBe(true);
      expect(check.matchType).toBe("exact");
    });

    it("accepts genuinely new findings after pre-load", () => {
      const registry = FindingsRegistry.fromFindings([sqlInjectionProducts]);

      const check = registry.isDuplicate(sentryExposure);
      expect(check.duplicate).toBe(false);
    });

    it("returns both pre-loaded and newly registered findings from getFindings()", async () => {
      const registry = FindingsRegistry.fromFindings([
        sqlInjectionProducts,
        missingCspRoot,
      ]);

      await registry.register(sentryExposure);
      const all = registry.getFindings();

      expect(all.length).toBe(3);
      expect(all.map((f) => f.title)).toContain(sentryExposure.title);
      expect(all.map((f) => f.title)).toContain(sqlInjectionProducts.title);
    });
  });

  // -------------------------------------------------------------------------
  // Concurrent registration
  // -------------------------------------------------------------------------

  describe("concurrent registration", () => {
    it("serialises concurrent register calls without losing data", async () => {
      const registry = new FindingsRegistry();

      // 5 agents submit the same finding, 5 submit unique findings
      const duplicateFinding = missingCspRoot;
      const uniqueFindings = [
        sqlInjectionProducts,
        corsWildcard,
        reflectedXss,
        storedXss,
        sentryExposure,
      ];

      const allSubmissions = [
        ...Array(5).fill(duplicateFinding),
        ...uniqueFindings,
      ] as Finding[];

      const results = await Promise.all(
        allSubmissions.map((f) => registry.register(f)),
      );

      // Only 1 of the 5 identical submissions should succeed
      const duplicateResults = results.slice(0, 5);
      const accepted = duplicateResults.filter((r) => !r.duplicate);
      const rejected = duplicateResults.filter((r) => r.duplicate);
      expect(accepted.length).toBe(1);
      expect(rejected.length).toBe(4);

      // All 5 unique findings should succeed
      const uniqueResults = results.slice(5);
      for (const r of uniqueResults) {
        expect(r.duplicate).toBe(false);
      }

      // Total: 1 (from dupes) + 5 (unique) = 6
      expect(registry.size).toBe(6);
    });

    it("handles large concurrent swarm without race conditions", async () => {
      const registry = new FindingsRegistry();

      const findings = Array.from({ length: 50 }, (_, i) =>
        makeFinding({
          title: `Unique Finding ${i}`,
          endpoint: `https://target.com/api/endpoint-${i}`,
        }),
      );

      await Promise.all(findings.map((f) => registry.register(f)));

      expect(registry.size).toBe(50);
    });
  });

  // -------------------------------------------------------------------------
  // Edge cases
  // -------------------------------------------------------------------------

  describe("edge cases", () => {
    it("empty registry returns not-duplicate for any finding", () => {
      const registry = new FindingsRegistry();
      const check = registry.isDuplicate(sqlInjectionProducts);
      expect(check.duplicate).toBe(false);
    });

    it("handles finding with empty title without throwing", async () => {
      const registry = new FindingsRegistry();
      const empty = makeFinding({ title: "" });
      const result = await registry.register(empty);
      expect(result.duplicate).toBe(false);
      expect(registry.size).toBe(1);
    });

    it("handles finding with very long title", async () => {
      const registry = new FindingsRegistry();
      const long = makeFinding({ title: "A".repeat(1000) });
      const result = await registry.register(long);
      expect(result.duplicate).toBe(false);
      expect(registry.size).toBe(1);
    });

    it("vuln class extraction is case insensitive", () => {
      expect(extractVulnClass("SQL INJECTION")).toBe(
        extractVulnClass("sql injection"),
      );
    });

    it("endpoint normalisation handles fragments", () => {
      const finding1 = makeFinding({
        title: "XSS on page",
        endpoint: "https://target.com/page#section",
      });
      const finding2 = makeFinding({
        title: "XSS on page",
        endpoint: "https://target.com/page",
      });
      const fp1 = generateFingerprint(finding1);
      const fp2 = generateFingerprint(finding2);
      expect(fp1.exactKey).toBe(fp2.exactKey);
    });

    it("endpoint normalisation preserves port numbers", () => {
      const finding = makeFinding({
        title: "XSS on page",
        endpoint: "https://target.com:8080/api",
      });
      const fp = generateFingerprint(finding);
      expect(fp.exactKey).toContain("8080");
    });

    it("handles unicode and special characters in title", async () => {
      const registry = new FindingsRegistry();
      const unicode = makeFinding({
        title: "XSS via «script» tag — héllo wörld",
        endpoint: "https://target.com/page",
      });
      const result = await registry.register(unicode);
      expect(result.duplicate).toBe(false);
      expect(registry.size).toBe(1);
    });

    it("getFindings returns a snapshot (not a live reference)", async () => {
      const registry = new FindingsRegistry();
      await registry.register(sqlInjectionProducts);

      const snapshot = registry.getFindings();
      await registry.register(corsWildcard);

      expect(snapshot.length).toBe(1);
      expect(registry.getFindings().length).toBe(2);
    });
  });

  // -------------------------------------------------------------------------
  // fromDirectory
  // -------------------------------------------------------------------------

  describe("fromDirectory", () => {
    let mockedFs: typeof import("fs");

    beforeEach(async () => {
      mockedFs = await import("fs");
    });

    afterEach(() => {
      vi.mocked(mockedFs.existsSync).mockReset();
      vi.mocked(mockedFs.readdirSync).mockReset();
      vi.mocked(mockedFs.readFileSync).mockReset();
    });

    it("loads and indexes JSON findings from a directory", () => {
      vi.mocked(mockedFs.existsSync).mockReturnValue(true);
      vi.mocked(mockedFs.readdirSync).mockReturnValue([
        "finding-1.json",
        "finding-2.json",
        "finding-3.json",
        "finding-1.md",
      ] as unknown as ReturnType<typeof mockedFs.readdirSync>);
      vi.mocked(mockedFs.readFileSync).mockImplementation((filePath) => {
        const p = String(filePath);
        if (p.includes("finding-1.json"))
          return JSON.stringify(sqlInjectionProducts);
        if (p.includes("finding-2.json")) return JSON.stringify(missingCspRoot);
        if (p.includes("finding-3.json")) return JSON.stringify(corsWildcard);
        return "";
      });

      const registry = FindingsRegistry.fromDirectory("/fake/findings");
      expect(registry.size).toBe(3);

      expect(registry.isDuplicate(sqlInjectionProductsId).duplicate).toBe(true);
      expect(registry.isDuplicate(missingCspApi).duplicate).toBe(true);
    });

    it("returns empty registry for missing directory", () => {
      vi.mocked(mockedFs.existsSync).mockReturnValue(false);

      const registry = FindingsRegistry.fromDirectory("/no/such/dir");
      expect(registry.size).toBe(0);
    });

    it("skips malformed JSON files gracefully", () => {
      vi.mocked(mockedFs.existsSync).mockReturnValue(true);
      vi.mocked(mockedFs.readdirSync).mockReturnValue([
        "good.json",
        "bad.json",
      ] as unknown as ReturnType<typeof mockedFs.readdirSync>);
      vi.mocked(mockedFs.readFileSync).mockImplementation((filePath) => {
        const p = String(filePath);
        if (p.includes("good.json")) return JSON.stringify(sentryExposure);
        if (p.includes("bad.json")) return "NOT VALID JSON {{{";
        return "";
      });

      const registry = FindingsRegistry.fromDirectory("/fake/findings");
      expect(registry.size).toBe(1);
    });

    it("skips JSON files that lack required fields", () => {
      vi.mocked(mockedFs.existsSync).mockReturnValue(true);
      vi.mocked(mockedFs.readdirSync).mockReturnValue([
        "good.json",
        "incomplete.json",
      ] as unknown as ReturnType<typeof mockedFs.readdirSync>);
      vi.mocked(mockedFs.readFileSync).mockImplementation((filePath) => {
        const p = String(filePath);
        if (p.includes("good.json")) return JSON.stringify(sentryExposure);
        if (p.includes("incomplete.json"))
          return JSON.stringify({ severity: "HIGH" });
        return "";
      });

      const registry = FindingsRegistry.fromDirectory("/fake/findings");
      expect(registry.size).toBe(1);
    });
  });

  // -------------------------------------------------------------------------
  // register() returns dedup result
  // -------------------------------------------------------------------------

  describe("register() return value", () => {
    it("returns { duplicate: false } for new findings", async () => {
      const registry = new FindingsRegistry();
      const result = await registry.register(sqlInjectionProducts);
      expect(result.duplicate).toBe(false);
      expect(result.matchedFinding).toBeUndefined();
      expect(result.matchType).toBeUndefined();
    });

    it("returns duplicate info with matchedFinding for exact matches", async () => {
      const registry = new FindingsRegistry();
      await registry.register(sqlInjectionProducts);

      const result = await registry.register(sqlInjectionProductsId);
      expect(result.duplicate).toBe(true);
      expect(result.matchType).toBe("exact");
      expect(result.matchedFinding?.title).toBe(sqlInjectionProducts.title);
    });

    it("returns duplicate info with matchedFinding for app-wide matches", async () => {
      const registry = new FindingsRegistry();
      await registry.register(missingCspRoot);

      const result = await registry.register(missingCspApi);
      expect(result.duplicate).toBe(true);
      expect(result.matchType).toBe("application-wide");
      expect(result.matchedFinding?.title).toBe(missingCspRoot.title);
    });

    it("does not add duplicate findings to the registry", async () => {
      const registry = new FindingsRegistry();
      await registry.register(sqlInjectionProducts);
      await registry.register(sqlInjectionProductsId); // duplicate
      await registry.register(sqlInjectionOrders); // app-wide dup

      expect(registry.size).toBe(1);
    });
  });
});

// ---------------------------------------------------------------------------
// Tier 3: Semantic dedup via LLM
// ---------------------------------------------------------------------------

describe("FindingsRegistry Tier 3 (semantic dedup)", () => {
  const mockedGenerate = vi.mocked(generateObjectResponse);

  afterEach(() => {
    mockedGenerate.mockReset();
  });

  it("skips Tier 3 when no model is configured", async () => {
    const registry = new FindingsRegistry(); // no model
    await registry.register(sqlInjectionProducts);

    // This finding has a completely different title/stem, so Tier 1+2 won't catch it.
    // Without a model, Tier 3 is skipped and it should be accepted.
    const noCspRephrased = makeFinding({
      title: "No CSP Header Configured",
      endpoint: "https://target.com/",
    });

    const result = await registry.register(noCspRephrased);
    expect(result.duplicate).toBe(false);
    expect(mockedGenerate).not.toHaveBeenCalled();
  });

  it("skips Tier 3 when registry is empty", async () => {
    const registry = new FindingsRegistry({ model: "test-model" });

    const result = await registry.register(sqlInjectionProducts);
    expect(result.duplicate).toBe(false);
    expect(mockedGenerate).not.toHaveBeenCalled();
  });

  it("calls LLM when Tier 1+2 miss and model is configured", async () => {
    mockedGenerate.mockResolvedValue({
      isDuplicate: true,
      matchedIndex: 1,
      reasoning: "Both describe missing CSP header",
    });

    const registry = new FindingsRegistry({ model: "test-model" });
    await registry.register(missingCspRoot);

    // Different phrasing — Tier 1+2 won't match but LLM will
    const rephrased = makeFinding({
      title: "No CSP Header Configured",
      endpoint: "https://target.com/admin",
    });

    const result = await registry.register(rephrased);
    expect(result.duplicate).toBe(true);
    expect(result.matchType).toBe("semantic");
    expect(result.matchedFinding?.title).toBe(missingCspRoot.title);
    expect(mockedGenerate).toHaveBeenCalledOnce();
  });

  it("accepts finding when LLM says not a duplicate", async () => {
    mockedGenerate.mockResolvedValue({
      isDuplicate: false,
      reasoning: "These are genuinely different vulnerabilities",
    });

    const registry = new FindingsRegistry({ model: "test-model" });
    await registry.register(sqlInjectionProducts);

    const genuinelyNew = makeFinding({
      title: "Broken Access Control on Admin Panel",
      endpoint: "https://target.com/admin",
    });

    const result = await registry.register(genuinelyNew);
    expect(result.duplicate).toBe(false);
    expect(registry.size).toBe(2);
    expect(mockedGenerate).toHaveBeenCalledOnce();
  });

  it("degrades gracefully when LLM errors out", async () => {
    mockedGenerate.mockRejectedValue(new Error("API unavailable"));

    const registry = new FindingsRegistry({ model: "test-model" });
    await registry.register(missingCspRoot);

    const rephrased = makeFinding({
      title: "No CSP Header Configured",
      endpoint: "https://target.com/admin",
    });

    // LLM fails — should fall through and accept the finding
    const result = await registry.register(rephrased);
    expect(result.duplicate).toBe(false);
    expect(registry.size).toBe(2);
  });

  it("does not call LLM when Tier 1 already matches", async () => {
    const registry = new FindingsRegistry({ model: "test-model" });
    await registry.register(sqlInjectionProducts);

    // Exact same endpoint + same vuln class — Tier 1 catches it
    const result = await registry.register(sqlInjectionProductsId);
    expect(result.duplicate).toBe(true);
    expect(result.matchType).toBe("exact");
    expect(mockedGenerate).not.toHaveBeenCalled();
  });

  it("does not call LLM when Tier 2 already matches", async () => {
    const registry = new FindingsRegistry({ model: "test-model" });
    await registry.register(missingCspRoot);

    // Same stem — Tier 2 catches it
    const result = await registry.register(missingCspApi);
    expect(result.duplicate).toBe(true);
    expect(result.matchType).toBe("application-wide");
    expect(mockedGenerate).not.toHaveBeenCalled();
  });

  it("re-checks Tier 1+2 after LLM to guard against races", async () => {
    // Simulate a slow LLM call during which another finding gets registered
    let resolveSlowCall: (value: unknown) => void;
    const slowCall = new Promise((resolve) => {
      resolveSlowCall = resolve;
    });

    mockedGenerate.mockImplementation(async () => {
      await slowCall;
      return { isDuplicate: false, reasoning: "Different" };
    });

    const registry = new FindingsRegistry({ model: "test-model" });
    await registry.register(sqlInjectionProducts);

    // Two agents submit findings that pass Tier 1+2 — both reach the LLM
    const finding1 = makeFinding({
      title: "Broken Access Control on Admin Panel",
      endpoint: "https://target.com/admin",
    });
    const finding2 = makeFinding({
      title: "Broken Access Control on Admin Panel",
      endpoint: "https://target.com/admin",
    });

    const promise1 = registry.register(finding1);
    const promise2 = registry.register(finding2);

    // Release the LLM calls
    resolveSlowCall!(undefined);

    const [result1, result2] = await Promise.all([promise1, promise2]);

    // One should succeed, the other should be caught by the Tier 1+2 re-check
    const accepted = [result1, result2].filter((r) => !r.duplicate);
    const rejected = [result1, result2].filter((r) => r.duplicate);
    expect(accepted.length).toBe(1);
    expect(rejected.length).toBe(1);
    expect(registry.size).toBe(2); // sqlInjection + 1 new
  });

  it("passes correct prompt structure to the LLM", async () => {
    mockedGenerate.mockResolvedValue({
      isDuplicate: false,
      reasoning: "Different",
    });

    const registry = new FindingsRegistry({ model: "test-model" });
    await registry.register(sqlInjectionProducts);

    const newFinding = makeFinding({
      title: "Completely Novel Vulnerability",
      endpoint: "https://target.com/novel",
    });
    await registry.register(newFinding);

    expect(mockedGenerate).toHaveBeenCalledWith(
      expect.objectContaining({
        model: "test-model",
        prompt: expect.stringContaining("Completely Novel Vulnerability"),
        system: expect.stringContaining("deduplication specialist"),
      }),
    );

    // The prompt should contain the existing finding
    const callArgs = mockedGenerate.mock.calls[0]![0] as { prompt: string };
    expect(callArgs.prompt).toContain(sqlInjectionProducts.title);
  });

  it("does not index finding rejected as semantic duplicate", async () => {
    mockedGenerate.mockResolvedValue({
      isDuplicate: true,
      matchedIndex: 1,
      reasoning: "Same vuln, different words",
    });

    const registry = new FindingsRegistry({ model: "test-model" });
    await registry.register(missingCspRoot);

    const rephrased = makeFinding({
      title: "No CSP Header Configured",
      endpoint: "https://target.com/admin",
    });

    const result = await registry.register(rephrased);
    expect(result.duplicate).toBe(true);
    expect(registry.size).toBe(1);
  });

  it("handles LLM returning an out-of-bounds matchedIndex", async () => {
    mockedGenerate.mockResolvedValue({
      isDuplicate: true,
      matchedIndex: 999, // doesn't exist
      reasoning: "Some match",
    });

    const registry = new FindingsRegistry({ model: "test-model" });
    await registry.register(sqlInjectionProducts);

    const newFinding = makeFinding({
      title: "Completely Novel Vulnerability",
      endpoint: "https://target.com/novel",
    });

    // Invalid index should be treated as not-duplicate (safe fallback)
    const result = await registry.register(newFinding);
    expect(result.duplicate).toBe(false);
    expect(registry.size).toBe(2);
  });
});

// ---------------------------------------------------------------------------
// unregister (rollback)
// ---------------------------------------------------------------------------

describe("FindingsRegistry.unregister", () => {
  it("removes a finding from all indexes so it can be re-registered", async () => {
    const registry = new FindingsRegistry();
    const finding = makeFinding({
      title: "SQL Injection in /api/products Search Parameter",
      endpoint: "https://target.com/api/products",
    });

    await registry.register(finding);
    expect(registry.size).toBe(1);

    await registry.unregister(finding);
    expect(registry.size).toBe(0);
    expect(registry.getFindings()).toEqual([]);

    // The same finding (or one with matching fingerprints) can now be registered again
    const result = await registry.register(finding);
    expect(result.duplicate).toBe(false);
    expect(registry.size).toBe(1);
  });

  it("clears both exact and app-wide keys", async () => {
    const registry = new FindingsRegistry();
    await registry.register(missingCspRoot);
    await registry.unregister(missingCspRoot);

    // Exact duplicate should no longer match
    expect(registry.isDuplicate(missingCspRoot).duplicate).toBe(false);

    // App-wide duplicate (same stem, different endpoint) should no longer match
    expect(registry.isDuplicate(missingCspApi).duplicate).toBe(false);
  });

  it("is safe to call on a finding that was never registered", async () => {
    const registry = new FindingsRegistry();
    await registry.unregister(sqlInjectionProducts);
    expect(registry.size).toBe(0);
  });

  it("does not remove other findings that share no keys", async () => {
    const registry = new FindingsRegistry();
    await registry.register(sqlInjectionProducts);
    await registry.register(reflectedXss);
    expect(registry.size).toBe(2);

    await registry.unregister(sqlInjectionProducts);
    expect(registry.size).toBe(1);
    expect(registry.getFindings()[0]!.title).toBe(reflectedXss.title);
  });

  it("only removes the exact reference — not another finding with the same fingerprint", async () => {
    const registry = new FindingsRegistry();
    const finding1 = makeFinding({
      title: "Unique Finding A",
      endpoint: "https://target.com/a",
    });
    const finding2 = makeFinding({
      title: "Unique Finding B",
      endpoint: "https://target.com/b",
    });

    await registry.register(finding1);
    await registry.register(finding2);

    // Unregister finding1 — finding2 should still be there
    await registry.unregister(finding1);
    expect(registry.size).toBe(1);
    expect(registry.getFindings()[0]).toBe(finding2);
  });

  it("serialises correctly with concurrent register/unregister calls", async () => {
    const registry = new FindingsRegistry();
    const finding = makeFinding({
      title: "Concurrent Test Finding",
      endpoint: "https://target.com/concurrent",
    });

    // Register then immediately unregister — should end at size 0
    await registry.register(finding);
    const [, secondRegResult] = await Promise.all([
      registry.unregister(finding),
      registry.register(finding),
    ]);

    // After unregister + re-register, exactly one copy should exist
    expect(secondRegResult.duplicate).toBe(false);
    expect(registry.size).toBe(1);
  });
});

// ---------------------------------------------------------------------------
// groupByRootCause
// ---------------------------------------------------------------------------

describe("groupByRootCause", () => {
  const mockedGenerate = vi.mocked(generateObjectResponse);

  afterEach(() => {
    mockedGenerate.mockReset();
  });

  it("groups Cognito enumeration findings on different endpoints", async () => {
    mockedGenerate.mockResolvedValueOnce({
      groups: [
        {
          groupId: "cognito-user-existence-leak",
          findingIndices: [0, 1],
          rootCause:
            "Cognito leaks user-existence information through distinct error responses",
        },
      ],
    });

    const findings = [
      makeFinding({
        title: "Email Enumeration via Forgot Password Flow",
        endpoint: "https://target.com/forgot-password",
        description:
          "The forgot password endpoint reveals whether an email exists via different error messages from Cognito.",
      }),
      makeFinding({
        title: "Username Enumeration via Cognito Account Lockout Response",
        endpoint: "https://target.com/login",
        description:
          "The login endpoint reveals user existence through Cognito lockout error responses.",
      }),
    ];
    const registry = FindingsRegistry.fromFindings(findings, {
      model: "test-model",
    });

    const groups = await registry.groupByRootCause();

    expect(groups).toHaveLength(1);
    expect(groups[0]!.groupId).toBe("cognito-user-existence-leak");
    expect(groups[0]!.findingIndices).toEqual([0, 1]);

    const allFindings = registry.getFindings();
    expect(allFindings[0]!.rootCauseGroup).toBe("cognito-user-existence-leak");
    expect(allFindings[1]!.rootCauseGroup).toBe("cognito-user-existence-leak");
    expect(allFindings[0]!.relatedFindings).toEqual([allFindings[1]!.title]);
    expect(allFindings[1]!.relatedFindings).toEqual([allFindings[0]!.title]);
  });

  it("groups same-endpoint auth + rate-limiting findings", async () => {
    mockedGenerate.mockResolvedValueOnce({
      groups: [
        {
          groupId: "unauth-ses-access",
          findingIndices: [0, 1],
          rootCause:
            "Unauthenticated access to SES API enables both abuse scenarios",
        },
      ],
    });

    const findings = [
      makeFinding({
        title: "Missing Rate Limiting on Email API",
        severity: "CRITICAL",
        endpoint: "https://target.com/api/email/send",
        description: "The email sending endpoint has no rate limiting.",
      }),
      makeFinding({
        title: "Unauthenticated Email Sending via SES API",
        severity: "HIGH",
        endpoint: "https://target.com/api/email/send",
        description:
          "The email sending endpoint does not require authentication.",
      }),
    ];
    const registry = FindingsRegistry.fromFindings(findings, {
      model: "test-model",
    });

    const groups = await registry.groupByRootCause();

    expect(groups).toHaveLength(1);
    expect(groups[0]!.groupId).toBe("unauth-ses-access");

    const allFindings = registry.getFindings();
    expect(allFindings[0]!.rootCauseGroup).toBe("unauth-ses-access");
    expect(allFindings[1]!.rootCauseGroup).toBe("unauth-ses-access");
  });

  it("does not group unrelated findings", async () => {
    mockedGenerate.mockResolvedValueOnce({
      groups: [],
    });

    const findings = [
      makeFinding({
        title: "SQL Injection in /api/products",
        endpoint: "https://target.com/api/products",
        description: "SQL injection via search parameter.",
      }),
      makeFinding({
        title: "Open Redirect on Login Callback",
        endpoint: "https://target.com/auth/callback",
        description: "Unvalidated redirect parameter in OAuth callback.",
      }),
    ];
    const registry = FindingsRegistry.fromFindings(findings, {
      model: "test-model",
    });

    const groups = await registry.groupByRootCause();

    expect(groups).toHaveLength(0);

    const allFindings = registry.getFindings();
    expect(allFindings[0]!.rootCauseGroup).toBeUndefined();
    expect(allFindings[1]!.rootCauseGroup).toBeUndefined();
  });

  it("returns empty array when no model configured", async () => {
    const registry = new FindingsRegistry(); // no model
    await registry.register(
      makeFinding({
        title: "Finding A",
        endpoint: "https://target.com/a",
      }),
    );
    await registry.register(
      makeFinding({
        title: "Finding B",
        endpoint: "https://target.com/b",
      }),
    );

    const groups = await registry.groupByRootCause();

    expect(groups).toEqual([]);
    expect(mockedGenerate).not.toHaveBeenCalled();
  });

  it("returns empty array when fewer than 2 findings", async () => {
    const registry = new FindingsRegistry({ model: "test-model" });
    await registry.register(
      makeFinding({
        title: "Single Finding",
        endpoint: "https://target.com/a",
      }),
    );

    const groups = await registry.groupByRootCause();

    expect(groups).toEqual([]);
    expect(mockedGenerate).not.toHaveBeenCalled();
  });

  it("sanitises out-of-bounds indices in returned groups", async () => {
    mockedGenerate.mockResolvedValueOnce({
      groups: [
        {
          groupId: "test-group",
          findingIndices: [0, 1, 999, -1],
          rootCause: "Shared root cause",
        },
      ],
    });

    const findings = [
      makeFinding({
        title: "Finding A",
        endpoint: "https://target.com/a",
      }),
      makeFinding({
        title: "Finding B",
        endpoint: "https://target.com/b",
      }),
    ];
    const registry = FindingsRegistry.fromFindings(findings, {
      model: "test-model",
    });

    const groups = await registry.groupByRootCause();

    expect(groups).toHaveLength(1);
    expect(groups[0]!.findingIndices).toEqual([0, 1]);
  });

  it("uses index-based exclusion for relatedFindings (handles same-titled findings)", async () => {
    mockedGenerate.mockResolvedValueOnce({
      groups: [
        {
          groupId: "same-title-group",
          findingIndices: [0, 1, 2],
          rootCause: "Shared root cause across endpoints",
        },
      ],
    });

    const findings = [
      makeFinding({
        title: "User Enumeration",
        endpoint: "https://target.com/login",
      }),
      makeFinding({
        title: "User Enumeration",
        endpoint: "https://target.com/register",
      }),
      makeFinding({
        title: "Different Finding",
        endpoint: "https://target.com/api",
      }),
    ];
    const registry = FindingsRegistry.fromFindings(findings, {
      model: "test-model",
    });

    const groups = await registry.groupByRootCause();

    const allFindings = registry.getFindings();
    // Index 0 should see indices 1 and 2 as related (even though idx 1 has same title)
    expect(allFindings[0]!.relatedFindings).toEqual([
      "User Enumeration",
      "Different Finding",
    ]);
    expect(allFindings[1]!.relatedFindings).toEqual([
      "User Enumeration",
      "Different Finding",
    ]);
    expect(allFindings[2]!.relatedFindings).toEqual([
      "User Enumeration",
      "User Enumeration",
    ]);
    expect(groups).toHaveLength(1);
  });

  it("returns empty array and logs when LLM call fails", async () => {
    mockedGenerate.mockRejectedValueOnce(new Error("API rate limit exceeded"));

    const findings = [
      makeFinding({
        title: "Finding A",
        endpoint: "https://target.com/a",
      }),
      makeFinding({
        title: "Finding B",
        endpoint: "https://target.com/b",
      }),
    ];
    const registry = FindingsRegistry.fromFindings(findings, {
      model: "test-model",
    });

    const groups = await registry.groupByRootCause();

    expect(groups).toEqual([]);
    const allFindings = registry.getFindings();
    expect(allFindings[0]!.rootCauseGroup).toBeUndefined();
    expect(allFindings[1]!.rootCauseGroup).toBeUndefined();
  });
});
