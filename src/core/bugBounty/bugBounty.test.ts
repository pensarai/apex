import { describe, expect, it, vi } from "vitest";
import {
  assertCommandInScope,
  assertUrlAllowedByPolicy,
  EngagementPolicyViolationError,
} from "../agents/offSecAgent/tools/scopeGuard";
import type { ToolContext } from "../agents/offSecAgent/tools/types";
import { analyzeBugBountyListing } from "./analyze";
import { compileEngagementPolicy } from "./policy";

const listing = `
<html>
  <head><title>Acme Security Bug Bounty</title></head>
  <body>
    <h2>In scope</h2>
    <p>https://app.acme.test and *.api.acme.test are eligible.</p>
    <h2>Out of scope</h2>
    <p>https://app.acme.test/admin and status.acme.test</p>
    <h2>Rules of engagement</h2>
    <p>You must not perform denial of service testing.</p>
    <p>Rate limit: 120 requests per minute.</p>
    <p>All requests must include header X-Bug-Bounty: researcher-123</p>
  </body>
</html>`;

describe("bug bounty listing analysis", () => {
  it("extracts assets, exclusions, rules, and required headers", async () => {
    const brief = await analyzeBugBountyListing({
      listingUrl: "https://hackerone.com/acme",
      content: listing,
    });

    expect(brief.platform).toBe("hackerone");
    expect(brief.programName).toBe("Acme Security Bug Bounty");
    expect(brief.assets).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          value: "https://app.acme.test/",
          inScope: true,
        }),
        expect.objectContaining({ value: "*.api.acme.test", inScope: true }),
        expect.objectContaining({
          value: "https://app.acme.test/admin",
          inScope: false,
        }),
      ]),
    );
    expect(brief.requiredHeaders).toEqual([
      expect.objectContaining({
        name: "X-Bug-Bounty",
        value: "researcher-123",
      }),
    ]);
    expect(
      brief.rules.some((rule) => rule.category === "prohibited-action"),
    ).toBe(true);
    expect(compileEngagementPolicy(brief).requestsPerSecond).toBe(2);
  });

  it("rejects loopback listing URLs before fetching", async () => {
    const fetchImpl = vi.fn();
    await expect(
      analyzeBugBountyListing({
        listingUrl: "http://127.0.0.1/program",
        fetchImpl: fetchImpl as unknown as typeof fetch,
      }),
    ).rejects.toThrow("publicly routable");
    expect(fetchImpl).not.toHaveBeenCalled();
  });

  it("rejects public hostnames that resolve to private addresses", async () => {
    const fetchImpl = vi.fn();
    await expect(
      analyzeBugBountyListing({
        listingUrl: "https://listing.example/program",
        fetchImpl: fetchImpl as unknown as typeof fetch,
        resolveHostname: async () => ["169.254.169.254"],
      }),
    ).rejects.toThrow("publicly routable");
    expect(fetchImpl).not.toHaveBeenCalled();
  });

  it("revalidates every redirect target before following it", async () => {
    const fetchImpl = vi.fn(
      async () =>
        new Response(null, {
          status: 302,
          headers: { location: "http://metadata.example/latest" },
        }),
    );
    await expect(
      analyzeBugBountyListing({
        listingUrl: "https://listing.example/program",
        fetchImpl: fetchImpl as unknown as typeof fetch,
        resolveHostname: async (hostname) =>
          hostname === "metadata.example" ? ["10.0.0.1"] : ["8.8.8.8"],
      }),
    ).rejects.toThrow("publicly routable");
    expect(fetchImpl).toHaveBeenCalledTimes(1);
  });
});

describe("engagement policy", () => {
  it("lets explicit URL exclusions override broader inclusions", async () => {
    const brief = await analyzeBugBountyListing({
      listingUrl: "https://bugcrowd.com/acme",
      content: listing,
    });
    const policy = compileEngagementPolicy(brief);

    expect(policy.canExecute).toBe(true);
    expect(() =>
      assertUrlAllowedByPolicy("https://app.acme.test/profile", policy),
    ).not.toThrow();
    expect(() =>
      assertUrlAllowedByPolicy("https://app.acme.test/admin/users", policy),
    ).toThrow(EngagementPolicyViolationError);
    expect(() =>
      assertUrlAllowedByPolicy("https://evil.test/", policy),
    ).toThrow("does not match an explicitly approved asset");

    const ctx = {
      session: {
        targets: ["https://app.acme.test"],
        config: {
          scopeConstraints: { allowedHosts: policy.allowedHosts },
          engagementPolicy: policy,
        },
      },
    } as unknown as ToolContext;
    expect(() =>
      assertCommandInScope("curl https://app.acme.test/profile", ctx),
    ).not.toThrow();
    expect(() => assertCommandInScope("nmap app.acme.test", ctx)).toThrow(
      "bare-host commands require an explicitly approved",
    );
  });

  it("blocks when a required header value is unavailable", async () => {
    const brief = await analyzeBugBountyListing({
      listingUrl: "https://intigriti.com/programs/acme",
      content: listing.replace("researcher-123", "&lt;your-handle&gt;"),
    });

    const blocked = compileEngagementPolicy(brief);
    expect(blocked.canExecute).toBe(false);
    expect(blocked.blockers).toContain(
      'Required header "X-Bug-Bounty" has no configured value.',
    );

    const resolved = compileEngagementPolicy(brief, {
      configuredHeaders: { "x-bug-bounty": "internal-handle" },
    });
    expect(resolved.canExecute).toBe(true);
    expect(resolved.requiredHeaders).toEqual({
      "X-Bug-Bounty": "internal-handle",
    });
  });

  it("blocks rules that cannot be enforced deterministically", async () => {
    const brief = await analyzeBugBountyListing({
      listingUrl: "https://hackerone.com/acme",
      content: listing
        .replace(
          "Rate limit: 120 requests per minute.",
          "Rate limit: be gentle.",
        )
        .replace(
          "You must not perform denial of service testing.",
          "Testing window: weekends only.",
        ),
    });
    const policy = compileEngagementPolicy(brief);
    expect(policy.canExecute).toBe(false);
    expect(policy.blockers).toEqual(
      expect.arrayContaining([
        "The program rate limit could not be enforced automatically.",
        expect.stringContaining("testing window requires manual scheduling"),
      ]),
    );
  });
});
