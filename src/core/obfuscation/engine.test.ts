import { beforeEach, describe, expect, it } from "vitest";
import {
  obfuscate,
  obfuscateValue,
  deobfuscate,
  resetObfuscation,
  setObfuscationEnabled,
  isObfuscationEnabled,
} from "./engine";

describe("obfuscation engine", () => {
  beforeEach(() => {
    resetObfuscation();
    setObfuscationEnabled(true);
  });

  it("is a no-op when disabled", () => {
    setObfuscationEnabled(false);
    expect(obfuscate("alice@acme.com 192.168.1.1")).toBe(
      "alice@acme.com 192.168.1.1",
    );
    expect(isObfuscationEnabled()).toBe(false);
  });

  it("redacts emails with stable placeholders", () => {
    const out1 = obfuscate("Contact alice@acme.com for details");
    const out2 = obfuscate("Email alice@acme.com again");
    expect(out1).toContain("[EMAIL_1]");
    expect(out1).not.toContain("alice@acme.com");
    expect(out2).toContain("[EMAIL_1]");
  });

  it("issues a new placeholder for a different value of the same category", () => {
    obfuscate("alice@acme.com");
    const out = obfuscate("bob@globex.io");
    expect(out).toContain("[EMAIL_2]");
  });

  it("redacts UUIDs", () => {
    const out = obfuscate("session 550e8400-e29b-41d4-a716-446655440000");
    expect(out).toContain("[UUID_1]");
  });

  it("redacts IPv4 addresses", () => {
    const out = obfuscate("Connecting to 10.0.42.17 and 192.168.1.1");
    expect(out).toContain("[IPV4_1]");
    expect(out).toContain("[IPV4_2]");
    expect(out).not.toContain("10.0.42.17");
  });

  it("redacts IPv4 addresses written with hyphens (session-name style)", () => {
    const out = obfuscate("session pentest-10-0-0-1 ready");
    expect(out).toContain("pentest-[IPV4_1]");
    expect(out).not.toContain("10-0-0-1");
  });

  it("does not redact non-octet hyphen sequences (dates, versions)", () => {
    const out = obfuscate("Build 2026-04-28-12 shipped");
    expect(out).toContain("2026-04-28-12");
  });

  it("redacts URLs and underlying hosts consistently", () => {
    const out = obfuscate("GET https://api.acme-corp.internal/v1/users → 200");
    expect(out).toContain("[URL_1]");
    expect(out).not.toContain("acme-corp.internal");
  });

  it("redacts every hostname including the operator's own infra", () => {
    // No allowlist: pensar.dev, github.com, subdomains thereof are all redacted.
    // A bare host gets a HOST placeholder; a host followed by a slash-path is
    // absorbed by the route pattern as a single PATH placeholder, which is
    // strictly more conservative.
    const out = obfuscate(
      "See staging-console.pensar.dev and github.com/org/repo",
    );
    expect(out).toContain("[HOST_1]");
    expect(out).toContain("[PATH_1]");
    expect(out).not.toContain("pensar.dev");
    expect(out).not.toContain("github.com");
    expect(out).not.toContain("/org/repo");
  });

  it("redacts JWTs and bearer-style tokens", () => {
    const jwt =
      "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
    const out = obfuscate(`Authorization: Bearer ${jwt}`);
    expect(out).toContain("[JWT_1]");
    expect(out).not.toContain(jwt);
  });

  it("redacts API keys", () => {
    const out = obfuscate("sk-abcdefghijklmnopqrstuvwxyz1234");
    expect(out).toContain("[TOKEN_1]");
  });

  it("redacts user home paths", () => {
    const out = obfuscate("/Users/alice/code/acme/src/index.ts");
    expect(out).toContain("[PATH_1]");
    expect(out).not.toContain("alice");
  });

  it("redacts API endpoint paths", () => {
    const out = obfuscate(
      "POST /v1/external/sendgrid/{tenant_id} returned 500",
    );
    expect(out).toContain("[PATH_1]");
    expect(out).not.toContain("/v1/external/sendgrid");
    expect(out).not.toContain("{tenant_id}");
  });

  it("redacts debug endpoint paths", () => {
    const out = obfuscate("Hit /__debug/pprof/heap on staging");
    expect(out).toContain("[PATH_1]");
    expect(out).not.toContain("/__debug/pprof/heap");
  });

  it("redacts single-segment debug endpoints", () => {
    const out = obfuscate("Health check at /__health returned 200");
    expect(out).toContain("[PATH_1]");
    expect(out).not.toContain("/__health");
  });

  it("redacts single-segment paths with trailing slash", () => {
    const out = obfuscate("Found /docs/ exposing the OpenAPI spec");
    expect(out).toContain("[PATH_1]");
    expect(out).not.toContain("/docs/");
  });

  it("redacts non-home filesystem paths", () => {
    const out = obfuscate(
      "AI catalog path: /tmp/ai_search_trimmed_catalog_tenant123.json",
    );
    expect(out).toContain("[PATH_1]");
    expect(out).not.toContain("tenant123");
  });

  it("absorbs nested placeholders into the surrounding route", () => {
    const out = obfuscate(
      "Internal document path: /core/documents/550e8400-e29b-41d4-a716-446655440000",
    );
    expect(out).toContain("[PATH_1]");
    expect(out).not.toContain("/core/documents");
    expect(out).not.toContain("550e8400");
  });

  it("redacts multi-segment paths without a leading slash", () => {
    const out = obfuscate("see __debug/config and __debug/endpoints");
    expect(out).not.toContain("__debug/config");
    expect(out).not.toContain("__debug/endpoints");
    expect(out).toMatch(/\[PATH_\d+\]/);
  });

  it("redacts template-style relative paths", () => {
    const out = obfuscate("media/{tenant_id} and access/users/${userId}/tenants");
    expect(out).not.toContain("media/{tenant_id}");
    expect(out).not.toContain("access/users/${userId}/tenants");
    expect(out).toMatch(/\[PATH_\d+\]/);
  });

  it("does not redact a bare slash command standing alone", () => {
    // No char follows → command router still sees it intact. This
    // matters in two places: (1) the engine being called on an input
    // buffer that starts with `/` (PromptInput already bypasses, but
    // the engine itself stays safe as a defence-in-depth), and (2)
    // a slash command that ends a line in agent prose.
    expect(obfuscate("/help")).toBe("/help");
    expect(obfuscate("/obfuscate")).toBe("/obfuscate");
    expect(obfuscate("see /obfuscate\nthen continue")).toBe(
      "see /obfuscate\nthen continue",
    );
  });

  it("redacts single-segment paths followed by char or space", () => {
    // The screenshot case: "/login, /tenant-selector, /dashboard, ..."
    const out = obfuscate("Routes: /login, /dashboard, /leads here.");
    expect(out).not.toContain("/login");
    expect(out).not.toContain("/dashboard");
    expect(out).not.toContain("/leads");
    expect(out).toMatch(/\[PATH_\d+\]/);
  });

  it("gives distinct route paths distinct placeholders", () => {
    const out = obfuscate("Hit /v1/users then /v1/orders next.");
    expect(out).toContain("[PATH_1]");
    expect(out).toContain("[PATH_2]");
  });

  it("redacts AWS Cognito-style region-prefixed identifiers", () => {
    const out = obfuscate("pool_id: us-east-1_X8rlYugE7");
    expect(out).toContain("[TOKEN_1]");
    expect(out).not.toContain("X8rlYugE7");
  });

  it("redacts opaque alphanumeric IDs with mixed letters and digits", () => {
    const out = obfuscate("client_id: q0vuru56saramn8hbgljgmuva");
    expect(out).toContain("[TOKEN_1]");
    expect(out).not.toContain("q0vuru56saramn8hbgljgmuva");
  });

  it("does not redact long all-letter identifiers", () => {
    const sentence = "function getUserTenantsFromCognitoPool() {}";
    expect(obfuscate(sentence)).toBe(sentence);
  });

  it("aliases bare org references once the host has been seen", () => {
    const first = obfuscate("Visited https://contoso.com for recon.");
    expect(first).toContain("[URL_1]");
    const second = obfuscate(
      "Only the contoso subdomain returned full data, the Contoso corporate tenant.",
    );
    expect(second).not.toContain("contoso");
    expect(second).not.toContain("Contoso");
    expect(second).toMatch(/\[URL_1\]/);
  });

  it("aliases the leading word of a redacted org name", () => {
    const first = obfuscate("Engagement scoped for Acme Corp.");
    expect(first).toContain("[ORG_1]");
    const second = obfuscate("Acme had three open S3 buckets.");
    expect(second).not.toContain("Acme");
    expect(second).toContain("[ORG_1]");
  });

  it("does not alias generic provider labels", () => {
    obfuscate("Bucket lives on s3.amazonaws.com behind cloudfront.net.");
    const out = obfuscate(
      "AWS announced a new Amazon S3 feature today, also Cloudflare.",
    );
    expect(out).toContain("Amazon");
    expect(out).toContain("Cloudflare");
  });

  it("alias replacement can be disabled per call (input round-trip)", () => {
    obfuscate("Reviewed https://contoso.com");
    const withAliases = obfuscate("Contoso is great");
    expect(withAliases).not.toContain("Contoso");
    const withoutAliases = obfuscate("Contoso is great", { aliases: false });
    expect(withoutAliases).toBe("Contoso is great");
  });

  it("redacts apparent company names with corporate suffixes", () => {
    const out = obfuscate("Engagement scoped for Acme Corp and Globex LLC.");
    expect(out).toContain("[ORG_1]");
    expect(out).toContain("[ORG_2]");
    expect(out).not.toContain("Acme");
    expect(out).not.toContain("Globex");
  });

  it("does not redact short capitalised English sentences without org cues", () => {
    const sentence = "The Quick Brown Fox jumped.";
    expect(obfuscate(sentence)).toBe(sentence);
  });

  it("redacts MAC addresses", () => {
    const out = obfuscate("nic 00:1A:2B:3C:4D:5E");
    expect(out).toContain("[MAC_1]");
  });

  it("redacts compressed IPv6 addresses", () => {
    const out = obfuscate("Bound to fe80::1 and 2001:db8::8a2e:370:7334");
    expect(out).toContain("[IPV6_1]");
    expect(out).toContain("[IPV6_2]");
    expect(out).not.toContain("fe80::1");
  });

  it("redacts a credit card number that passes Luhn", () => {
    const out = obfuscate("Card 4111 1111 1111 1111 on file");
    expect(out).toContain("[CARD_1]");
  });

  it("redacts phone numbers", () => {
    const out = obfuscate("Call +1 415 555 0123 today");
    expect(out).toContain("[PHONE_1]");
  });

  it("obfuscateValue assigns category placeholder when enabled", () => {
    expect(obfuscateValue("acme-internal-host", "HOST")).toBe("[HOST_1]");
  });

  it("returns original from obfuscateValue when disabled", () => {
    setObfuscationEnabled(false);
    expect(obfuscateValue("acme-internal-host", "HOST")).toBe(
      "acme-internal-host",
    );
  });

  it("ignores common file extensions when redacting hostnames", () => {
    const out = obfuscate("Edit config.json then run app.py");
    expect(out).toContain("config.json");
    expect(out).toContain("app.py");
  });

  it("deobfuscate restores originals from placeholders", () => {
    const original = "Scan staging-console.pensar.dev and 10.0.0.1";
    const redacted = obfuscate(original);
    expect(redacted).not.toContain("staging-console.pensar.dev");
    expect(redacted).not.toContain("10.0.0.1");
    expect(deobfuscate(redacted)).toBe(original);
  });

  it("deobfuscate handles two-digit indices without prefix collision", () => {
    // Build 11 host entries so we have [HOST_10] and [HOST_1] coexisting.
    for (let i = 1; i <= 11; i++) {
      obfuscate(`host-${i}.example.com`);
    }
    const text = "see [HOST_1] and [HOST_10]";
    const restored = deobfuscate(text);
    expect(restored).toContain("host-1.example.com");
    expect(restored).toContain("host-10.example.com");
    expect(restored).not.toContain("[HOST_1]");
    expect(restored).not.toContain("[HOST_10]");
  });

  it("deobfuscate is a no-op when nothing has been obfuscated", () => {
    resetObfuscation();
    expect(deobfuscate("plain text [HOST_1]")).toBe("plain text [HOST_1]");
  });

  it("deobfuscate works even when obfuscation is disabled", () => {
    obfuscate("acme.example.com");
    setObfuscationEnabled(false);
    expect(deobfuscate("seen at [HOST_1]")).toBe("seen at acme.example.com");
  });
});
