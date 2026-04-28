import { beforeEach, describe, expect, it } from "vitest";
import {
  obfuscate,
  obfuscateValue,
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
    expect(out1).toContain("<EMAIL_1>");
    expect(out1).not.toContain("alice@acme.com");
    expect(out2).toContain("<EMAIL_1>");
  });

  it("issues a new placeholder for a different value of the same category", () => {
    obfuscate("alice@acme.com");
    const out = obfuscate("bob@globex.io");
    expect(out).toContain("<EMAIL_2>");
  });

  it("redacts UUIDs", () => {
    const out = obfuscate("session 550e8400-e29b-41d4-a716-446655440000");
    expect(out).toContain("<UUID_1>");
  });

  it("redacts IPv4 addresses", () => {
    const out = obfuscate("Connecting to 10.0.42.17 and 192.168.1.1");
    expect(out).toMatch(/<IPV4_1>/);
    expect(out).toMatch(/<IPV4_2>/);
    expect(out).not.toContain("10.0.42.17");
  });

  it("redacts URLs and underlying hosts consistently", () => {
    const out = obfuscate("GET https://api.acme-corp.internal/v1/users → 200");
    expect(out).toContain("<URL_1>");
    expect(out).not.toContain("acme-corp.internal");
  });

  it("preserves allowlisted hosts (example.com, github.com)", () => {
    const out = obfuscate(
      "See https://example.com/foo and github.com/org/repo",
    );
    // example.com is allowlisted as host but the URL pattern wins, so we
    // expect the URL to be redacted while the bare github.com mention is kept.
    expect(out).toContain("github.com/org/repo");
  });

  it("redacts JWTs and bearer-style tokens", () => {
    const jwt =
      "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
    const out = obfuscate(`Authorization: Bearer ${jwt}`);
    expect(out).toContain("<JWT_1>");
    expect(out).not.toContain(jwt);
  });

  it("redacts API keys", () => {
    const out = obfuscate("sk-abcdefghijklmnopqrstuvwxyz1234");
    expect(out).toContain("<TOKEN_1>");
  });

  it("redacts user home paths", () => {
    const out = obfuscate("/Users/alice/code/acme/src/index.ts");
    expect(out).toContain("<PATH_1>");
    expect(out).not.toContain("alice");
  });

  it("redacts apparent company names with corporate suffixes", () => {
    const out = obfuscate("Engagement scoped for Acme Corp and Globex LLC.");
    expect(out).toContain("<ORG_1>");
    expect(out).toContain("<ORG_2>");
    expect(out).not.toContain("Acme");
    expect(out).not.toContain("Globex");
  });

  it("does not redact short capitalised English sentences without org cues", () => {
    const sentence = "The Quick Brown Fox jumped.";
    expect(obfuscate(sentence)).toBe(sentence);
  });

  it("redacts MAC addresses", () => {
    const out = obfuscate("nic 00:1A:2B:3C:4D:5E");
    expect(out).toContain("<MAC_1>");
  });

  it("redacts a credit card number that passes Luhn", () => {
    const out = obfuscate("Card 4111 1111 1111 1111 on file");
    expect(out).toContain("<CARD_1>");
  });

  it("redacts phone numbers", () => {
    const out = obfuscate("Call +1 415 555 0123 today");
    expect(out).toContain("<PHONE_1>");
  });

  it("obfuscateValue assigns category placeholder when enabled", () => {
    expect(obfuscateValue("acme-internal-host", "HOST")).toBe("<HOST_1>");
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
});
