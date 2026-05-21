/**
 * Contract tests for the custom-headers subsystem.
 *
 * These pin the behaviours the rest of the codebase relies on: the
 * resolver's layering and scope check, the blessed `targetFetch`,
 * shell-command injection, history redaction, and the parser's error
 * contract.
 *
 * If you break one of these tests intentionally, also update the
 * corresponding INV-* doc in the resolver / parse files.
 */

import { mkdtempSync, rmSync } from "fs";
import { writeFile } from "fs/promises";
import { tmpdir } from "os";
import { join } from "path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { redactSecretsInHistoryEntry } from "../history";
import {
  formatParseError,
  parseHeaderLine,
  parseHeadersFromFile,
} from "./parse";
import {
  applyHeadersToShellCommand,
  type ResolverSession,
  resolveEffectiveHeaders,
  targetFetch,
} from "./targetHeaders";
import { isSensitiveHeaderName, renderHeaderValue } from "./types";

function makeSession(
  overrides: Partial<ResolverSession> = {},
): ResolverSession {
  return {
    targets: ["https://example.com"],
    config: { headers: { "X-Test": "1" } },
    ...overrides,
  };
}

// ---------------------------------------------------------------------------
// parseHeaderLine — total parser contract
// ---------------------------------------------------------------------------

describe("parseHeaderLine", () => {
  it("accepts Name: Value", () => {
    const r = parseHeaderLine("X-API-Key: abc");
    expect(r.ok).toBe(true);
    if (r.ok) {
      expect(r.value.name).toBe("X-API-Key");
      expect(r.value.value).toBe("abc");
    }
  });

  it("strips a leading -H curl prefix and surrounding quotes", () => {
    const r = parseHeaderLine(`-H "Authorization: Bearer xyz"`);
    expect(r.ok).toBe(true);
    if (r.ok) {
      expect(r.value.name).toBe("Authorization");
      expect(r.value.value).toBe("Bearer xyz");
    }
  });

  it("rejects a missing colon", () => {
    const r = parseHeaderLine("X-API-Key abc");
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.error.kind).toBe("missing-colon");
  });

  it("rejects whitespace in the name", () => {
    const r = parseHeaderLine("X API: abc");
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.error.kind).toBe("name-has-whitespace");
  });

  it("rejects CRLF in the value (injection guard)", () => {
    const r = parseHeaderLine("X: a\r\nInjected: 1");
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.error.kind).toBe("crlf-in-value");
  });

  it("never throws — totality", () => {
    const inputs = ["", ":", "a:", ":b", "no colon", "x\nx: y"];
    for (const i of inputs) {
      expect(() => parseHeaderLine(i)).not.toThrow();
    }
  });

  it("formatParseError never includes the raw value", () => {
    const r = parseHeaderLine("Authorization Bearer secret-token-abc-123");
    expect(r.ok).toBe(false);
    if (!r.ok) {
      const formatted = formatParseError(r.error);
      expect(formatted).not.toContain("secret-token-abc-123");
    }
  });
});

// ---------------------------------------------------------------------------
// parseHeadersFromFile — JSON and Name:Value branches
// ---------------------------------------------------------------------------

describe("parseHeadersFromFile", () => {
  let tmp: string;

  beforeEach(() => {
    tmp = mkdtempSync(join(tmpdir(), "headers-contract-"));
  });
  afterEach(() => {
    rmSync(tmp, { recursive: true, force: true });
  });

  it("parses JSON object", async () => {
    const file = join(tmp, "h.json");
    await writeFile(file, JSON.stringify({ "X-API-Key": "abc" }));
    const r = await parseHeadersFromFile(file);
    expect(r.ok).toBe(true);
    if (r.ok) expect(r.value[0].name).toBe("X-API-Key");
  });

  it("parses Name: Value lines with # comments", async () => {
    const file = join(tmp, "h.txt");
    await writeFile(file, "# a comment\nX-API-Key: abc\nUser-Agent: test\n");
    const r = await parseHeadersFromFile(file);
    expect(r.ok).toBe(true);
    if (r.ok) expect(r.value).toHaveLength(2);
  });

  it("returns file-read-failed for a missing file", async () => {
    const r = await parseHeadersFromFile(join(tmp, "does-not-exist"));
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.error[0].kind).toBe("file-read-failed");
  });

  it("rejects JSON with non-string values", async () => {
    const file = join(tmp, "bad.json");
    await writeFile(file, `{"X-API-Key": 42}`);
    const r = await parseHeadersFromFile(file);
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.error[0].kind).toBe("invalid-json");
  });
});

// ---------------------------------------------------------------------------
// resolveEffectiveHeaders — layering + scope
// ---------------------------------------------------------------------------

describe("resolveEffectiveHeaders", () => {
  it("returns empty for out-of-scope URLs (INV-scope-bound)", () => {
    const s = makeSession({
      targets: ["https://example.com"],
      config: { headers: { Authorization: "Bearer x" } },
    });
    const r = resolveEffectiveHeaders(s, "https://evil.com/path");
    expect(r).toEqual({});
  });

  it("merges session + credential + request layers", () => {
    const s = makeSession({
      config: { headers: { "X-Session": "1", "X-Both": "from-session" } },
      credentialManager: {
        listCredentialsWithHeaders: () => [
          {
            tokens: { customHeaders: { "X-Cred": "1", "X-Both": "from-cred" } },
          },
        ],
      },
    });
    const rec = resolveEffectiveHeaders(s, "https://example.com/api", {
      "X-Request": "1",
      "X-Both": "from-request",
    });
    expect(rec["X-Session"]).toBe("1");
    expect(rec["X-Cred"]).toBe("1");
    expect(rec["X-Request"]).toBe("1");
    // INV-precedence-deterministic: request beats credential beats session
    expect(rec["X-Both"]).toBe("from-request");
  });

  it("preserves first-seen casing on case-insensitive collision", () => {
    const s = makeSession({
      config: { headers: { "X-Foo": "lower" } },
    });
    const rec = resolveEffectiveHeaders(s, "https://example.com/api", {
      "x-foo": "upper",
    });
    expect(rec["X-Foo"]).toBe("upper");
    expect(rec["x-foo"]).toBeUndefined();
  });

  it("respects scopeConstraints.allowedHosts when no target is set", () => {
    const s = makeSession({
      targets: [],
      config: {
        headers: { "X-Test": "1" },
        scopeConstraints: { allowedHosts: ["api.internal"] },
      },
    });
    expect(resolveEffectiveHeaders(s, "https://api.internal/x")).toEqual({
      "X-Test": "1",
    });
    expect(resolveEffectiveHeaders(s, "https://example.com/x")).toEqual({});
  });
});

// ---------------------------------------------------------------------------
// targetFetch — proves headers actually hit the network call
// ---------------------------------------------------------------------------

describe("targetFetch", () => {
  it("merges resolved headers into the fetch call", async () => {
    const session = makeSession({
      config: { headers: { "X-API-Key": "abc" } },
    });
    const spy = vi
      .spyOn(globalThis, "fetch")
      .mockResolvedValue(new Response("ok"));

    await targetFetch(session, "https://example.com/x");

    expect(spy).toHaveBeenCalledTimes(1);
    const init = spy.mock.calls[0][1] as RequestInit;
    expect(init.headers).toMatchObject({ "X-API-Key": "abc" });

    spy.mockRestore();
  });

  it("does not leak session headers to out-of-scope hosts", async () => {
    const session = makeSession({
      config: { headers: { Authorization: "Bearer secret" } },
    });
    const spy = vi
      .spyOn(globalThis, "fetch")
      .mockResolvedValue(new Response("ok"));

    await targetFetch(session, "https://attacker.example.net/leak");

    const init = spy.mock.calls[0][1] as RequestInit;
    expect(init.headers).toEqual({});

    spy.mockRestore();
  });

  it("preserves caller overrides on out-of-scope URLs", async () => {
    // INV-scope-bound applies only to the resolver-injected layers
    // (session/global/credential). Caller-explicit overrides like
    // `Accept` for research URLs must pass through.
    const session = makeSession({
      config: { headers: { Authorization: "Bearer secret" } },
    });
    const spy = vi
      .spyOn(globalThis, "fetch")
      .mockResolvedValue(new Response("ok"));

    await targetFetch(session, "https://cve.example.org/writeup", {
      headers: { Accept: "text/html", "Accept-Language": "en-US" },
    });

    const init = spy.mock.calls[0][1] as RequestInit;
    expect(init.headers).toEqual({
      Accept: "text/html",
      "Accept-Language": "en-US",
    });

    spy.mockRestore();
  });
});

// ---------------------------------------------------------------------------
// applyHeadersToShellCommand — injection + fail-closed
// ---------------------------------------------------------------------------

describe("applyHeadersToShellCommand", () => {
  it("injects -H flags into curl commands", () => {
    const session = makeSession({
      config: { headers: { "X-API-Key": "abc" } },
    });
    const r = applyHeadersToShellCommand(
      "curl https://example.com/api",
      session,
      ["example.com"],
    );
    expect(r.status).toBe("injected");
    expect(r.tool).toBe("curl");
    expect(r.command).toContain(`-H "X-API-Key: abc"`);
  });

  it("returns unknown-tool when the binary is not in the registry (INV-shell-injection)", () => {
    const session = makeSession({
      config: { headers: { "X-API-Key": "abc" } },
    });
    const r = applyHeadersToShellCommand(
      "my-custom-tool --target https://example.com",
      session,
      ["example.com"],
    );
    expect(r.status).toBe("unknown-tool");
  });

  it("returns no-headers for known non-HTTP tools like nmap", () => {
    const session = makeSession({
      config: { headers: { "User-Agent": "pensar-apex" } },
    });
    const r = applyHeadersToShellCommand(
      "nmap -sV example.com",
      session,
      ["example.com"],
    );
    expect(r.status).toBe("no-headers");
    expect(r.command).toBe("nmap -sV example.com");
  });

  it("returns no-headers for non-HTTP tools behind sudo/timeout wrappers", () => {
    const session = makeSession({
      config: { headers: { "User-Agent": "pensar-apex" } },
    });
    const r = applyHeadersToShellCommand(
      "sudo timeout 60 nmap -p- example.com",
      session,
      ["example.com"],
    );
    expect(r.status).toBe("no-headers");
  });

  it("returns no-headers when no in-scope host is present on the command", () => {
    const session = makeSession({
      config: { headers: { "X-API-Key": "abc" } },
    });
    const r = applyHeadersToShellCommand(
      "curl https://other.example.net/",
      session,
      ["other.example.net"],
    );
    expect(r.status).toBe("no-headers");
  });

  it("skips headers already present on the command", () => {
    const session = makeSession({
      config: { headers: { "X-API-Key": "from-session", "X-Other": "1" } },
    });
    const r = applyHeadersToShellCommand(
      `curl -H "X-API-Key: explicit" https://example.com/`,
      session,
      ["example.com"],
    );
    expect(r.status).toBe("injected");
    expect(r.command).toContain(`X-API-Key: explicit`);
    expect(r.command).not.toContain(`X-API-Key: from-session`);
    expect(r.command).toContain(`X-Other: 1`);
  });

  it("shell-escapes values containing quotes, dollar, and backticks", () => {
    const session = makeSession({
      config: {
        headers: { "X-Risky": 'val with "quotes" and $VAR and `cmd`' },
      },
    });
    const r = applyHeadersToShellCommand("curl https://example.com/", session, [
      "example.com",
    ]);
    expect(r.status).toBe("injected");
    // Every shell-special character must be backslash-escaped inside
    // the double-quoted -H argument.
    expect(r.command).toContain(`\\"quotes\\"`);
    expect(r.command).toContain(`\\$VAR`);
    expect(r.command).toContain("\\`cmd\\`");
  });
});

// ---------------------------------------------------------------------------
// Redaction of header-bearing history entries
// ---------------------------------------------------------------------------

describe("redactSecretsInHistoryEntry", () => {
  it("masks the value of /headers add", () => {
    const r = redactSecretsInHistoryEntry(
      "/headers add Authorization: Bearer super-secret",
    );
    expect(r).toBe("/headers add Authorization: <redacted>");
  });

  it("masks the value of /headers set", () => {
    const r = redactSecretsInHistoryEntry("/headers set X-API-Key: abc123");
    expect(r).toBe("/headers set X-API-Key: <redacted>");
  });

  it("masks --header CLI flag payload", () => {
    const r = redactSecretsInHistoryEntry(
      `pensar pentest --target https://example.com --header "Authorization: Bearer xyz"`,
    );
    expect(r).not.toContain("xyz");
    expect(r).toContain("Authorization: <redacted>");
  });

  it("masks multi-word quoted --header values (Bearer <token>)", () => {
    // Regression: a previous regex stopped at the first whitespace in
    // the value, leaving the token after "Bearer " on disk.
    const r = redactSecretsInHistoryEntry(
      `pensar pentest --header "Authorization: Bearer super-secret-token"`,
    );
    expect(r).not.toContain("super-secret-token");
    expect(r).toContain(`"Authorization: <redacted>"`);
  });

  it("leaves unrelated commands untouched", () => {
    const input = "/skills list";
    expect(redactSecretsInHistoryEntry(input)).toBe(input);
  });
});

// ---------------------------------------------------------------------------
// Display sensitivity — masking by default
// ---------------------------------------------------------------------------

describe("renderHeaderValue", () => {
  it("masks sensitive headers when showSecrets is false", () => {
    const v = renderHeaderValue("Authorization", "Bearer secret", false);
    expect(v).not.toContain("secret");
  });

  it("reveals sensitive headers when showSecrets is true", () => {
    const v = renderHeaderValue("Authorization", "Bearer secret", true);
    expect(v).toContain("secret");
  });

  it("does not mask non-sensitive headers", () => {
    const v = renderHeaderValue("X-Request-Id", "abc-123", false);
    expect(v).toBe("abc-123");
  });

  it("isSensitiveHeaderName covers the common cases", () => {
    expect(isSensitiveHeaderName("Authorization")).toBe(true);
    expect(isSensitiveHeaderName("Cookie")).toBe(true);
    expect(isSensitiveHeaderName("X-API-Key")).toBe(true);
    expect(isSensitiveHeaderName("Set-Cookie")).toBe(true);
    expect(isSensitiveHeaderName("User-Agent")).toBe(false);
  });
});
