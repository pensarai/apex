import { describe, expect, it } from "vitest";
import {
  getAllowedHosts,
  isHostAllowed,
  extractHostname,
  assertUrlInScope,
  assertCommandInScope,
  extractHostsFromCommand,
  ScopeViolationError,
} from "./scopeGuard";
import type { ToolContext } from "./types";
import type { SessionInfo } from "../../../session";

function makeCtx(overrides: Partial<ToolContext> = {}): ToolContext {
  return {
    session: {
      id: "ses_test",
      version: "1.0.0",
      targets: [],
      time: { created: Date.now(), updated: Date.now() },
      rootPath: "/tmp/test",
      logsPath: "/tmp/test/logs",
      findingsPath: "/tmp/test/findings",
      scratchpadPath: "/tmp/test/scratchpad",
      pocsPath: "/tmp/test/pocs",
    } as SessionInfo,
    agentCwd: "/tmp/test",
    ...overrides,
  };
}

// ---------------------------------------------------------------------------
// getAllowedHosts
// ---------------------------------------------------------------------------

describe("getAllowedHosts", () => {
  it("returns empty when no target is set", () => {
    expect(getAllowedHosts(makeCtx())).toEqual([]);
  });

  it("extracts hostname from ctx.target", () => {
    const hosts = getAllowedHosts(makeCtx({ target: "https://example.com" }));
    expect(hosts).toContain("example.com");
  });

  it("extracts from session.targets", () => {
    const ctx = makeCtx();
    ctx.session.targets = ["https://api.example.com", "https://other.dev"];
    const hosts = getAllowedHosts(ctx);
    expect(hosts).toContain("api.example.com");
    expect(hosts).toContain("other.dev");
  });

  it("extracts from scopeConstraints.allowedHosts", () => {
    const ctx = makeCtx();
    ctx.session.config = {
      scopeConstraints: { allowedHosts: ["custom.host.io"] },
    };
    const hosts = getAllowedHosts(ctx);
    expect(hosts).toContain("custom.host.io");
  });

  it("deduplicates across sources", () => {
    const ctx = makeCtx({ target: "https://example.com" });
    ctx.session.targets = ["https://example.com"];
    ctx.session.config = {
      scopeConstraints: { allowedHosts: ["example.com"] },
    };
    const hosts = getAllowedHosts(ctx);
    expect(hosts).toEqual(["example.com"]);
  });

  it("lowercases all hostnames", () => {
    const ctx = makeCtx({ target: "https://EXAMPLE.COM" });
    ctx.session.config = {
      scopeConstraints: { allowedHosts: ["OTHER.Dev"] },
    };
    const hosts = getAllowedHosts(ctx);
    expect(hosts).toContain("example.com");
    expect(hosts).toContain("other.dev");
  });
});

// ---------------------------------------------------------------------------
// isHostAllowed
// ---------------------------------------------------------------------------

describe("isHostAllowed", () => {
  it("allows everything when allowedHosts is empty", () => {
    expect(isHostAllowed("anything.com", [])).toBe(true);
  });

  it("matches exact hostname", () => {
    expect(isHostAllowed("example.com", ["example.com"])).toBe(true);
  });

  it("matches subdomain of allowed host", () => {
    expect(isHostAllowed("api.example.com", ["example.com"])).toBe(true);
    expect(isHostAllowed("deep.sub.example.com", ["example.com"])).toBe(true);
  });

  it("rejects unrelated domains", () => {
    expect(isHostAllowed("evil.com", ["example.com"])).toBe(false);
  });

  it("rejects suffix-similar but non-subdomain hosts", () => {
    expect(isHostAllowed("notexample.com", ["example.com"])).toBe(false);
  });

  it("is case-insensitive", () => {
    expect(isHostAllowed("API.EXAMPLE.COM", ["example.com"])).toBe(true);
  });

  it("is case-insensitive on allowedHosts side", () => {
    expect(isHostAllowed("api.example.com", ["EXAMPLE.COM"])).toBe(true);
    expect(isHostAllowed("example.com", ["Example.Com"])).toBe(true);
  });

  it("matches IP addresses exactly", () => {
    expect(isHostAllowed("192.168.1.1", ["192.168.1.1"])).toBe(true);
    expect(isHostAllowed("192.168.1.2", ["192.168.1.1"])).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// extractHostname
// ---------------------------------------------------------------------------

describe("extractHostname", () => {
  it("extracts hostname from https URL", () => {
    expect(extractHostname("https://example.com/path")).toBe("example.com");
  });

  it("extracts hostname from http URL with port", () => {
    expect(extractHostname("http://api.example.com:8080/test")).toBe(
      "api.example.com",
    );
  });

  it("handles bare hostname (no scheme)", () => {
    expect(extractHostname("example.com")).toBe("example.com");
  });

  it("returns null for empty/invalid input", () => {
    expect(extractHostname("")).toBe(null);
    expect(extractHostname("   ")).toBe(null);
  });
});

// ---------------------------------------------------------------------------
// assertUrlInScope
// ---------------------------------------------------------------------------

describe("assertUrlInScope", () => {
  it("is a no-op when no scope is configured", () => {
    expect(() =>
      assertUrlInScope("https://anywhere.com", makeCtx()),
    ).not.toThrow();
  });

  it("allows in-scope URLs", () => {
    const ctx = makeCtx({ target: "https://example.com" });
    expect(() =>
      assertUrlInScope("https://example.com/login", ctx),
    ).not.toThrow();
    expect(() =>
      assertUrlInScope("https://api.example.com/v1", ctx),
    ).not.toThrow();
  });

  it("blocks out-of-scope URLs", () => {
    const ctx = makeCtx({ target: "https://example.com" });
    expect(() => assertUrlInScope("https://evil.com", ctx)).toThrow(
      ScopeViolationError,
    );
  });

  it("includes the hostname and allowed list in the error", () => {
    const ctx = makeCtx({ target: "https://example.com" });
    try {
      assertUrlInScope("https://evil.com/attack", ctx);
      expect.fail("should have thrown");
    } catch (e) {
      expect(e).toBeInstanceOf(ScopeViolationError);
      expect((e as ScopeViolationError).hostname).toBe("evil.com");
      expect((e as ScopeViolationError).allowedHosts).toContain("example.com");
    }
  });

  it("handles bare strings by parsing as hostname", () => {
    const ctx = makeCtx({ target: "https://example.com" });
    // parseTargetUrl adds https:// prefix, so "example.com" parses fine
    expect(() => assertUrlInScope("example.com/path", ctx)).not.toThrow();
    // Out-of-scope bare hostname still blocked
    expect(() => assertUrlInScope("evil.com", ctx)).toThrow(
      ScopeViolationError,
    );
  });

  it("blocks unparseable URLs when scope is active (fail-closed)", () => {
    const ctx = makeCtx({ target: "https://example.com" });
    expect(() => assertUrlInScope("", ctx)).toThrow(ScopeViolationError);
    expect(() => assertUrlInScope("   ", ctx)).toThrow(ScopeViolationError);
  });

  it("allows unparseable URLs when no scope is configured (no-op)", () => {
    expect(() => assertUrlInScope("", makeCtx())).not.toThrow();
    expect(() => assertUrlInScope("   ", makeCtx())).not.toThrow();
  });
});

// ---------------------------------------------------------------------------
// extractHostsFromCommand
// ---------------------------------------------------------------------------

describe("extractHostsFromCommand", () => {
  it("extracts http URLs from commands", () => {
    const hosts = extractHostsFromCommand(
      'curl -i https://example.com/test -H "Accept: text/html"',
    );
    expect(hosts).toContain("example.com");
  });

  it("extracts multiple URLs", () => {
    const hosts = extractHostsFromCommand(
      "curl https://a.com && wget http://b.com/file",
    );
    expect(hosts).toContain("a.com");
    expect(hosts).toContain("b.com");
  });

  it("extracts bare hostname after nmap", () => {
    const hosts = extractHostsFromCommand("nmap -sV -sC example.com");
    expect(hosts).toContain("example.com");
  });

  it("extracts bare hostname after nmap with -p flag", () => {
    const hosts = extractHostsFromCommand("nmap -p 443 target.com");
    expect(hosts).toContain("target.com");
  });

  it("extracts IP addresses from commands", () => {
    const hosts = extractHostsFromCommand("nmap -sV 192.168.1.1");
    expect(hosts).toContain("192.168.1.1");
  });

  it("extracts host from dig command", () => {
    const hosts = extractHostsFromCommand("dig example.com");
    expect(hosts).toContain("example.com");
  });

  it("extracts host from openssl s_client connect", () => {
    const hosts = extractHostsFromCommand(
      "openssl s_client -connect example.com:443",
    );
    expect(hosts).toContain("example.com");
  });

  it("extracts host from gobuster", () => {
    const hosts = extractHostsFromCommand(
      "gobuster dir -u https://example.com -w /usr/share/wordlists/common.txt",
    );
    expect(hosts).toContain("example.com");
  });

  it("handles piped commands", () => {
    const hosts = extractHostsFromCommand(
      "curl https://example.com | grep admin",
    );
    expect(hosts).toContain("example.com");
  });

  it("returns empty array for commands without network targets", () => {
    const hosts = extractHostsFromCommand("ls -la /tmp");
    expect(hosts).toEqual([]);
  });

  it("ignores flags (tokens starting with -)", () => {
    const hosts = extractHostsFromCommand("nmap -sV --script vuln example.com");
    expect(hosts).not.toContain("--script");
    expect(hosts).toContain("example.com");
  });

  it("handles commands with sudo and timeout prefix", () => {
    const hosts = extractHostsFromCommand(
      "sudo timeout 30 nmap -p- target.com",
    );
    expect(hosts).toContain("target.com");
  });

  it("extracts host with port from bare hostname", () => {
    const hosts = extractHostsFromCommand("nc target.com:8080");
    expect(hosts).toContain("target.com");
  });

  it("does not treat output filenames as hostnames (nmap -oN)", () => {
    const hosts = extractHostsFromCommand("nmap -oN output.txt target.com");
    expect(hosts).toContain("target.com");
    expect(hosts).not.toContain("output.txt");
  });

  it("does not treat output filenames as hostnames (nmap -oX)", () => {
    const hosts = extractHostsFromCommand("nmap -sV -oX report.xml target.com");
    expect(hosts).toContain("target.com");
    expect(hosts).not.toContain("report.xml");
  });

  it("does not treat output filenames as hostnames (curl -o)", () => {
    const hosts = extractHostsFromCommand(
      "curl -o results.html https://target.com",
    );
    expect(hosts).toContain("target.com");
    expect(hosts).not.toContain("results.html");
  });

  it("does not treat script names as hostnames (nmap --script)", () => {
    const hosts = extractHostsFromCommand(
      "nmap --script ssl-enum-ciphers.nse -p 443 target.com",
    );
    expect(hosts).toContain("target.com");
    expect(hosts).not.toContain("ssl-enum-ciphers.nse");
  });

  it("does not treat wordlist paths as hostnames (gobuster -w)", () => {
    const hosts = extractHostsFromCommand(
      "gobuster dir -u https://target.com -w wordlist.txt",
    );
    expect(hosts).toContain("target.com");
    expect(hosts).not.toContain("wordlist.txt");
  });

  it("handles --flag=value without skipping the next token", () => {
    const hosts = extractHostsFromCommand("nmap --script=vuln target.com");
    expect(hosts).toContain("target.com");
  });
});

// ---------------------------------------------------------------------------
// assertCommandInScope
// ---------------------------------------------------------------------------

describe("assertCommandInScope", () => {
  it("is a no-op when no scope is configured", () => {
    expect(() =>
      assertCommandInScope("curl https://anywhere.com", makeCtx()),
    ).not.toThrow();
  });

  it("allows in-scope commands", () => {
    const ctx = makeCtx({ target: "https://example.com" });
    expect(() =>
      assertCommandInScope("nmap -sV example.com", ctx),
    ).not.toThrow();
    expect(() =>
      assertCommandInScope("curl https://api.example.com/v1", ctx),
    ).not.toThrow();
  });

  it("blocks out-of-scope commands", () => {
    const ctx = makeCtx({ target: "https://example.com" });
    expect(() => assertCommandInScope("nmap -sV evil.com", ctx)).toThrow(
      ScopeViolationError,
    );
  });

  it("blocks mixed-scope commands (one host out of scope)", () => {
    const ctx = makeCtx({ target: "https://example.com" });
    expect(() =>
      assertCommandInScope(
        "curl https://example.com/ok && curl https://evil.com/bad",
        ctx,
      ),
    ).toThrow(ScopeViolationError);
  });

  it("allows commands with no network targets", () => {
    const ctx = makeCtx({ target: "https://example.com" });
    expect(() => assertCommandInScope("cat /etc/passwd", ctx)).not.toThrow();
    expect(() =>
      assertCommandInScope("echo hello && ls -la", ctx),
    ).not.toThrow();
  });

  it("allows local file operations", () => {
    const ctx = makeCtx({ target: "https://example.com" });
    expect(() =>
      assertCommandInScope("grep -r 'password' /var/log", ctx),
    ).not.toThrow();
  });
});
