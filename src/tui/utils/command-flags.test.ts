import { describe, expect, it, beforeEach, afterEach } from "vitest";
import { mkdtempSync, writeFileSync, rmSync } from "fs";
import { join } from "path";
import { tmpdir } from "os";
import {
  resolveFlagValue,
  resolveThreatModelPrompt,
  buildOperatorSessionConfig,
  buildSwarmSessionConfig,
  parseWebFlags,
} from "./command-flags";

// ---------------------------------------------------------------------------
// parseWebFlags — swarm scope
// ---------------------------------------------------------------------------

describe("parseWebFlags", () => {
  it("auto-populates the target host and port for skipped-wizard swarm runs", () => {
    const flags = parseWebFlags([
      "--target",
      "https://example.com:8080",
      "--swarm",
    ]);

    expect(flags.hosts).toEqual(["example.com"]);
    expect(flags.ports).toEqual([8080]);

    const params = buildSwarmSessionConfig(flags);

    expect(params.config.scopeConstraints).toMatchObject({
      allowedHosts: ["example.com"],
      allowedPorts: [8080],
    });
  });

  it("merges target-derived scope with explicit hosts and ports", () => {
    const flags = parseWebFlags([
      "--target",
      "https://example.com:8080",
      "--swarm",
      "--hosts",
      "api.example.com",
      "--ports",
      "8443",
    ]);

    expect(flags.hosts).toEqual(["api.example.com", "example.com"]);
    expect(flags.ports).toEqual([8443, 8080]);
  });

  it("parses Burp Suite integration flags", () => {
    const flags = parseWebFlags([
      "--target",
      "https://example.com",
      "--burp-proxy",
      "http://127.0.0.1:8081",
      "--burp-mcp-url",
      "http://127.0.0.1:9877",
      "--burp-mcp-proxy-jar",
      "/tmp/mcp-proxy-all.jar",
      "--burp-transport",
      "stdio",
      "--burp-timeout-ms",
      "30000",
      "--burp-allow-config-mutation",
      "--burp-insecure-tls",
    ]);

    expect(flags.burp).toBe(true);
    expect(flags.burpProxy).toBe("http://127.0.0.1:8081");
    expect(flags.burpMcpUrl).toBe("http://127.0.0.1:9877");
    expect(flags.burpMcpProxyJar).toBe("/tmp/mcp-proxy-all.jar");
    expect(flags.burpTransport).toBe("stdio");
    expect(flags.burpTimeoutMs).toBe(30000);
    expect(flags.burpAllowConfigMutation).toBe(true);
    expect(flags.burpInsecureTls).toBe(true);
  });

  it("maps Burp Suite flags into session config", () => {
    const flags = parseWebFlags([
      "--target",
      "https://example.com",
      "--burp",
      "--burp-mcp-proxy-jar",
      "/tmp/mcp-proxy-all.jar",
    ]);

    const params = buildOperatorSessionConfig(flags);

    expect(params.config.burpSuite).toEqual({
      enabled: true,
      mcpProxyArgs: [
        "-jar",
        "/tmp/mcp-proxy-all.jar",
        "--sse-url",
        "http://127.0.0.1:9876/sse",
      ],
    });
  });
});

// ---------------------------------------------------------------------------
// resolveFlagValue
// ---------------------------------------------------------------------------

describe("resolveFlagValue", () => {
  let tempDir: string;

  beforeEach(() => {
    tempDir = mkdtempSync(join(tmpdir(), "apex-test-"));
  });

  afterEach(() => {
    rmSync(tempDir, { recursive: true, force: true });
  });

  it("returns inline text as-is when no @ prefix", () => {
    expect(resolveFlagValue("hello world")).toBe("hello world");
  });

  it("returns empty string as-is", () => {
    expect(resolveFlagValue("")).toBe("");
  });

  it("returns text containing @ in the middle as-is", () => {
    expect(resolveFlagValue("user@example.com")).toBe("user@example.com");
  });

  it("reads file contents when value starts with @", () => {
    const filePath = join(tempDir, "prompt.txt");
    writeFileSync(filePath, "file content here");

    const result = resolveFlagValue(`@${filePath}`);
    expect(result).toBe("file content here");
  });

  it("reads multiline file contents", () => {
    const filePath = join(tempDir, "multi.txt");
    const content = "line 1\nline 2\nline 3\n";
    writeFileSync(filePath, content);

    const result = resolveFlagValue(`@${filePath}`);
    expect(result).toBe(content);
  });

  it("resolves relative @ paths against cwd", () => {
    const filePath = join(tempDir, "relative.txt");
    writeFileSync(filePath, "relative content");

    // Temporarily change cwd to tempDir
    const originalCwd = process.cwd();
    process.chdir(tempDir);
    try {
      const result = resolveFlagValue("@relative.txt");
      expect(result).toBe("relative content");
    } finally {
      process.chdir(originalCwd);
    }
  });

  it("handles absolute @ paths", () => {
    const filePath = join(tempDir, "absolute.txt");
    writeFileSync(filePath, "absolute content");

    const result = resolveFlagValue(`@${filePath}`);
    expect(result).toBe("absolute content");
  });

  it("throws when @ references a nonexistent file", () => {
    expect(() => resolveFlagValue("@/nonexistent/file.txt")).toThrow();
  });
});

// ---------------------------------------------------------------------------
// resolveThreatModelPrompt
// ---------------------------------------------------------------------------

describe("resolveThreatModelPrompt", () => {
  let tempDir: string;

  beforeEach(() => {
    tempDir = mkdtempSync(join(tmpdir(), "apex-test-"));
  });

  afterEach(() => {
    rmSync(tempDir, { recursive: true, force: true });
  });

  it("wraps inline text with preamble and threat-model tags", () => {
    const result = resolveThreatModelPrompt("My threat model content");

    expect(result).toContain("## Threat Model");
    expect(result).toContain("<threat-model>");
    expect(result).toContain("My threat model content");
    expect(result).toContain("</threat-model>");
  });

  it("contains key guidance phrases in the preamble", () => {
    const result = resolveThreatModelPrompt("content");

    expect(result).toContain("Prioritize attack paths by severity");
    expect(result).toContain("Use the pentest guidance");
    expect(result).toContain("Check existing controls");
    expect(result).toContain("Verify control gaps");
    expect(result).toContain("Reference attacker profiles");
    expect(result).toContain("Don't limit yourself");
  });

  it("wraps @file content with preamble", () => {
    const filePath = join(tempDir, "threat-model.md");
    writeFileSync(filePath, "SQL injection risk on /api/users");

    const result = resolveThreatModelPrompt(`@${filePath}`);

    expect(result).toContain("## Threat Model");
    expect(result).toContain("<threat-model>");
    expect(result).toContain("SQL injection risk on /api/users");
    expect(result).toContain("</threat-model>");
  });

  it("places the content inside threat-model tags at the end", () => {
    const result = resolveThreatModelPrompt("my content");

    // Content should appear between the tags
    const tagStart = result.indexOf("<threat-model>");
    const tagEnd = result.indexOf("</threat-model>");
    const contentIdx = result.indexOf("my content");

    expect(tagStart).toBeGreaterThan(-1);
    expect(tagEnd).toBeGreaterThan(tagStart);
    expect(contentIdx).toBeGreaterThan(tagStart);
    expect(contentIdx).toBeLessThan(tagEnd);
  });
});

// ---------------------------------------------------------------------------
// parseWebFlags — prompt and threatModel flags
// ---------------------------------------------------------------------------

describe("parseWebFlags prompt/threatModel", () => {
  let tempDir: string;

  beforeEach(() => {
    tempDir = mkdtempSync(join(tmpdir(), "apex-test-"));
  });

  afterEach(() => {
    rmSync(tempDir, { recursive: true, force: true });
  });

  it("parses --prompt with inline text", () => {
    const flags = parseWebFlags(["--prompt", "Focus on auth bypass"]);
    expect(flags.prompt).toBe("Focus on auth bypass");
  });

  it("parses --prompt with =value syntax", () => {
    const flags = parseWebFlags(["--prompt=Focus on SSRF"]);
    expect(flags.prompt).toBe("Focus on SSRF");
  });

  it("parses --prompt with @file reference", () => {
    const filePath = join(tempDir, "custom-prompt.txt");
    writeFileSync(filePath, "Test all API endpoints");

    const flags = parseWebFlags(["--prompt", `@${filePath}`]);
    expect(flags.prompt).toBe("Test all API endpoints");
  });

  it("parses --threat-model with inline text", () => {
    const flags = parseWebFlags(["--threat-model", "XSS on login"]);

    expect(flags.threatModel).toContain("## Threat Model");
    expect(flags.threatModel).toContain("<threat-model>");
    expect(flags.threatModel).toContain("XSS on login");
    expect(flags.threatModel).toContain("</threat-model>");
  });

  it("parses --threat-model with @file reference", () => {
    const filePath = join(tempDir, "tm.md");
    writeFileSync(filePath, "IDOR on user profiles");

    const flags = parseWebFlags(["--threat-model", `@${filePath}`]);

    expect(flags.threatModel).toContain("## Threat Model");
    expect(flags.threatModel).toContain("IDOR on user profiles");
  });

  it("parses both --prompt and --threat-model together", () => {
    const flags = parseWebFlags([
      "--target",
      "http://example.com",
      "--prompt",
      "Be thorough",
      "--threat-model",
      "SQL injection risk",
    ]);

    expect(flags.target).toBe("http://example.com");
    expect(flags.prompt).toBe("Be thorough");
    expect(flags.threatModel).toContain("SQL injection risk");
    expect(flags.threatModel).toContain("## Threat Model");
  });

  it("does not set prompt or threatModel when flags are absent", () => {
    const flags = parseWebFlags(["--target", "http://example.com"]);
    expect(flags.prompt).toBeUndefined();
    expect(flags.threatModel).toBeUndefined();
  });
});
