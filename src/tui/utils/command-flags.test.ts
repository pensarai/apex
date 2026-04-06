import { describe, expect, it, beforeEach, afterEach } from "vitest";
import { mkdtempSync, writeFileSync, rmSync } from "fs";
import { join } from "path";
import { tmpdir } from "os";
import {
  resolveFlagValue,
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
    expect(flags.threatModel).toContain("XSS on login");
  });

  it("parses --threat-model with @file reference", () => {
    const filePath = join(tempDir, "tm.md");
    writeFileSync(filePath, "IDOR on user profiles");

    const flags = parseWebFlags(["--threat-model", `@${filePath}`]);
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
  });

  it("does not set prompt or threatModel when flags are absent", () => {
    const flags = parseWebFlags(["--target", "http://example.com"]);
    expect(flags.prompt).toBeUndefined();
    expect(flags.threatModel).toBeUndefined();
  });
});
