import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { runScanner, type ScannerTool } from "./scanners";

const TOOLS: ScannerTool[] = [
  "semgrep",
  "gitleaks",
  "osv-scanner",
  "trivy-fs",
  "bandit",
  "gosec",
  "cargo-audit",
  "pip-audit",
  "npm-audit",
  "trufflehog",
];

describe("runScanner", () => {
  let workDir: string;
  let codebase: string;
  let outDir: string;

  beforeEach(() => {
    workDir = mkdtempSync(join(tmpdir(), "wb-scan-"));
    codebase = join(workDir, "codebase");
    outDir = join(workDir, "out");
    mkdirSync(codebase, { recursive: true });
    writeFileSync(join(codebase, "main.py"), "print('hi')\n");
  });

  afterEach(() => {
    rmSync(workDir, { recursive: true, force: true });
  });

  it.each(
    TOOLS,
  )("reports a structured error when %s is not on PATH", (tool) => {
    const originalPath = process.env.PATH;
    process.env.PATH = "/var/empty";
    try {
      const result = runScanner(
        tool,
        codebase,
        "-",
        join(outDir, `${tool}.json`),
      );
      expect(result.tool).toBe(tool);
      expect(result.error).toBeDefined();
    } finally {
      process.env.PATH = originalPath;
    }
  });
});
