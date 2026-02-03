import { readFileSync, writeFileSync, mkdirSync, rmSync, existsSync } from "fs";
import { join, dirname } from "path";
import { fileURLToPath } from "url";
import type { VulnerabilityClass } from "../types";

// Map vulnerability classes to guidance files
const GUIDANCE_FILE_MAP: Record<VulnerabilityClass, string[]> = {
  sql_injection: ["sql-injection.md"],
  nosql_injection: ["sql-injection.md"],
  xss: ["xss.md", "csp-bypass.md"],
  command_injection: ["command-injection.md"],
  ssti: ["ssti.md"],
  path_traversal: ["path-traversal.md"],
  ssrf: ["ssrf.md"],
  idor: ["idor.md"],
  authentication_bypass: ["authentication-bypass.md"],
  jwt_vulnerabilities: ["authentication-bypass.md"],
  deserialization: ["deserialization.md"],
  xxe: ["xxe.md"],
  crypto: ["authentication-bypass.md"],
  business_logic: ["business-logic.md"],
  generic: ["csrf.md", "cors.md", "open-redirect.md", "file-upload.md"],
};

function getGuidanceSourceDir(): string {
  const __filename = fileURLToPath(import.meta.url);
  return dirname(__filename);
}

export function injectGuidanceFiles(
  guidancePath: string,
  vulnerabilityClass: VulnerabilityClass
): string[] {
  const sourceDir = getGuidanceSourceDir();
  const filesToInject = GUIDANCE_FILE_MAP[vulnerabilityClass] || [];
  const injectedFiles: string[] = [];

  mkdirSync(guidancePath, { recursive: true });

  for (const filename of filesToInject) {
    const sourcePath = join(sourceDir, filename);
    const destPath = join(guidancePath, filename);

    if (existsSync(sourcePath)) {
      writeFileSync(destPath, readFileSync(sourcePath, "utf-8"));
      injectedFiles.push(destPath);
    }
  }
  return injectedFiles;
}

export function cleanupGuidanceFiles(guidancePath: string): void {
  if (existsSync(guidancePath)) {
    rmSync(guidancePath, { recursive: true, force: true });
  }
}

export function listGuidanceFiles(guidancePath: string): string[] {
  if (!existsSync(guidancePath)) {
    return [];
  }
  const { readdirSync } = require("fs");
  return readdirSync(guidancePath)
    .filter((f: string) => f.endsWith(".md"))
    .map((f: string) => join(guidancePath, f));
}
