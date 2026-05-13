import { spawn } from "child_process";
import { existsSync } from "fs";
import { readFile } from "fs/promises";
import { join } from "path";
import type { SessionInfo } from "../session";
import { writeWhiteboxArtifact } from "./artifacts";
import type {
  RepoProfile,
  ScanKind,
  ScanRunResult,
  WhiteboxArtifactRef,
} from "./types";

const MAX_SCAN_OUTPUT = 2 * 1024 * 1024;

export type WhiteboxScanAdapter = {
  id: string;
  kind: ScanKind;
  tool: string;
  detect: (profile: RepoProfile) => boolean;
  buildCommand: (profile: RepoProfile) => string[];
  parseSummary: (raw: string) => ScanRunResult["findings"];
};

function hasTool(profile: RepoProfile, tool: string): boolean {
  return profile.toolAvailability.some(
    (entry) => entry.name === tool && entry.available,
  );
}

function hasLanguage(profile: RepoProfile, language: string): boolean {
  return profile.languages.includes(
    language as RepoProfile["languages"][number],
  );
}

function simpleLineFindings(
  tool: string,
  raw: string,
): ScanRunResult["findings"] {
  return raw
    .split("\n")
    .map((line) => line.trim())
    .filter(Boolean)
    .slice(0, 50)
    .map((line) => ({
      tool,
      title: line.slice(0, 160),
      description: line,
    }));
}

export const WHITEBOX_SCAN_ADAPTERS: WhiteboxScanAdapter[] = [
  {
    id: "semgrep",
    kind: "static",
    tool: "semgrep",
    detect: (profile) => hasTool(profile, "semgrep"),
    buildCommand: () => [
      "semgrep",
      "--config",
      "p/security-audit",
      "--json",
      ".",
    ],
    parseSummary: (raw) => {
      try {
        const parsed = JSON.parse(raw) as {
          results?: Array<{
            check_id?: string;
            path?: string;
            start?: { line?: number };
            extra?: { severity?: string; message?: string };
          }>;
        };
        return (parsed.results ?? []).slice(0, 100).map((result) => ({
          tool: "semgrep",
          severity: result.extra?.severity,
          title: result.check_id ?? result.extra?.message ?? "Semgrep finding",
          location: result.path
            ? { file: result.path, line: result.start?.line }
            : undefined,
          description: result.extra?.message,
        }));
      } catch {
        return simpleLineFindings("semgrep", raw);
      }
    },
  },
  {
    id: "gitleaks",
    kind: "secrets",
    tool: "gitleaks",
    detect: (profile) => hasTool(profile, "gitleaks"),
    buildCommand: () => [
      "gitleaks",
      "detect",
      "--no-banner",
      "--report-format",
      "json",
    ],
    parseSummary: (raw) => {
      try {
        const parsed = JSON.parse(raw) as Array<{
          RuleID?: string;
          File?: string;
          StartLine?: number;
          Description?: string;
        }>;
        return parsed.slice(0, 100).map((finding) => ({
          tool: "gitleaks",
          severity: "HIGH",
          title: finding.RuleID ?? "Potential secret",
          location: finding.File
            ? { file: finding.File, line: finding.StartLine }
            : undefined,
          description: finding.Description,
        }));
      } catch {
        return simpleLineFindings("gitleaks", raw);
      }
    },
  },
  {
    id: "trufflehog",
    kind: "secrets",
    tool: "trufflehog",
    detect: (profile) => hasTool(profile, "trufflehog"),
    buildCommand: () => ["trufflehog", "filesystem", ".", "--json"],
    parseSummary: (raw) => simpleLineFindings("trufflehog", raw),
  },
  {
    id: "osv-scanner",
    kind: "dependencies",
    tool: "osv-scanner",
    detect: (profile) => hasTool(profile, "osv-scanner"),
    buildCommand: () => ["osv-scanner", "--recursive", "--format", "json", "."],
    parseSummary: (raw) => simpleLineFindings("osv-scanner", raw),
  },
  {
    id: "trivy-fs",
    kind: "dependencies",
    tool: "trivy",
    detect: (profile) => hasTool(profile, "trivy"),
    buildCommand: () => ["trivy", "fs", "--format", "json", "."],
    parseSummary: (raw) => simpleLineFindings("trivy", raw),
  },
  {
    id: "npm-audit",
    kind: "dependencies",
    tool: "npm",
    detect: (profile) =>
      profile.packageManagers.includes("npm") ||
      existsSync(join(profile.rootPath, "package-lock.json")),
    buildCommand: () => ["npm", "audit", "--json"],
    parseSummary: (raw) => simpleLineFindings("npm audit", raw),
  },
  {
    id: "pip-audit",
    kind: "dependencies",
    tool: "pip-audit",
    detect: (profile) =>
      hasTool(profile, "pip-audit") && hasLanguage(profile, "python"),
    buildCommand: () => ["pip-audit", "--format", "json"],
    parseSummary: (raw) => simpleLineFindings("pip-audit", raw),
  },
  {
    id: "gosec",
    kind: "static",
    tool: "gosec",
    detect: (profile) =>
      hasTool(profile, "gosec") && hasLanguage(profile, "go"),
    buildCommand: () => ["gosec", "-fmt", "json", "./..."],
    parseSummary: (raw) => simpleLineFindings("gosec", raw),
  },
  {
    id: "cargo-audit",
    kind: "dependencies",
    tool: "cargo-audit",
    detect: (profile) =>
      hasTool(profile, "cargo-audit") && hasLanguage(profile, "rust"),
    buildCommand: () => ["cargo", "audit", "--json"],
    parseSummary: (raw) => simpleLineFindings("cargo audit", raw),
  },
  {
    id: "bandit",
    kind: "static",
    tool: "bandit",
    detect: (profile) =>
      hasTool(profile, "bandit") && hasLanguage(profile, "python"),
    buildCommand: () => ["bandit", "-r", ".", "-f", "json"],
    parseSummary: (raw) => simpleLineFindings("bandit", raw),
  },
];

export function selectScanAdapters(input: {
  profile: RepoProfile;
  kind?: ScanKind;
  scannerIds?: string[];
}): WhiteboxScanAdapter[] {
  const selectedIds = input.scannerIds ? new Set(input.scannerIds) : undefined;
  return WHITEBOX_SCAN_ADAPTERS.filter((adapter) => {
    if (input.kind && adapter.kind !== input.kind) return false;
    if (selectedIds && !selectedIds.has(adapter.id)) return false;
    return adapter.detect(input.profile);
  });
}

export async function runScanAdapter(input: {
  adapter: WhiteboxScanAdapter;
  profile: RepoProfile;
  session: SessionInfo;
  timeoutSeconds: number;
}): Promise<ScanRunResult> {
  const command = input.adapter.buildCommand(input.profile);
  const startedAt = Date.now();
  const raw = await runCommand(
    command,
    input.profile.rootPath,
    input.timeoutSeconds,
  );
  const duration = Date.now() - startedAt;
  const artifact = await writeWhiteboxArtifact({
    session: input.session,
    type: "static-scan",
    name: `${input.adapter.id}-output`,
    content: raw.stdout + (raw.stderr ? `\n\n[stderr]\n${raw.stderr}` : ""),
    description: `${input.adapter.id} scan output (${duration}ms)`,
    extension: ".txt",
  });

  return {
    scanner: input.adapter.id,
    command,
    exitCode: raw.exitCode,
    findings: input.adapter.parseSummary(raw.stdout || raw.stderr),
    artifact,
  };
}

async function runCommand(
  command: string[],
  cwd: string,
  timeoutSeconds: number,
): Promise<{ stdout: string; stderr: string; exitCode: number | null }> {
  return new Promise((resolve) => {
    const child = spawn(command[0]!, command.slice(1), {
      cwd,
      stdio: ["ignore", "pipe", "pipe"],
    });
    let stdout = "";
    let stderr = "";
    let settled = false;

    const timeout = setTimeout(() => {
      child.kill("SIGTERM");
    }, timeoutSeconds * 1000);

    child.stdout.on("data", (data) => {
      if (stdout.length < MAX_SCAN_OUTPUT) stdout += data.toString();
    });
    child.stderr.on("data", (data) => {
      if (stderr.length < MAX_SCAN_OUTPUT) stderr += data.toString();
    });
    child.on("close", (code) => {
      if (settled) return;
      settled = true;
      clearTimeout(timeout);
      resolve({ stdout, stderr, exitCode: code });
    });
    child.on("error", (error) => {
      if (settled) return;
      settled = true;
      clearTimeout(timeout);
      resolve({ stdout, stderr: error.message, exitCode: null });
    });
  });
}

export async function readScanArtifact(
  artifact: WhiteboxArtifactRef,
  session: SessionInfo,
): Promise<string> {
  return readFile(join(session.rootPath, artifact.path), "utf-8");
}
