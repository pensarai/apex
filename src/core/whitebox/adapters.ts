import { existsSync } from "node:fs";
import { join } from "node:path";
import type { SessionInfo } from "../session";
import { writeWhiteboxArtifact } from "./artifacts";
import { runSpawnBounded } from "./boundedProcess";
import type { RepoProfile, ScanKind, ScanRunResult } from "./types";

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

const WHITEBOX_SCAN_ADAPTERS: WhiteboxScanAdapter[] = [
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

const KNOWN_ADAPTER_IDS = new Set(WHITEBOX_SCAN_ADAPTERS.map((a) => a.id));

function selectScanAdapters(input: {
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

/** Like {@link selectScanAdapters} but reports adapter ids that are not recognized. */
export function selectScanAdaptersWithMeta(input: {
  profile: RepoProfile;
  kind?: ScanKind;
  scannerIds?: string[];
}): { adapters: WhiteboxScanAdapter[]; unknownScannerIds: string[] } {
  let unknownScannerIds: string[] = [];
  let scannerIds = input.scannerIds;
  if (scannerIds?.length) {
    unknownScannerIds = scannerIds.filter((id) => !KNOWN_ADAPTER_IDS.has(id));
    scannerIds = scannerIds.filter((id) => KNOWN_ADAPTER_IDS.has(id));
  }
  const adapters = selectScanAdapters({
    profile: input.profile,
    kind: input.kind,
    scannerIds,
  });
  return { adapters, unknownScannerIds };
}

export async function runScanAdapter(input: {
  adapter: WhiteboxScanAdapter;
  profile: RepoProfile;
  session: SessionInfo;
  timeoutSeconds: number;
}): Promise<ScanRunResult> {
  const command = input.adapter.buildCommand(input.profile);
  const startedAt = Date.now();
  const raw = await runSpawnBounded({
    command,
    cwd: input.profile.rootPath,
    timeoutSeconds: input.timeoutSeconds,
    maxTotalBytes: MAX_SCAN_OUTPUT,
    detached: false,
  });
  const duration = Date.now() - startedAt;

  let fileBody = raw.stdout + (raw.stderr ? `\n\n[stderr]\n${raw.stderr}` : "");
  if (raw.outputTruncated) {
    fileBody +=
      "\n\n[apex] Scanner stdout/stderr capture hit the byte cap (truncated).\n";
  }
  if (raw.timedOut) {
    fileBody += "\n[apex] Scanner timed out.\n";
  }

  const artifact = await writeWhiteboxArtifact({
    session: input.session,
    type: "static-scan",
    name: `${input.adapter.id}-output`,
    content: fileBody,
    description: `${input.adapter.id} scan output (${duration}ms)`,
    extension: ".txt",
  });

  return {
    scanner: input.adapter.id,
    command,
    exitCode: raw.exitCode,
    findings: input.adapter.parseSummary(raw.stdout || raw.stderr),
    artifact,
    outputTruncated: raw.outputTruncated,
    timedOut: raw.timedOut,
  };
}
