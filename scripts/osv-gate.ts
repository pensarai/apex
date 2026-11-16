#!/usr/bin/env bun
/**
 * Fails a PR that introduces a dependency with a critical or high advisory, or
 * any malware advisory, in the root `bun.lock`.
 *
 * Both lockfiles are scanned offline with `osv-scanner`: the head checkout and
 * the base ref's copy. An advisory is introduced when its id appears on a
 * package in the head scan but not on that package in the base scan, so moving
 * to a less vulnerable version passes, and an advisory published against an
 * unchanged package is reported without blocking the PR that happened to run.
 *
 * Severity is the OSV CVSS score: 9.0 and up is critical, 7.0 and up is high.
 * An introduced advisory with no score is a warning. Existing advisories, the
 * other lockfiles and the licenses of added packages (from the npm registry,
 * so the dependency list never goes to OSV or deps.dev) are reported only.
 *
 * Exceptions are `[[IgnoredVulns]]` entries in `osv-scanner.toml`, each with a
 * `reason`. Run `bun run check:osv-gate [--base <ref>]`; the base defaults to
 * the remote default branch (`origin/HEAD`).
 */
import { spawnSync } from "node:child_process";
import {
  appendFileSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";

export type Severity = "critical" | "high" | "medium" | "low" | "unscored";

interface OsvVulnerability {
  id: string;
  aliases?: string[];
  summary?: string;
  affected?: { ranges?: { events?: Record<string, string>[] }[] }[];
}

interface OsvPackage {
  package: { name: string; version: string; ecosystem: string };
  vulnerabilities?: OsvVulnerability[];
  groups?: { ids: string[]; aliases?: string[]; max_severity?: string }[];
}

export interface OsvScan {
  results?: { packages?: OsvPackage[] }[] | null;
}

export interface Finding {
  id: string;
  /** Every id and alias of the advisory group; matches it across scans. */
  aliases: string[];
  pkg: string;
  version: string;
  severity: Severity;
  score: number | null;
  malware: boolean;
  fixAvailable: boolean;
  summary: string;
}

export interface GateResult {
  blocking: Finding[];
  warnings: Finding[];
  introduced: Finding[];
  existing: Finding[];
  addedPackages: string[];
}

export function severityOf(maxSeverity: string | undefined): {
  severity: Severity;
  score: number | null;
} {
  const score = maxSeverity ? Number(maxSeverity) : NaN;
  if (!Number.isFinite(score)) return { severity: "unscored", score: null };
  if (score >= 9) return { severity: "critical", score };
  if (score >= 7) return { severity: "high", score };
  if (score >= 4) return { severity: "medium", score };
  return { severity: "low", score };
}

function packagesOf(scan: OsvScan): OsvPackage[] {
  return (scan.results ?? []).flatMap((r) => r.packages ?? []);
}

export function findingsFromScan(scan: OsvScan): Finding[] {
  const findings: Finding[] = [];
  for (const p of packagesOf(scan)) {
    const vulns = new Map((p.vulnerabilities ?? []).map((v) => [v.id, v]));
    for (const group of p.groups ?? []) {
      const id = group.ids[0];
      if (!id)
        throw new Error(`osv-scanner group without an id on ${p.package.name}`);
      const vuln = vulns.get(id);
      const ids = [...group.ids, ...(group.aliases ?? [])];
      findings.push({
        id,
        aliases: ids,
        pkg: p.package.name,
        version: p.package.version,
        ...severityOf(group.max_severity),
        malware: ids.some((i) => i.startsWith("MAL-")),
        fixAvailable: (vuln?.affected ?? []).some((a) =>
          (a.ranges ?? []).some((r) =>
            (r.events ?? []).some((e) => "fixed" in e),
          ),
        ),
        summary: vuln?.summary ?? "",
      });
    }
  }
  return findings;
}

export function packageVersions(scan: OsvScan): Set<string> {
  return new Set(
    packagesOf(scan).map((p) => `${p.package.name}@${p.package.version}`),
  );
}

const isBlocking = (f: Finding) =>
  f.malware || f.severity === "critical" || f.severity === "high";

export function compareScans(base: OsvScan, head: OsvScan): GateResult {
  // An advisory is the same one when any id or alias matches on that package:
  // osv-scanner's group ids are only sorted, so the first id can change
  // between scans when the duplicate records that apply change.
  const baseAliases = new Map<string, Set<string>>();
  for (const f of findingsFromScan(base)) {
    const known = baseAliases.get(f.pkg) ?? new Set<string>();
    for (const a of f.aliases) known.add(a);
    baseAliases.set(f.pkg, known);
  }
  const inBase = (f: Finding) =>
    f.aliases.some((a) => baseAliases.get(f.pkg)?.has(a));
  const headFindings = findingsFromScan(head);
  const introduced = headFindings.filter((f) => !inBase(f));
  const basePackages = packageVersions(base);
  return {
    introduced,
    existing: headFindings.filter(inBase),
    blocking: introduced.filter(isBlocking),
    warnings: introduced.filter(
      (f) => !isBlocking(f) && f.severity === "unscored",
    ),
    addedPackages: [...packageVersions(head)]
      .filter((p) => !basePackages.has(p))
      .sort(),
  };
}

export interface IgnoredVuln {
  id?: unknown;
  reason?: unknown;
}

/** Every exception must name an advisory and say why it is accepted. */
export function invalidExceptions(entries: IgnoredVuln[]): string[] {
  return entries.flatMap((e, i) => {
    const problems: string[] = [];
    if (typeof e.id !== "string" || !e.id)
      problems.push(`entry ${i + 1} has no id`);
    if (typeof e.reason !== "string" || !e.reason.trim())
      problems.push(
        `${typeof e.id === "string" ? e.id : `entry ${i + 1}`} has no reason`,
      );
    return problems;
  });
}

const SEVERITY_ORDER: Severity[] = [
  "critical",
  "high",
  "unscored",
  "medium",
  "low",
];

function findingRows(findings: Finding[]): string[] {
  return [...findings]
    .sort(
      (a, b) =>
        SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity),
    )
    .map(
      (f) =>
        `| ${f.malware ? "malware" : f.severity}${f.score === null ? "" : ` (${f.score})`} | \`${f.pkg}@${f.version}\` | ${f.id} | ${f.fixAvailable ? "yes" : "no"} | ${f.summary.replace(/\|/g, "\\|")} |`,
    );
}

function counts(findings: Finding[]): string {
  const by = new Map<string, Set<string>>();
  for (const f of findings) {
    const key = f.malware ? "malware" : f.severity;
    by.set(key, (by.get(key) ?? new Set()).add(`${f.pkg}\0${f.id}`));
  }
  const parts = ["malware", ...SEVERITY_ORDER].flatMap((s) => {
    const seen = by.get(s);
    return seen ? [`${seen.size} ${s}`] : [];
  });
  return parts.length ? parts.join(", ") : "none";
}

export function renderSummary(
  result: GateResult,
  licenses: Map<string, string>,
  otherLockfiles: { path: string; findings: Finding[] }[],
): string {
  const header =
    "| Severity | Package | Advisory | Fix | Summary |\n| --- | --- | --- | --- | --- |";
  const lines = ["## Vulnerable dependencies", ""];
  if (result.blocking.length) {
    lines.push(
      `**Blocked:** this PR introduces ${result.blocking.length} critical, high or malware advisories in \`bun.lock\`. Upgrade or remove the package, or add an \`[[IgnoredVulns]]\` entry with a \`reason\` to \`osv-scanner.toml\`.`,
      "",
      header,
      ...findingRows(result.blocking),
      "",
    );
  } else {
    lines.push(
      "No critical, high or malware advisories introduced in `bun.lock`.",
      "",
    );
  }
  const other = result.introduced.filter((f) => !result.blocking.includes(f));
  if (other.length) {
    lines.push(
      "### Other introduced advisories",
      "",
      header,
      ...findingRows(other),
      "",
    );
  }
  lines.push(
    "### Already in the lockfile",
    "",
    `Not blocking: ${counts(result.existing)}.`,
    "",
  );
  const existingSevere = result.existing.filter(isBlocking);
  if (existingSevere.length) {
    lines.push(
      "<details><summary>Critical and high</summary>",
      "",
      header,
      ...findingRows(existingSevere),
      "",
      "</details>",
      "",
    );
  }
  for (const lock of otherLockfiles) {
    lines.push(`Not gated, \`${lock.path}\`: ${counts(lock.findings)}.`, "");
  }
  if (result.addedPackages.length) {
    lines.push(
      `### Added packages (${result.addedPackages.length})`,
      "",
      "| Package | License |",
      "| --- | --- |",
      ...result.addedPackages.map(
        (p) => `| \`${p}\` | ${licenses.get(p) ?? "not looked up"} |`,
      ),
      "",
    );
  }
  return lines.join("\n");
}

const MAX_LICENSE_LOOKUPS = 200;

export async function lookupLicenses(
  packages: string[],
  fetcher: typeof fetch = fetch,
  timeoutMs = 10_000,
): Promise<Map<string, string>> {
  const licenses = new Map<string, string>();
  const queue = packages.slice(0, MAX_LICENSE_LOOKUPS);
  const worker = async () => {
    for (let p = queue.shift(); p !== undefined; p = queue.shift()) {
      const at = p.lastIndexOf("@");
      const name = p.slice(0, at);
      const version = p.slice(at + 1);
      const url = `https://registry.npmjs.org/${name.replace("/", "%2f")}/${encodeURIComponent(version)}`;
      try {
        // A stalled registry must not hold up the verdict; the body read shares the deadline.
        const res = await fetcher(url, {
          signal: AbortSignal.timeout(timeoutMs),
        });
        if (!res.ok) {
          licenses.set(p, `unknown (registry ${res.status})`);
          continue;
        }
        const meta = (await res.json()) as {
          license?: string | { type?: string };
        };
        const license =
          typeof meta.license === "string" ? meta.license : meta.license?.type;
        licenses.set(p, license || "none declared");
      } catch {
        // Report-only: a registry failure leaves the license unknown and the gate unchanged.
        licenses.set(p, "unknown (registry unreachable)");
      }
    }
  };
  await Promise.all(Array.from({ length: 8 }, worker));
  return licenses;
}

// Lockfiles reported but not gated. This repository has none besides bun.lock.
const OTHER_LOCKFILES: string[] = [];

function git(args: string[]): string {
  const res = spawnSync("git", args, {
    encoding: "utf8",
    maxBuffer: 256 * 1024 * 1024,
  });
  if (res.status !== 0)
    throw new Error(`git ${args.join(" ")} failed: ${res.stderr}`);
  return res.stdout;
}

function scan(lockfile: string, config?: string): OsvScan {
  const args = [
    "scan",
    "source",
    "--offline-vulnerabilities",
    "--download-offline-databases",
    "--all-packages",
    "--format",
    "json",
    "-L",
    lockfile,
    ...(config ? ["--config", config] : []),
  ];
  const res = spawnSync("osv-scanner", args, {
    encoding: "utf8",
    maxBuffer: 256 * 1024 * 1024,
  });
  if (res.error)
    throw new Error(`osv-scanner could not run: ${res.error.message}`);
  // 0: nothing found, 1: vulnerabilities found. Anything else is a failed scan.
  if (res.status !== 0 && res.status !== 1)
    throw new Error(
      `osv-scanner failed on ${lockfile} (exit ${res.status}): ${res.stderr}`,
    );
  return JSON.parse(res.stdout) as OsvScan;
}

/** The trunk as the remote names it (`origin/staging` today), never hardcoded. */
function defaultBranchRef(): string {
  const res = spawnSync(
    "git",
    ["symbolic-ref", "--short", "refs/remotes/origin/HEAD"],
    { encoding: "utf8" },
  );
  if (res.status !== 0)
    throw new Error(
      "Cannot tell the default branch: origin/HEAD is not set. Run `git remote set-head origin --auto`, or pass --base <ref>.",
    );
  return res.stdout.trim();
}

async function main(): Promise<void> {
  const baseArg = process.argv.indexOf("--base");
  const baseRef =
    baseArg === -1 ? defaultBranchRef() : process.argv[baseArg + 1];
  if (!baseRef) throw new Error("--base needs a ref");
  const root = git(["rev-parse", "--show-toplevel"]).trim();
  process.chdir(root);

  const config = resolve("osv-scanner.toml");
  const parsed = Bun.TOML.parse(readFileSync(config, "utf8")) as {
    IgnoredVulns?: IgnoredVuln[];
  };
  const problems = invalidExceptions(parsed.IgnoredVulns ?? []);
  if (problems.length) {
    for (const p of problems)
      console.log(`::error file=osv-scanner.toml::Exception ${p}`);
    process.exit(1);
  }

  const mergeBase = git(["merge-base", baseRef, "HEAD"]).trim();
  const baseDir = mkdtempSync(join(tmpdir(), "osv-gate-base-"));
  let baseScan: OsvScan;
  try {
    writeFileSync(
      join(baseDir, "bun.lock"),
      git(["show", `${mergeBase}:bun.lock`]),
    );
    baseScan = scan(join(baseDir, "bun.lock"));
  } finally {
    rmSync(baseDir, { recursive: true, force: true });
  }

  const result = compareScans(baseScan, scan("bun.lock", config));
  const others = OTHER_LOCKFILES.map((path) => ({
    path,
    findings: findingsFromScan(scan(path)),
  }));
  const licenses = await lookupLicenses(result.addedPackages);

  const summary = renderSummary(result, licenses, others);
  console.log(summary);
  if (process.env.GITHUB_STEP_SUMMARY)
    appendFileSync(process.env.GITHUB_STEP_SUMMARY, `${summary}\n`);
  for (const f of result.blocking)
    console.log(
      `::error file=bun.lock,title=Vulnerable dependency::${f.pkg}@${f.version} ${f.id} (${f.malware ? "malware" : f.severity})`,
    );
  for (const f of result.warnings)
    console.log(
      `::warning file=bun.lock,title=Unscored advisory::${f.pkg}@${f.version} ${f.id}`,
    );
  if (result.blocking.length) process.exit(1);
}

if (import.meta.main) await main();
