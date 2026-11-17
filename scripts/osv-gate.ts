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
  affected?: {
    package?: { name?: string; ecosystem?: string };
    ranges?: { events?: Record<string, string>[] }[];
  }[];
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
        // An advisory can cover several packages; only this package's entries say whether it has a fix.
        // Every record in the group is the same advisory; any of them may list
        // the fix, but only for this package's entries.
        fixAvailable: group.ids
          .flatMap((gid) => vulns.get(gid)?.affected ?? [])
          .filter(
            (a) =>
              a.package?.name === p.package.name &&
              (!a.package.ecosystem ||
                a.package.ecosystem === p.package.ecosystem),
          )
          .some((a) =>
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
  // Two findings are the same advisory on the same package when any id or
  // alias matches: osv-scanner's group ids are only sorted, so the first id can
  // change between scans when the duplicate records that apply change.
  const same = (a: Finding, b: Finding) =>
    a.pkg === b.pkg && a.aliases.some((x) => b.aliases.includes(x));
  const baseFindings = findingsFromScan(base);
  const headFindings = findingsFromScan(head);
  const existing: Finding[] = [];
  const introduced: Finding[] = [];
  for (const h of headFindings) {
    const baseVersions = new Set(
      baseFindings.filter((b) => same(b, h)).map((b) => b.version),
    );
    if (baseVersions.has(h.version)) {
      existing.push(h);
      continue;
    }
    // A version that did not have this advisory at the base replaces one the
    // PR removed, so a straight upgrade passes. Affected versions beyond the
    // ones removed are introduced.
    const headVersions = new Set(
      headFindings.filter((x) => same(x, h)).map((x) => x.version),
    );
    const removed = [...baseVersions].filter((v) => !headVersions.has(v));
    const added = [...headVersions].filter((v) => !baseVersions.has(v)).sort();
    (added.indexOf(h.version) < removed.length ? existing : introduced).push(h);
  }
  const basePackages = packageVersions(base);
  return {
    introduced,
    existing,
    blocking: introduced.filter(isBlocking),
    warnings: introduced.filter(
      (f) => !isBlocking(f) && f.severity === "unscored",
    ),
    addedPackages: [...packageVersions(head)]
      .filter((p) => !basePackages.has(p))
      .sort(),
  };
}

type ConfigEntry = Record<string, string | boolean>;

export interface OsvConfig {
  IgnoredVulns: ConfigEntry[];
  PackageOverrides: ConfigEntry[];
}

/** The line without its comment; a `#` inside a quoted string is kept. */
function stripComment(line: string): string {
  let quote: string | null = null;
  for (let i = 0; i < line.length; i++) {
    const c = line[i];
    if (quote) {
      if (quote === '"' && c === "\\") i++;
      else if (c === quote) quote = null;
    } else if (c === '"' || c === "'") quote = c;
    else if (c === "#") return line.slice(0, i);
  }
  return line;
}

function parseValue(raw: string, where: string): string | boolean {
  if (raw.startsWith('"')) {
    const m = /^"((?:[^"\\]|\\.)*)"$/.exec(raw);
    if (!m) throw new Error(`${where}: cannot read the string ${raw}`);
    return JSON.parse(`"${m[1]}"`) as string;
  }
  if (raw.startsWith("'")) {
    const m = /^'([^']*)'$/.exec(raw);
    if (!m) throw new Error(`${where}: cannot read the string ${raw}`);
    return m[1] ?? "";
  }
  if (raw === "true") return true;
  if (raw === "false") return false;
  // Dates, numbers and one-line arrays are kept as text.
  return raw;
}

/**
 * The tables of osv-scanner.toml that can hide a finding. The file is held to
 * an allowlist so the gate reads it exactly as osv-scanner does: comments,
 * [[IgnoredVulns]] and [[PackageOverrides]] tables, and one-line `key = value`
 * entries inside them, with table and key names matched case-insensitively.
 * Anything else (a top-level key, another table, an inline table, a
 * multi-line value, a line it cannot read) is an error, never skipped, so an
 * exception cannot slip past the reason check.
 */
export function parseOsvConfig(toml: string): OsvConfig {
  const config: OsvConfig = { IgnoredVulns: [], PackageOverrides: [] };
  let current: ConfigEntry | null = null;
  toml.split("\n").forEach((raw, n) => {
    const line = stripComment(raw).trim();
    if (!line) return;
    const where = `osv-scanner.toml line ${n + 1}`;
    const header = /^\[\[\s*([A-Za-z]+)\s*\]\]$/.exec(line);
    if (header) {
      const name = header[1] ?? "";
      const table = (Object.keys(config) as (keyof OsvConfig)[]).find(
        (t) => t.toLowerCase() === name.toLowerCase(),
      );
      if (!table)
        throw new Error(`${where}: the gate does not check [[${name}]] tables`);
      current = {};
      config[table].push(current);
      return;
    }
    if (line.startsWith("["))
      throw new Error(
        `${where}: the gate cannot check "${line}"; use [[IgnoredVulns]] or [[PackageOverrides]] with one-line keys`,
      );
    const kv = /^([A-Za-z][\w.-]*)\s*=\s*(.+)$/.exec(line);
    if (!kv) throw new Error(`${where}: cannot read "${line}"`);
    const key = kv[1] ?? "";
    const value = kv[2] ?? "";
    if (value.startsWith('"""') || value.startsWith("'''"))
      throw new Error(`${where}: the gate cannot check multi-line strings`);
    // A top-level key can hold the same exceptions as an array of inline
    // tables (IgnoredVulns = [{ ... }]), so none is allowed.
    if (!current)
      throw new Error(
        `${where}: the gate allows no top-level settings; put exceptions in [[IgnoredVulns]] or [[PackageOverrides]] tables`,
      );
    // An inline table can spell an ignore many ways ({ "ignore" = true }, ...);
    // dotted keys can only spell it one way, which the gate checks exactly.
    if (value.startsWith("{"))
      throw new Error(
        `${where}: write dotted keys (vulnerability.ignore = true), not inline tables`,
      );
    current[key.toLowerCase()] = parseValue(value, where);
  });
  return config;
}

/** A package override hides findings when any of its keys ignores the package or its vulnerabilities. */
function overrideHides(override: ConfigEntry): boolean {
  // license.ignore only skips license checks; vulnerabilities are still reported.
  return override.ignore === true || override["vulnerability.ignore"] === true;
}

const hasReason = (entry: ConfigEntry) =>
  typeof entry.reason === "string" && entry.reason.trim() !== "";

/**
 * Every way osv-scanner.toml can hide a finding needs a reason: an ignored
 * advisory must also name it, and a package override that ignores the package
 * or its vulnerabilities is held to the same rule.
 */
export function invalidExceptions(config: OsvConfig): string[] {
  const ignored = config.IgnoredVulns.flatMap((e, i) => {
    const problems: string[] = [];
    if (typeof e.id !== "string" || !e.id)
      problems.push(`entry ${i + 1} has no id`);
    if (!hasReason(e))
      problems.push(
        `${typeof e.id === "string" ? e.id : `entry ${i + 1}`} has no reason`,
      );
    return problems;
  });
  const overrides = config.PackageOverrides.flatMap((o, i) =>
    overrideHides(o) && !hasReason(o)
      ? [
          `${typeof o.name === "string" ? o.name : `override ${i + 1}`} ignores vulnerabilities without a reason`,
        ]
      : [],
  );
  return [...ignored, ...overrides];
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
  let problems: string[];
  try {
    problems = invalidExceptions(parseOsvConfig(readFileSync(config, "utf8")));
  } catch (err) {
    // A config the gate cannot read is a failed gate, reported where it points.
    console.log(
      `::error file=osv-scanner.toml::${err instanceof Error ? err.message : String(err)}`,
    );
    process.exit(1);
  }
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
