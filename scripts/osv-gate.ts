#!/usr/bin/env bun
/**
 * Fails a PR that introduces a dependency with a critical or high advisory, or
 * any malware advisory, in a gated lockfile (`GATED_LOCKFILES`), or whose
 * lockfile holds a registry package osv-scanner did not read.
 *
 * Each lockfile in the head checkout and the base ref's copy are scanned
 * offline in one `osv-scanner` run, so all match one advisory database snapshot
 * under the same exceptions. An advisory is introduced when its id appears on a
 * package in the head scan but not on that package in the base scan, so moving
 * to a less vulnerable version passes, and an advisory published against an
 * unchanged package is reported without blocking the PR that happened to run.
 *
 * The gate also reads each lockfile itself and fails when a registry package in
 * the head copy is missing from osv-scanner's result: a package the scanner
 * never read is never matched against an advisory. A package hidden by a
 * `[[PackageOverrides]]` entry with `ignore = true` is excepted. A shortfall in
 * the base copy is a warning only.
 *
 * Severity is the OSV CVSS score: 9.0 and up is critical, 7.0 and up is high.
 * An introduced advisory with no score is a warning. Existing advisories and
 * the licenses of added packages (from the npm registry, so the dependency list
 * never goes to OSV or deps.dev) are reported only.
 *
 * Exceptions are `[[IgnoredVulns]]` entries in `osv-scanner.toml`, each with a
 * `reason`. Run `bun run check:osv-gate [--base <ref>]`; the base defaults to
 * the remote default branch (`origin/HEAD`).
 */
import { spawnSync } from "node:child_process";
import {
  appendFileSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { basename, dirname, join, resolve } from "node:path";

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
  results?: { source?: { path?: string }; packages?: OsvPackage[] }[] | null;
  /** Set by `scan`: packages the run's `[[PackageOverrides]]` ignores left out. */
  ignoredPackages?: Set<string>;
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

/** Lockfiles the gate blocks on, relative to the repository root. */
export const GATED_LOCKFILES = [
  "bun.lock",
  // Installed with `npm ci` into the offsec Camoufox sandbox images.
  "scripts/offsec-sandbox/package-lock.json",
];

export interface LockfilePair {
  /** Path relative to the repo root, used in the summary and annotations. */
  path: string;
  /** The merge base's copy; absent when the PR adds the lockfile. */
  base?: string;
  head: string;
}

export interface LockfileResult {
  path: string;
  result: GateResult;
}

export interface ScannedLockfile extends LockfileResult {
  files: LockfilePair;
  base: OsvScan;
  head: OsvScan;
  /** Packages the run's exceptions left out (`ignoredPackagesFrom`). */
  ignored: Set<string>;
}

/** What osv-scanner read of each copy; `base` is null for a lockfile the PR adds. */
export interface LockfileCoverage {
  head: Coverage;
  base: Coverage | null;
}

export interface Coverage {
  /** Registry packages the lockfile holds. */
  total: number;
  /** Workspace, link, file, Git and tarball entries, which are not checked. */
  other: number;
  missing: string[];
  /** Left out on purpose by a `[[PackageOverrides]]` ignore. */
  hidden: string[];
}

export interface GatedLockfile extends LockfileResult {
  coverage: LockfileCoverage;
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
    // osv-scanner reads keys case-insensitively, so a repeated key (Ignore and
    // ignore) could let it read a value the reason check never saw.
    if (Object.hasOwn(current, key.toLowerCase()))
      throw new Error(`${where}: "${key}" is set twice in one entry`);
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

const HEADER =
  "| Severity | Package | Advisory | Fix | Summary |\n| --- | --- | --- | --- | --- |";

const MAX_LISTED = 20;

function packageList(packages: string[]): string {
  const listed = packages.slice(0, MAX_LISTED).map((p) => `\`${p}\``);
  if (packages.length > MAX_LISTED)
    listed.push(`and ${packages.length - MAX_LISTED} more`);
  return listed.join(", ");
}

function coverageLines(
  { head, base }: LockfileCoverage,
  path: string,
): string[] {
  const lines: string[] = [];
  if (head.missing.length) {
    lines.push(
      `**Blocked:** osv-scanner did not read ${head.missing.length} of the ${head.total} registry packages locked in \`${path}\`, so they were never checked for advisories: ${packageList(head.missing)}. Check that the lockfile is one the package manager wrote, and the osv-scanner version.`,
    );
  } else {
    const hidden = head.hidden.length
      ? `, apart from ${head.hidden.length} that \`[[PackageOverrides]]\` entries hide with \`ignore = true\``
      : "";
    lines.push(
      `osv-scanner read all ${head.total} registry packages locked in \`${path}\`${hidden}.`,
    );
  }
  if (head.other)
    lines.push(
      `${head.other} workspace, link, file or Git entries are not counted.`,
    );
  if (base === null)
    lines.push(
      `\`${path}\` is new in this PR, so every advisory in it counts as introduced.`,
    );
  else if (base.missing.length)
    lines.push(
      `**Warning:** osv-scanner did not read ${base.missing.length} of the ${base.total} registry packages in the merge base's \`${path}\`: ${packageList(base.missing)}. Advisories already on them may show as introduced by this PR.`,
    );
  return [lines.join(" "), ""];
}

function lockfileSection(
  { path, result, coverage }: GatedLockfile,
  licenses: Map<string, string>,
): string[] {
  const lines = [`### \`${path}\``, "", ...coverageLines(coverage, path)];
  if (result.blocking.length) {
    lines.push(
      `**Blocked:** this PR introduces ${result.blocking.length} critical, high or malware advisories in \`${path}\`. Upgrade or remove the package, or add an \`[[IgnoredVulns]]\` entry with a \`reason\` to \`osv-scanner.toml\`.`,
      "",
      HEADER,
      ...findingRows(result.blocking),
      "",
    );
  } else {
    lines.push(
      `No critical, high or malware advisories introduced in \`${path}\`.`,
      "",
    );
  }
  const other = result.introduced.filter((f) => !result.blocking.includes(f));
  if (other.length) {
    lines.push(
      "#### Other introduced advisories",
      "",
      HEADER,
      ...findingRows(other),
      "",
    );
  }
  lines.push(
    "#### Already in the lockfile",
    "",
    `Not blocking: ${counts(result.existing)}.`,
    "",
  );
  const existingSevere = result.existing.filter(isBlocking);
  if (existingSevere.length) {
    lines.push(
      "<details><summary>Critical and high</summary>",
      "",
      HEADER,
      ...findingRows(existingSevere),
      "",
      "</details>",
      "",
    );
  }
  if (result.addedPackages.length) {
    lines.push(
      `#### Added packages (${result.addedPackages.length})`,
      "",
      "| Package | License |",
      "| --- | --- |",
      ...result.addedPackages.map(
        (p) => `| \`${p}\` | ${licenses.get(p) ?? "not looked up"} |`,
      ),
      "",
    );
  }
  return lines;
}

export function renderSummary(
  results: GatedLockfile[],
  licenses: Map<string, string>,
): string {
  const lines = ["## Vulnerable dependencies", ""];
  for (const r of results) lines.push(...lockfileSection(r, licenses));
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

/** Whether `path` exists in `commit`; a lockfile the PR adds does not. */
function existsAt(commit: string, path: string): boolean {
  return spawnSync("git", ["cat-file", "-e", `${commit}:${path}`]).status === 0;
}

function git(args: string[]): string {
  const res = spawnSync("git", args, {
    encoding: "utf8",
    maxBuffer: 256 * 1024 * 1024,
  });
  if (res.status !== 0)
    throw new Error(`git ${args.join(" ")} failed: ${res.stderr}`);
  return res.stdout;
}

function scan(
  lockfiles: string[],
  config?: string,
  { download = true }: { download?: boolean } = {},
): OsvScan {
  const args = [
    "scan",
    "source",
    // Full offline mode: only the advisory database download below touches the
    // network; no other scanner feature can send the dependency list anywhere.
    "--offline",
    ...(download ? ["--download-offline-databases"] : []),
    "--all-packages",
    "--format",
    "json",
    ...lockfiles.flatMap((l) => ["-L", l]),
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
      `osv-scanner failed on ${lockfiles.join(", ")} (exit ${res.status}): ${res.stderr}`,
    );
  const scanned = JSON.parse(res.stdout) as OsvScan;
  scanned.ignoredPackages = ignoredPackagesFrom(res.stderr);
  return scanned;
}

/**
 * The npm packages osv-scanner logs as dropped by a `[[PackageOverrides]]`
 * ignore ("Package npm/<name>/<version> has been filtered out because: …"), as
 * `name@version`. The scanner applies its own override rules, so the gate takes
 * its word; a log line it does not recognize excuses nothing.
 */
export function ignoredPackagesFrom(log: string | undefined): Set<string> {
  const ignored = new Set<string>();
  for (const line of (log ?? "").split("\n")) {
    const m =
      /^Package npm\/(.+)\/([^/\s]+) has been filtered out because:/.exec(
        line.trim(),
      );
    if (m) ignored.add(`${m[1]}@${m[2]}`);
  }
  return ignored;
}

/**
 * Splits a scan of several lockfiles into one scan per lockfile, in order.
 * osv-scanner names each result by the path it was given and leaves out a
 * lockfile with no packages, so a missing or unknown source fails the gate
 * rather than reading as a lockfile with no findings. osv-scanner reports
 * Windows paths with forward slashes, so both sides are compared that way.
 */
export function splitBySource(scan: OsvScan, lockfiles: string[]): OsvScan[] {
  const slashed = (path = "") => path.replaceAll("\\", "/");
  const results = scan.results ?? [];
  for (const r of results)
    if (!lockfiles.some((l) => slashed(l) === slashed(r.source?.path)))
      throw new Error(
        `osv-scanner returned results for an unexpected source: ${r.source?.path}`,
      );
  return lockfiles.map((path) => {
    const own = results.filter(
      (r) => slashed(r.source?.path) === slashed(path),
    );
    if (!own.length)
      throw new Error(`osv-scanner returned no results for ${path}`);
    return { results: own };
  });
}

/** Scans every base and head lockfile together, then compares each pair. */
export function scanAndCompare(
  pairs: LockfilePair[],
  config: string,
  scanner: typeof scan = scan,
): ScannedLockfile[] {
  // One run over every lockfile: both sides honor the exceptions (a finding
  // hidden only on the head would read as a version the PR removed), match
  // against one database snapshot, and load every ecosystem either one uses.
  const files = pairs.flatMap((p) => (p.base ? [p.base, p.head] : [p.head]));
  const scanned = scanner(files, config, { download: true });
  const scans = splitBySource(scanned, files);
  const ignored = scanned.ignoredPackages ?? new Set<string>();
  const byFile = new Map(files.map((f, i) => [f, scans[i]!]));
  return pairs.map((p) => {
    // A lockfile the PR adds has no base: everything in it is introduced.
    const base = p.base ? byFile.get(p.base)! : { results: [] };
    const head = byFile.get(p.head)!;
    return {
      path: p.path,
      result: compareScans(base, head),
      files: p,
      base,
      head,
      ignored,
    };
  });
}

/** bun.lock is JSON that allows trailing commas; drops them outside strings. */
export function parseJsonWithTrailingCommas(text: string): unknown {
  const out: string[] = [];
  let inString = false;
  for (let i = 0; i < text.length; i++) {
    const c = text.charAt(i);
    if (inString) {
      if (c === "\\") {
        out.push(c, text[i + 1] ?? "");
        i++;
        continue;
      }
      if (c === '"') inString = false;
    } else if (c === '"') inString = true;
    else if (c === ",") {
      let j = i + 1;
      while (j < text.length && " \t\r\n".includes(text.charAt(j))) j++;
      if (text[j] === "}" || text[j] === "]") continue;
    }
    out.push(c);
  }
  return JSON.parse(out.join(""));
}

// Any other version is a workspace, link, file, Git or tarball dependency,
// which osv-scanner names differently, or an entry the gate cannot read.
const REGISTRY_VERSION = /^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.+-]+)?$/;
// Bun writes a local tarball as a bare path: ./x.tgz, ../x.tgz or /x.tgz.
const BUN_NOT_REGISTRY =
  /^(?:workspace:|link:|file:|root:|git\+|git:|github:|https?:|\.{1,2}\/|\/)/;
const NPM_NOT_REGISTRY = /^(?:git\+|git:|github:|file:)/;

export interface LockedPackages {
  /** Registry packages as `name@version`, each once. */
  registry: Set<string>;
  other: number;
}

/**
 * The registry packages a lockfile holds, read without osv-scanner. Each name
 * and version counts once, as osv-scanner lists it. bun.lock entries hold the
 * resolved `name@version` first (an npm alias resolves to the real name);
 * package-lock.json keys are install paths, where the root, links and
 * workspace or out-of-tree targets are not registry packages. An entry the
 * gate cannot read throws.
 */
export function lockedPackages(path: string, text: string): LockedPackages {
  const isBun = basename(path) === "bun.lock";
  if (!isBun && basename(path) !== "package-lock.json")
    throw new Error(
      `${path}: the gate reads bun.lock and package-lock.json only`,
    );
  const lock = (
    isBun ? parseJsonWithTrailingCommas(text) : JSON.parse(text)
  ) as { packages?: unknown } | null;
  const packages = lock?.packages;
  if (!packages || typeof packages !== "object" || Array.isArray(packages))
    throw new Error(`${path} has no packages map the gate can read`);
  const registry = new Set<string>();
  let other = 0;
  for (const [key, entry] of Object.entries(
    packages as Record<string, unknown>,
  )) {
    if (isBun) {
      const id: unknown = Array.isArray(entry) ? entry[0] : undefined;
      const at = typeof id === "string" ? id.indexOf("@", 1) : -1;
      if (typeof id !== "string" || at < 1)
        throw new Error(`${path}: cannot read the package entry "${key}"`);
      const version = id.slice(at + 1);
      if (REGISTRY_VERSION.test(version)) registry.add(id);
      else if (BUN_NOT_REGISTRY.test(version)) other++;
      else
        throw new Error(`${path}: cannot read the version of "${key}" (${id})`);
      continue;
    }
    if (key === "") continue;
    if (!entry || typeof entry !== "object")
      throw new Error(`${path}: cannot read the package entry "${key}"`);
    const e = entry as {
      name?: unknown;
      version?: unknown;
      resolved?: unknown;
      link?: unknown;
    };
    const at = key.lastIndexOf("node_modules/");
    if (
      e.link === true ||
      at === -1 ||
      (typeof e.resolved === "string" && NPM_NOT_REGISTRY.test(e.resolved))
    ) {
      other++;
      continue;
    }
    const name =
      typeof e.name === "string"
        ? e.name
        : key.slice(at + "node_modules/".length);
    if (typeof e.version !== "string" || !REGISTRY_VERSION.test(e.version))
      throw new Error(
        `${path}: cannot read the version of "${key}" (${String(e.version)})`,
      );
    registry.add(`${name}@${e.version}`);
  }
  return { registry, other };
}

/**
 * Locked registry packages missing from osv-scanner's result: their advisories
 * were never checked. A package the scanner says a `[[PackageOverrides]]`
 * ignore left out is returned as `hidden`; that entry already needs a reason.
 */
export function unreadPackages(
  locked: LockedPackages,
  scan: OsvScan,
  ignored: Set<string>,
): Coverage {
  const read = packageVersions(scan);
  const missing: string[] = [];
  const hidden: string[] = [];
  for (const p of [...locked.registry].sort()) {
    if (read.has(p)) continue;
    (ignored.has(p) ? hidden : missing).push(p);
  }
  return { total: locked.registry.size, other: locked.other, missing, hidden };
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
  let results: GatedLockfile[];
  try {
    const pairs = GATED_LOCKFILES.map((path, i): LockfilePair => {
      // Absolute paths: osv-scanner reports each result under the path it was given.
      const head = resolve(path);
      if (!existsSync(head))
        throw new Error(`Gated lockfile ${path} is missing from the checkout`);
      if (!existsAt(mergeBase, path)) return { path, head };
      // osv-scanner picks its parser from the file name, so keep it.
      const base = join(baseDir, String(i), basename(path));
      mkdirSync(dirname(base));
      writeFileSync(base, git(["show", `${mergeBase}:${path}`]));
      return { path, base, head };
    });
    results = scanAndCompare(pairs, config).map(
      ({ path, result, files, base, head, ignored }) => {
        const coverageOf = (file: string, scanned: OsvScan) =>
          unreadPackages(
            lockedPackages(path, readFileSync(file, "utf8")),
            scanned,
            ignored,
          );
        return {
          path,
          result,
          coverage: {
            head: coverageOf(files.head, head),
            base: files.base ? coverageOf(files.base, base) : null,
          },
        };
      },
    );
  } finally {
    rmSync(baseDir, { recursive: true, force: true });
  }

  const licenses = await lookupLicenses([
    ...new Set(results.flatMap((r) => r.result.addedPackages)),
  ]);

  const summary = renderSummary(results, licenses);
  console.log(summary);
  if (process.env.GITHUB_STEP_SUMMARY)
    appendFileSync(process.env.GITHUB_STEP_SUMMARY, `${summary}\n`);
  for (const { path, result, coverage } of results) {
    if (coverage.head.missing.length)
      console.log(
        `::error file=${path},title=Packages osv-scanner did not read::${coverage.head.missing.length} of ${coverage.head.total} registry packages, starting with ${coverage.head.missing.slice(0, 5).join(", ")}`,
      );
    for (const f of result.blocking)
      console.log(
        `::error file=${path},title=Vulnerable dependency::${f.pkg}@${f.version} ${f.id} (${f.malware ? "malware" : f.severity})`,
      );
    for (const f of result.warnings)
      console.log(
        `::warning file=${path},title=Unscored advisory::${f.pkg}@${f.version} ${f.id}`,
      );
  }
  if (
    results.some(
      (r) => r.result.blocking.length || r.coverage.head.missing.length,
    )
  )
    process.exit(1);
}

if (import.meta.main) await main();
