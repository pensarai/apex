/**
 * Normalize scanner outputs to a shared finding schema.
 *
 * Usage: bun parse-results.ts --tool <tool> --input <path>
 *
 * Each scanner emits its own JSON / NDJSON shape. This script converts
 * those into a uniform `ParseResult` so the agent consuming downstream
 * doesn't need to know per-scanner details. Findings that the parser
 * can't fully understand are still included with a placeholder severity
 * — better to surface a noisy finding than to silently drop it.
 */

import { readFileSync } from "node:fs";
import { z } from "zod";

// ---------------------------------------------------------------------------
// Schema
// ---------------------------------------------------------------------------

export const Severity = z.enum(["info", "low", "medium", "high", "critical"]);
export type Severity = z.infer<typeof Severity>;

export const Finding = z.object({
  tool: z.string(),
  ruleId: z.string(),
  severity: Severity.optional(),
  message: z.string(),
  path: z.string(),
  startLine: z.number().int().positive().optional(),
  endLine: z.number().int().positive().optional(),
  cwe: z.array(z.string()).optional(),
});
export type Finding = z.infer<typeof Finding>;

export const ParseResult = z.object({
  tool: z.string(),
  findings: z.array(Finding),
  truncated: z.boolean().default(false),
  notes: z.array(z.string()).default([]),
});
export type ParseResult = z.infer<typeof ParseResult>;

// ---------------------------------------------------------------------------
// Per-tool parsers
// ---------------------------------------------------------------------------

function asStr(v: unknown, fallback = ""): string {
  return typeof v === "string" ? v : fallback;
}

function asNum(v: unknown): number | undefined {
  return typeof v === "number" && Number.isFinite(v) ? v : undefined;
}

function asArr(v: unknown): unknown[] {
  return Array.isArray(v) ? v : [];
}

function mapSeverity(raw: unknown): Severity | undefined {
  if (typeof raw !== "string") return undefined;
  const s = raw.toLowerCase();
  if (s === "critical") return "critical";
  if (s === "error" || s === "high") return "high";
  if (s === "warning" || s === "medium") return "medium";
  if (s === "low") return "low";
  if (s === "info" || s === "informational" || s === "note") return "info";
  return undefined;
}

function extractCweStrings(value: unknown): string[] | undefined {
  // CWEs surface in lots of shapes: ["CWE-79", ...], "CWE-79",
  // [{ id: "CWE-79" }], "79", etc. We normalize to the "CWE-<n>" form
  // when possible and otherwise just preserve the raw string.
  const acc: string[] = [];
  const visit = (v: unknown): void => {
    if (typeof v === "string") {
      acc.push(/^CWE-/i.test(v) ? v : `CWE-${v.replace(/^CWE-?/i, "")}`);
    } else if (typeof v === "number") {
      acc.push(`CWE-${v}`);
    } else if (Array.isArray(v)) {
      v.forEach(visit);
    } else if (v && typeof v === "object") {
      const obj = v as Record<string, unknown>;
      if ("id" in obj) visit(obj.id);
      else if ("cwe_id" in obj) visit(obj.cwe_id);
    }
  };
  visit(value);
  return acc.length > 0 ? acc : undefined;
}

// -- semgrep ----------------------------------------------------------------

function parseSemgrep(raw: unknown): ParseResult {
  const obj = (raw ?? {}) as Record<string, unknown>;
  const results = asArr(obj.results);
  const findings: Finding[] = results.map((r) => {
    const rec = r as Record<string, unknown>;
    const start = rec.start as Record<string, unknown> | undefined;
    const end = rec.end as Record<string, unknown> | undefined;
    const extra = (rec.extra ?? {}) as Record<string, unknown>;
    const metadata = (extra.metadata ?? {}) as Record<string, unknown>;
    return {
      tool: "semgrep",
      ruleId: asStr(rec.check_id, "unknown"),
      severity: mapSeverity(extra.severity ?? metadata.severity),
      message: asStr(extra.message ?? rec.check_id, ""),
      path: asStr(rec.path, ""),
      startLine: asNum(start?.line),
      endLine: asNum(end?.line),
      cwe: extractCweStrings(metadata.cwe ?? metadata.cwes),
    };
  });
  return ParseResult.parse({ tool: "semgrep", findings });
}

// -- gitleaks ---------------------------------------------------------------

function parseGitleaks(raw: unknown): ParseResult {
  const arr = asArr(raw);
  const findings: Finding[] = arr.map((r) => {
    const rec = r as Record<string, unknown>;
    return {
      tool: "gitleaks",
      ruleId: asStr(rec.RuleID ?? rec.Description, "unknown"),
      severity: "high" as const,
      message: asStr(rec.Description ?? rec.RuleID, "secret detected"),
      path: asStr(rec.File, ""),
      startLine: asNum(rec.StartLine),
      endLine: asNum(rec.EndLine),
    };
  });
  return ParseResult.parse({ tool: "gitleaks", findings });
}

// -- osv-scanner ------------------------------------------------------------

function parseOsvScanner(raw: unknown): ParseResult {
  const obj = (raw ?? {}) as Record<string, unknown>;
  const findings: Finding[] = [];
  for (const result of asArr(obj.results)) {
    const r = result as Record<string, unknown>;
    const source = (r.source ?? {}) as Record<string, unknown>;
    const path = asStr(source.path, "");
    for (const pkg of asArr(r.packages)) {
      const p = pkg as Record<string, unknown>;
      const pkgInfo = (p.package ?? {}) as Record<string, unknown>;
      for (const v of asArr(p.vulnerabilities)) {
        const vuln = v as Record<string, unknown>;
        const aliases = asArr(vuln.aliases).filter(
          (a): a is string => typeof a === "string",
        );
        findings.push({
          tool: "osv-scanner",
          ruleId: asStr(vuln.id, aliases[0] ?? "unknown"),
          severity: undefined,
          message: `${asStr(pkgInfo.name, "?")}@${asStr(pkgInfo.version, "?")}: ${asStr(vuln.summary, asStr(vuln.id))}`,
          path,
          cwe: undefined,
        });
      }
    }
  }
  return ParseResult.parse({ tool: "osv-scanner", findings });
}

// -- trivy-fs ---------------------------------------------------------------

function parseTrivy(raw: unknown): ParseResult {
  const obj = (raw ?? {}) as Record<string, unknown>;
  const findings: Finding[] = [];
  for (const result of asArr(obj.Results)) {
    const r = result as Record<string, unknown>;
    const target = asStr(r.Target, "");
    for (const vuln of asArr(r.Vulnerabilities)) {
      const v = vuln as Record<string, unknown>;
      findings.push({
        tool: "trivy-fs",
        ruleId: asStr(v.VulnerabilityID, "unknown"),
        severity: mapSeverity(v.Severity),
        message: `${asStr(v.PkgName, "?")}@${asStr(v.InstalledVersion, "?")}: ${asStr(v.Title, asStr(v.Description))}`,
        path: target,
        cwe: extractCweStrings(v.CweIDs),
      });
    }
  }
  return ParseResult.parse({ tool: "trivy-fs", findings });
}

// -- bandit -----------------------------------------------------------------

function parseBandit(raw: unknown): ParseResult {
  const obj = (raw ?? {}) as Record<string, unknown>;
  const results = asArr(obj.results);
  const findings: Finding[] = results.map((r) => {
    const rec = r as Record<string, unknown>;
    return {
      tool: "bandit",
      ruleId: asStr(rec.test_id, "unknown"),
      severity: mapSeverity(rec.issue_severity),
      message: asStr(rec.issue_text, ""),
      path: asStr(rec.filename, ""),
      startLine: asNum(rec.line_number),
      cwe: extractCweStrings(rec.cwe),
    };
  });
  return ParseResult.parse({ tool: "bandit", findings });
}

// -- gosec ------------------------------------------------------------------

function parseGosec(raw: unknown): ParseResult {
  const obj = (raw ?? {}) as Record<string, unknown>;
  const issues = asArr(obj.Issues);
  const findings: Finding[] = issues.map((r) => {
    const rec = r as Record<string, unknown>;
    return {
      tool: "gosec",
      ruleId: asStr(rec.rule_id, "unknown"),
      severity: mapSeverity(rec.severity),
      message: asStr(rec.details, ""),
      path: asStr(rec.file, ""),
      startLine: asNum(parseInt(asStr(rec.line, ""), 10)),
      cwe: extractCweStrings(rec.cwe),
    };
  });
  return ParseResult.parse({ tool: "gosec", findings });
}

// -- cargo-audit ------------------------------------------------------------

function parseCargoAudit(raw: unknown): ParseResult {
  const obj = (raw ?? {}) as Record<string, unknown>;
  const vulnerabilities = (obj.vulnerabilities ?? {}) as Record<
    string,
    unknown
  >;
  const list = asArr(vulnerabilities.list);
  const findings: Finding[] = list.map((r) => {
    const rec = r as Record<string, unknown>;
    const advisory = (rec.advisory ?? {}) as Record<string, unknown>;
    const pkg = (rec.package ?? {}) as Record<string, unknown>;
    return {
      tool: "cargo-audit",
      ruleId: asStr(advisory.id, "unknown"),
      severity: undefined,
      message: `${asStr(pkg.name, "?")}@${asStr(pkg.version, "?")}: ${asStr(advisory.title, "")}`,
      path: "Cargo.lock",
    };
  });
  return ParseResult.parse({ tool: "cargo-audit", findings });
}

// -- pip-audit --------------------------------------------------------------

function parsePipAudit(raw: unknown): ParseResult {
  const obj = (raw ?? {}) as Record<string, unknown>;
  const deps = asArr(obj.dependencies);
  const findings: Finding[] = [];
  for (const dep of deps) {
    const d = dep as Record<string, unknown>;
    for (const v of asArr(d.vulns)) {
      const vuln = v as Record<string, unknown>;
      findings.push({
        tool: "pip-audit",
        ruleId: asStr(vuln.id, "unknown"),
        severity: undefined,
        message: `${asStr(d.name, "?")}@${asStr(d.version, "?")}: ${asStr(vuln.description, asStr(vuln.id))}`,
        path: "requirements.txt",
      });
    }
  }
  return ParseResult.parse({ tool: "pip-audit", findings });
}

// -- npm-audit --------------------------------------------------------------

function parseNpmAudit(raw: unknown): ParseResult {
  const obj = (raw ?? {}) as Record<string, unknown>;
  const vulns = (obj.vulnerabilities ?? {}) as Record<string, unknown>;
  const findings: Finding[] = [];
  for (const [pkgName, info] of Object.entries(vulns)) {
    const v = info as Record<string, unknown>;
    const via = asArr(v.via);
    // Each entry in `via` is either a string (a dependency name) or a
    // detailed object describing the underlying advisory.
    for (const entry of via) {
      if (typeof entry === "string") continue;
      const adv = entry as Record<string, unknown>;
      findings.push({
        tool: "npm-audit",
        ruleId: asStr(adv.source ?? adv.url ?? adv.title, "unknown"),
        severity: mapSeverity(adv.severity ?? v.severity),
        message: `${pkgName}: ${asStr(adv.title, "")}`,
        path: "package.json",
        cwe: extractCweStrings(adv.cwe ?? adv.cwes),
      });
    }
  }
  return ParseResult.parse({ tool: "npm-audit", findings });
}

// -- trufflehog (NDJSON) ----------------------------------------------------

function parseTrufflehog(rawText: string): ParseResult {
  const lines = rawText
    .split(/\r?\n/)
    .map((l) => l.trim())
    .filter((l) => l.length > 0);
  const findings: Finding[] = [];
  for (const line of lines) {
    try {
      const rec = JSON.parse(line) as Record<string, unknown>;
      const sourceMeta = (rec.SourceMetadata ?? {}) as Record<string, unknown>;
      const data = (sourceMeta.Data ?? {}) as Record<string, unknown>;
      const fsBlock = (data.Filesystem ?? {}) as Record<string, unknown>;
      findings.push({
        tool: "trufflehog",
        ruleId: asStr(rec.DetectorName, "unknown"),
        severity: "high",
        message: `${asStr(rec.DetectorName, "secret")}: ${asStr(rec.Raw ?? "", "(redacted)").slice(0, 80)}`,
        path: asStr(fsBlock.file, ""),
        startLine: asNum(fsBlock.line),
      });
    } catch {
      // Skip lines that aren't valid JSON.
    }
  }
  return ParseResult.parse({ tool: "trufflehog", findings });
}

// ---------------------------------------------------------------------------
// Dispatcher
// ---------------------------------------------------------------------------

export type Tool =
  | "semgrep"
  | "gitleaks"
  | "osv-scanner"
  | "trivy-fs"
  | "bandit"
  | "gosec"
  | "cargo-audit"
  | "pip-audit"
  | "npm-audit"
  | "trufflehog";

/**
 * Parse a scanner's raw output and return a normalized ParseResult.
 *
 * Most parsers consume parsed JSON. TruffleHog emits NDJSON, so its
 * parser handles the raw string itself.
 */
export function parseScannerOutput(tool: Tool, rawText: string): ParseResult {
  if (tool === "trufflehog") {
    return parseTrufflehog(rawText);
  }
  let raw: unknown;
  try {
    raw = JSON.parse(rawText);
  } catch {
    return ParseResult.parse({
      tool,
      findings: [],
      notes: [`Failed to parse ${tool} output as JSON`],
    });
  }
  switch (tool) {
    case "semgrep":
      return parseSemgrep(raw);
    case "gitleaks":
      return parseGitleaks(raw);
    case "osv-scanner":
      return parseOsvScanner(raw);
    case "trivy-fs":
      return parseTrivy(raw);
    case "bandit":
      return parseBandit(raw);
    case "gosec":
      return parseGosec(raw);
    case "cargo-audit":
      return parseCargoAudit(raw);
    case "pip-audit":
      return parsePipAudit(raw);
    case "npm-audit":
      return parseNpmAudit(raw);
  }
}

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

function parseArgs(argv: string[]): { tool: string; input: string } {
  let tool = "";
  let input = "";
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--tool") {
      tool = argv[++i] ?? "";
    } else if (a === "--input") {
      input = argv[++i] ?? "";
    }
  }
  if (!tool || !input) {
    throw new Error("Usage: bun parse-results.ts --tool <tool> --input <path>");
  }
  return { tool, input };
}

const SUPPORTED: Tool[] = [
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

function isCli(): boolean {
  // Bun and Node both set import.meta.url to the executing module.
  // The "main module" check is environment-specific, so we just look at
  // process.argv[1] which should be the script path when invoked directly.
  if (typeof process === "undefined") return false;
  const entry = process.argv[1] ?? "";
  return /parse-results\.(ts|js)$/.test(entry);
}

if (isCli()) {
  const { tool, input } = parseArgs(process.argv.slice(2));
  if (!SUPPORTED.includes(tool as Tool)) {
    console.error(`Unknown tool "${tool}". Supported: ${SUPPORTED.join(", ")}`);
    process.exit(2);
  }
  const raw = readFileSync(input, "utf-8");
  const result = parseScannerOutput(tool as Tool, raw);
  process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
}
