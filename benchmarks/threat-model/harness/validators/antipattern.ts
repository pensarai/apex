/**
 * Threat Model Benchmark — Anti-Pattern Validator
 *
 * Detects anti-patterns that the skill prompt explicitly forbids.
 * 5 automated checks + 1 optional LLM check.
 */

import type {
  ParsedThreatModel,
  AntiPatternScore,
  BehavioralMetrics,
  ToolCallRecord,
} from "../types";

// ---------------------------------------------------------------------------
// STRIDE Category Names
// ---------------------------------------------------------------------------

const STRIDE_CATEGORIES = [
  "spoofing",
  "tampering",
  "repudiation",
  "information disclosure",
  "denial of service",
  "elevation of privilege",
];

const SOURCE_EXTS =
  /\.(ts|tsx|py|go|rs|php|java|rb|js|jsx|vue|svelte|c|cpp|h|cs)$/;

// ---------------------------------------------------------------------------
// Automated Checks
// ---------------------------------------------------------------------------

/** A-01: No STRIDE categories used as organizing headers */
function checkNoStride(parsed: ParsedThreatModel): number {
  const headings = [
    ...parsed.sectionsFound,
    ...parsed.attackPaths.map((ap) => ap.title),
  ];
  const headingText = headings.join(" ").toLowerCase();

  for (const cat of STRIDE_CATEGORIES) {
    // Only flag if used as a heading/organizing principle, not as inline mention
    if (
      parsed.sectionsFound.some((s) =>
        s.toLowerCase().includes(cat),
      )
    ) {
      return 0;
    }
  }

  // Also check if multiple STRIDE terms appear as AP title prefixes
  let strideCount = 0;
  for (const ap of parsed.attackPaths) {
    const titleLower = ap.title.toLowerCase();
    if (STRIDE_CATEGORIES.some((c) => titleLower.startsWith(c))) {
      strideCount++;
    }
  }
  // If more than half of attack paths are named after STRIDE categories, fail
  if (
    parsed.attackPaths.length > 0 &&
    strideCount / parsed.attackPaths.length > 0.5
  ) {
    return 0;
  }

  return 1;
}

/** A-02: No DREAD scoring */
function checkNoDread(parsed: ParsedThreatModel): number {
  const dreadTerms = [
    "damage potential",
    "reproducibility",
    "exploitability",
    "affected users",
    "discoverability",
    "dread score",
    "dread rating",
  ];
  const rawLower = parsed.raw.toLowerCase();
  for (const term of dreadTerms) {
    if (rawLower.includes(term)) return 0;
  }
  return 1;
}

/** A-03: No CWE numbers as section headers or organizing principle */
function checkNoCweAsAnalysis(parsed: ParsedThreatModel): number {
  // CWE numbers in ## or ### headings = bad
  const headings = parsed.sectionsFound.join(" ");
  if (/CWE-\d+/i.test(headings)) return 0;

  // CWE numbers as AP titles (not supplementary) = bad
  for (const ap of parsed.attackPaths) {
    // If the title IS a CWE reference (not just contains one supplementarily)
    if (/^CWE-\d+/i.test(ap.title.trim())) return 0;
  }

  return 1;
}

/** A-04: Source code was actually read (from trace) */
function checkSourceCodeRead(trace: ToolCallRecord[]): number {
  const readCalls = trace.filter((t) => t.name === "read_file");
  const sourcePaths = readCalls
    .map((t) => (t.args.file_path ?? t.args.path) as string | undefined)
    .filter((p): p is string => p !== undefined)
    .filter((p) => SOURCE_EXTS.test(p));

  const uniqueSourceFiles = new Set(sourcePaths);

  // Require at least 5 unique source files to be read
  return uniqueSourceFiles.size >= 5 ? 1 : 0;
}

/** A-05: No user clarification requested */
function checkNoUserClarification(parsed: ParsedThreatModel): number {
  const clarificationPhrases = [
    "please clarify",
    "could you tell me",
    "can you provide",
    "I need more information",
    "would you like me to",
    "shall I",
    "do you want me to",
    "please let me know",
  ];

  const rawLower = parsed.raw.toLowerCase();
  for (const phrase of clarificationPhrases) {
    if (rawLower.includes(phrase)) return 0;
  }
  return 1;
}

// ---------------------------------------------------------------------------
// Positive Depth Checks (measure good practices, not just absence of bad)
// ---------------------------------------------------------------------------

/** A-06: Mechanism steps reference code (file paths, inline code) */
function checkMechanismCodeRefs(parsed: ParsedThreatModel): number {
  if (parsed.attackPaths.length === 0) return 0;
  const codeRefPattern = /`[^`]+`|[a-zA-Z_]+\.[a-zA-Z]{1,4}(?::\d+)?/;
  let withRefs = 0;
  for (const ap of parsed.attackPaths) {
    if (ap.mechanism.some((step) => codeRefPattern.test(step))) withRefs++;
  }
  return withRefs / parsed.attackPaths.length;
}

/** A-07: Attack path entry points are specific (route, file, flag — not vague labels) */
function checkEntryPointSpecificity(parsed: ParsedThreatModel): number {
  if (parsed.attackPaths.length === 0) return 0;
  const specificPattern = /\/[a-z]|\.ts|\.py|\.go|\.rs|\.php|--[a-z]/i;
  let specific = 0;
  for (const ap of parsed.attackPaths) {
    if (specificPattern.test(ap.entryPoint)) specific++;
  }
  return specific / parsed.attackPaths.length;
}

/** A-08: Pentest guidance includes concrete techniques (tools, payloads, commands) */
function checkPentestGuidanceConcreteness(parsed: ParsedThreatModel): number {
  if (parsed.attackPaths.length === 0) return 0;
  const concretePattern =
    /curl |sqlmap|burp|payload|`[^`]+`|--[a-z]|UNION|SELECT|<script|\.\.\/|%00|nmap|nikto|ffuf|wfuzz|hydra|john/i;
  let concrete = 0;
  for (const ap of parsed.attackPaths) {
    if (concretePattern.test(ap.pentestGuidance)) concrete++;
  }
  return concrete / parsed.attackPaths.length;
}

// ---------------------------------------------------------------------------
// Main Validator
// ---------------------------------------------------------------------------

export function validateAntiPatterns(
  parsed: ParsedThreatModel,
  trace: ToolCallRecord[],
): AntiPatternScore {
  const checks: Record<string, number> = {
    // Negative checks (avoid bad patterns)
    no_stride: checkNoStride(parsed),
    no_dread: checkNoDread(parsed),
    no_cwe_as_analysis: checkNoCweAsAnalysis(parsed),
    source_code_read: checkSourceCodeRead(trace),
    no_user_clarification: checkNoUserClarification(parsed),
    // Positive depth checks (demonstrate good analysis)
    mechanism_code_refs: checkMechanismCodeRefs(parsed),
    entry_point_specificity: checkEntryPointSpecificity(parsed),
    pentest_guidance_concrete: checkPentestGuidanceConcreteness(parsed),
  };

  const values = Object.values(checks);
  const score = values.reduce((a, b) => a + b, 0) / values.length;

  return { score, checks };
}
