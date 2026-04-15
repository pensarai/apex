/**
 * Threat Model Benchmark — Anti-Pattern Validator (v3)
 *
 * 5 negative checks (avoid bad patterns) + 3 positive depth checks.
 * Uses weighted scoring to emphasize discriminating checks.
 */

import type {
  ParsedThreatModel,
  AntiPatternScore,
  ToolCallRecord,
} from "../types";

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
// Negative Checks (avoid bad patterns)
// ---------------------------------------------------------------------------

/** No STRIDE categories used as organizing headers */
function checkNoStride(parsed: ParsedThreatModel): number {
  for (const cat of STRIDE_CATEGORIES) {
    if (parsed.sectionsFound.some((s) => s.toLowerCase().includes(cat))) {
      return 0;
    }
  }
  let strideCount = 0;
  for (const ap of parsed.attackPaths) {
    if (STRIDE_CATEGORIES.some((c) => ap.title.toLowerCase().startsWith(c))) {
      strideCount++;
    }
  }
  if (parsed.attackPaths.length > 0 && strideCount / parsed.attackPaths.length > 0.5) {
    return 0;
  }
  return 1;
}

/** No DREAD as a scoring framework (individual terms like "exploitability" are fine) */
function checkNoDread(parsed: ParsedThreatModel): number {
  const rawLower = parsed.raw.toLowerCase();
  const dreadFramework = [
    "dread score",
    "dread rating",
    "dread analysis",
    "dread methodology",
    "dread framework",
  ];
  for (const term of dreadFramework) {
    if (rawLower.includes(term)) return 0;
  }
  // Check for all 5 DREAD components appearing together (as a scoring table)
  if (
    /damage\s*potential.*reproducibility.*exploitability.*affected\s*users.*discoverability/is.test(
      rawLower,
    )
  ) {
    return 0;
  }
  return 1;
}

/** No CWE numbers as section headers or organizing principle */
function checkNoCweAsAnalysis(parsed: ParsedThreatModel): number {
  const headings = parsed.sectionsFound.join(" ");
  if (/CWE-\d+/i.test(headings)) return 0;
  for (const ap of parsed.attackPaths) {
    if (/^CWE-\d+/i.test(ap.title.trim())) return 0;
  }
  return 1;
}

/** Source code was actually read (>= 8 unique source files from trace) */
function checkSourceCodeRead(trace: ToolCallRecord[]): number {
  const readCalls = trace.filter((t) => t.name === "read_file");
  const sourcePaths = readCalls
    .map((t) => (t.args.file_path ?? t.args.path) as string | undefined)
    .filter((p): p is string => p !== undefined)
    .filter((p) => SOURCE_EXTS.test(p));
  const unique = new Set(sourcePaths);
  // Graduated: 8+ = 1.0, 5-7 = 0.7, <5 = 0.3
  if (unique.size >= 8) return 1;
  if (unique.size >= 5) return 0.7;
  return 0.3;
}

/** No user clarification requested */
function checkNoUserClarification(parsed: ParsedThreatModel): number {
  const phrases = [
    "please clarify", "could you tell me", "can you provide",
    "I need more information", "would you like me to",
    "shall I", "do you want me to", "please let me know",
  ];
  const rawLower = parsed.raw.toLowerCase();
  for (const phrase of phrases) {
    if (rawLower.includes(phrase)) return 0;
  }
  return 1;
}

// ---------------------------------------------------------------------------
// Positive Depth Checks (measure good practices)
// ---------------------------------------------------------------------------

/** Mechanism steps reference code (file paths, inline code, line numbers) */
function checkMechanismCodeRefs(parsed: ParsedThreatModel): number {
  if (parsed.attackPaths.length === 0) return 0;
  // Require actual file paths or backtick code — not just any dot-access
  const codeRefPattern = /`[^`]{3,}`|[a-zA-Z_]+\/[a-zA-Z_]+\.[a-zA-Z]{1,4}|line\s+\d+/i;
  let withRefs = 0;
  for (const ap of parsed.attackPaths) {
    if (ap.mechanism.some((step) => codeRefPattern.test(step))) withRefs++;
  }
  return withRefs / parsed.attackPaths.length;
}

/** Entry points are specific — supports REST, GraphQL, gRPC, CLI, events */
function checkEntryPointSpecificity(parsed: ParsedThreatModel): number {
  if (parsed.attackPaths.length === 0) return 0;
  const specificPattern =
    /\/[a-z]|\.ts|\.py|\.go|\.rs|\.php|\.java|--[a-z]|mutation\s|query\s|subscription\s|grpc\.|\.proto|topic:|queue:|event\.|handler|endpoint|route/i;
  let specific = 0;
  for (const ap of parsed.attackPaths) {
    if (specificPattern.test(ap.entryPoint)) specific++;
  }
  return specific / parsed.attackPaths.length;
}

/** Pentest guidance includes concrete techniques (tools, payloads, commands) */
function checkPentestGuidanceConcreteness(parsed: ParsedThreatModel): number {
  if (parsed.attackPaths.length === 0) return 0;
  const concretePattern =
    /curl |sqlmap|burp|payload|`[^`]+`|--[a-z]|UNION|SELECT|<script|\.\.\/|%00|%27|nmap|nikto|ffuf|wfuzz|hydra|john|POST\s+\/|GET\s+\//i;
  let concrete = 0;
  for (const ap of parsed.attackPaths) {
    if (concretePattern.test(ap.pentestGuidance)) concrete++;
  }
  return concrete / parsed.attackPaths.length;
}

// ---------------------------------------------------------------------------
// Main Validator
// ---------------------------------------------------------------------------

/** Check weights — positive depth checks weighted higher than easy negative checks */
const CHECK_WEIGHTS: Record<string, number> = {
  // Negative checks (low weight — usually pass)
  no_stride: 0.08,
  no_dread: 0.08,
  no_cwe_as_analysis: 0.08,
  no_user_clarification: 0.06,
  // Positive depth checks (high weight — real variance)
  source_code_read: 0.15,
  mechanism_code_refs: 0.15,
  entry_point_specificity: 0.20,
  pentest_guidance_concrete: 0.20,
};

export function validateAntiPatterns(
  parsed: ParsedThreatModel,
  trace: ToolCallRecord[],
): AntiPatternScore {
  const checks: Record<string, number> = {
    no_stride: checkNoStride(parsed),
    no_dread: checkNoDread(parsed),
    no_cwe_as_analysis: checkNoCweAsAnalysis(parsed),
    no_user_clarification: checkNoUserClarification(parsed),
    source_code_read: checkSourceCodeRead(trace),
    mechanism_code_refs: checkMechanismCodeRefs(parsed),
    entry_point_specificity: checkEntryPointSpecificity(parsed),
    pentest_guidance_concrete: checkPentestGuidanceConcreteness(parsed),
  };

  // Weighted score
  let score = 0;
  for (const [key, weight] of Object.entries(CHECK_WEIGHTS)) {
    score += (checks[key] ?? 0) * weight;
  }

  return { score, checks };
}
