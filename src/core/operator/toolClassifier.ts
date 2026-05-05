import type { ToolClassification } from "./types";

/**
 * Binary, rules-only tool classifier.
 *
 * Every tool call resolves to `safe` or `destructive`. The dispatch order
 * matters — dangerous patterns are checked *before* safe allowlists so
 * obfuscated commands like `dig example.com; rm -rf /tmp` cannot be downgraded
 * by their first token. That precedence is the single most important safety
 * property of this module.
 *
 * No LLM path, no cache, no timeouts — regex matching is microseconds.
 * Anything outside the narrow safe allowlist defaults to destructive.
 */

// ---------------------------------------------------------------------------
// Context
// ---------------------------------------------------------------------------

export interface ToolClassificationContext {
  toolName: string;
  args: Record<string, unknown>;
}

// ---------------------------------------------------------------------------
// Pattern tables
// ---------------------------------------------------------------------------

/**
 * Patterns that unambiguously indicate a dangerous follow-on command or
 * file/credential access. Any match forces `destructive` immediately,
 * before the allowlist is consulted.
 *
 * Command substitution on its own (`` `…` `` / `$(…)`) is intentionally
 * *not* in this list — pentest tooling legitimately uses it for things
 * like timestamped output paths (`OUT=/tmp/ffuf-$(date +%s).json`). It is
 * handled by `SHELL_CONTROL_OPERATORS` below and still escalates to
 * destructive; substituted content that is actually dangerous (rm,
 * /etc/passwd, SQL drops, pipe-to-shell) matches one of the rules here
 * and remains destructive.
 */
const DANGEROUS_PATTERNS = [
  // Command injection — shell metacharacters chained with a dangerous tool.
  /;\s*(rm|cat|wget|curl|nc|bash|sh|python|perl|ruby)\b/i,
  /\|\s*(bash|sh|nc)\b/i,

  // SQL injection with dangerous payloads
  /;\s*DROP\s+TABLE/i,
  /;\s*DELETE\s+FROM/i,
  /;\s*UPDATE\s+.*SET/i,
  /;\s*INSERT\s+INTO/i,
  /UNION\s+SELECT.*FROM\s+information_schema/i,

  // Arbitrary file system access
  /\/etc\/passwd/,
  /\/etc\/shadow/,
  /\.\.\/.*\.\.\//, // Path traversal
];

/**
 * Destructive command verbs. Shell-side state-changing operations always
 * classify as destructive regardless of what comes before them.
 */
const DESTRUCTIVE_COMMAND_PATTERNS = [
  /\brm\s+(-[rfRiIvV-]*\s+)*[./~\w-]+/i,
  /\b(mv|cp|chmod|chown|truncate|dd)\b/i,
  />\s*[./~\w-]+/, // stdout/stderr redirect into a file
  /\b(curl|http)\b.*\s-X\s*(PUT|PATCH|DELETE)\b/i,
  /\bsqlmap\b.*\s--dump\b/i,
];

/**
 * Shell control operators. When present, the command becomes too opaque for
 * a safe-allowlist match; we force destructive so the operator can review it.
 * Actually dangerous inner content still hits `DANGEROUS_PATTERNS` first.
 */
const SHELL_CONTROL_OPERATORS = [
  /(^|[^|])\|([^|]|$)/, // pipe (not `||`)
  /&&/,
  /\|\|/,
  /(^|[^&])&([^&]|$)/, // background separator (not `&&`)
  /;/,
  />/,
  /<\s*[./~\w-]+/,
  /`[^`]+`/, // backtick command substitution
  /\$\([^)]+\)/, // $() command substitution
];

/**
 * Intrusive scanners and fuzzers. Anything that generates unbounded
 * interaction with a target or runs active exploitation tooling.
 */
const INTRUSIVE_COMMANDS = [
  /\b(sqlmap|hydra|nikto|dirb|gobuster|ffuf|wfuzz|dirsearch)\b/i,
  /\bnmap\b.*(-p-|-sC|--script|--min-rate|-A|-O)/i,
];

/**
 * Safe command allowlist. Matches only after all dangerous-pattern checks
 * have failed. Everything else falls through to destructive.
 *
 * `cat` is intentionally absent: path-prefix blocklists cannot enumerate
 * every sensitive file (~/.ssh/id_rsa, /proc/self/environ, .env, credential
 * stores), so arbitrary file reads stay destructive and require approval.
 */
const SAFE_COMMANDS = [
  /^dig(\s|$)/i,
  /^whois(\s|$)/i,
  /^host(\s|$)/i,
  /^nslookup(\s|$)/i,
  /^pwd$/i,
  /^ls(\s+-[a-zA-Z]+)*(\s+[./~\w-]+)?$/i,
  /^curl\s+(-I|--head)(\s|$)/i,
  /^openssl\s+s_client(\s|$)/i,
  // `-sC` is intentionally excluded — it is an alias for `--script=default`
  // which runs NSE scripts and is caught by `INTRUSIVE_COMMANDS`.
  /^nmap\s+.*(-sV|--version-all)/i,
];

/**
 * Tools that never interact with the target and have no dangerous inputs.
 * These are safe by name alone — no args inspection needed.
 */
const SAFE_TOOLS = new Set<string>([
  "scratchpad",
  "analyze_scan",
  "generate_report",
  "store_plan",
  "get_plan",
  "check_testing_coverage",
  "validate_completeness",
  "record_test_result",
  "update_attack_surface",
  "record_credential",
  "update_endpoint_status",
  "record_verified_finding",
  "get_attack_surface",
  "enumerate_endpoints",
  "browser_screenshot",
  "browser_console",
]);

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

/**
 * Classify a tool call as `safe` or `destructive`.
 *
 * Order of checks is load-bearing:
 *   1. Tool-specific rules (http_request, execute_command, POC content).
 *   2. Safe-by-name allowlist.
 *   3. Default destructive.
 */
export function classifyToolCall(
  ctx: ToolClassificationContext,
): ToolClassification {
  const { toolName, args } = ctx;

  if (toolName === "http_request") {
    return classifyHttpRequest(args);
  }

  if (toolName === "execute_command") {
    return classifyExecuteCommand(args);
  }

  if (
    toolName === "document_finding" ||
    toolName === "document_vulnerability"
  ) {
    const pocContent = String(args.pocContent || "");
    if (containsDangerousPatterns(pocContent)) {
      return destructive("POC content contains dangerous execution patterns");
    }
    // POC docs still invoke execution-capable content; treat conservatively.
    return destructive(
      "Documented finding may invoke exploitation and requires review",
    );
  }

  if (SAFE_TOOLS.has(toolName)) {
    return safe(`${toolName} is read-only / local state only`);
  }

  return destructive(`${toolName} is not in the safe allowlist`);
}

// ---------------------------------------------------------------------------
// Tool-specific rules
// ---------------------------------------------------------------------------

function classifyHttpRequest(
  args: Record<string, unknown>,
): ToolClassification {
  const method = String(args.method || "GET").toUpperCase();
  const body = String(args.body || "");
  const url = String(args.url || "");
  const combined = body + " " + url;

  // Dangerous payloads anywhere in body or URL = destructive.
  if (containsDangerousPatterns(combined)) {
    return destructive(
      "HTTP request contains potentially dangerous payload patterns",
    );
  }

  // Common probing payloads (SQLi/XSS/SSTI markers) = destructive.
  if (containsProbingPatterns(combined)) {
    return destructive("HTTP request contains injection-style payload markers");
  }

  // State-changing methods = destructive by default. `POST /login` is the
  // single most state-changing call most webapps accept; auto-approving it
  // was the regression that Josh flagged on #706 review.
  if (method !== "GET" && method !== "HEAD" && method !== "OPTIONS") {
    return destructive(
      `HTTP ${method} is state-changing and requires approval`,
    );
  }

  return safe(`HTTP ${method} request with no attack markers`);
}

function classifyExecuteCommand(
  args: Record<string, unknown>,
): ToolClassification {
  const command = normalizeCommand(String(args.command || ""));

  if (!command) {
    return destructive("Empty or missing shell command");
  }

  // Escalation checks run before the safe allowlist so first-token commands
  // can't mask chained danger.
  if (containsDangerousPatterns(command)) {
    return destructive("Command contains dangerous execution patterns");
  }

  if (containsDestructiveCommandPatterns(command)) {
    return destructive("Command contains destructive or state-changing verbs");
  }

  if (matchesAny(command, INTRUSIVE_COMMANDS)) {
    return destructive("Command runs an intrusive scanner or fuzzer");
  }

  if (containsShellControlOperators(command)) {
    return destructive(
      "Command uses shell control operators and requires review",
    );
  }

  if (matchesAny(command, SAFE_COMMANDS)) {
    return safe("Command is passive / low-risk reconnaissance");
  }

  return destructive("Shell command is not in the safe allowlist");
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * Probing patterns — injection markers in HTTP payloads. Currently treated
 * as destructive; kept as a distinct list so future policy can soften if
 * needed (e.g. "probing without `requireApproval`" for known-safe targets).
 */
const PROBING_PATTERNS = [
  /['"]?\s*(OR|AND)\s+['"]?\d+['"]?\s*=\s*['"]?\d+/i,
  /['"]?\s*;\s*--/,
  /UNION\s+SELECT/i,
  /<script\b/i,
  /javascript:/i,
  /on\w+\s*=/i,
  /\{\{.*\}\}/,
  /\$\{.*\}/,
  /<%= .* %>/,
];

function containsDangerousPatterns(content: string): boolean {
  return DANGEROUS_PATTERNS.some((p) => p.test(content));
}

function containsProbingPatterns(content: string): boolean {
  return PROBING_PATTERNS.some((p) => p.test(content));
}

function containsDestructiveCommandPatterns(content: string): boolean {
  return DESTRUCTIVE_COMMAND_PATTERNS.some((p) => p.test(content));
}

function containsShellControlOperators(content: string): boolean {
  return SHELL_CONTROL_OPERATORS.some((p) => p.test(content));
}

function matchesAny(command: string, patterns: RegExp[]): boolean {
  return patterns.some((p) => p.test(command));
}

function normalizeCommand(command: string): string {
  return command.trim().replace(/\s+/g, " ");
}

function safe(reasoning: string): ToolClassification {
  return { intent: "safe", reasoning };
}

function destructive(reasoning: string): ToolClassification {
  return { intent: "destructive", reasoning };
}

// ---------------------------------------------------------------------------
// Convenience accessors
// ---------------------------------------------------------------------------

export function getClassificationReason(
  ctx: ToolClassificationContext,
): string {
  return classifyToolCall(ctx).reasoning;
}
