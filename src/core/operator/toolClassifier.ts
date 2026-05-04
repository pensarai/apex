import { z } from "zod";
import { generateObjectResponse, type AIModel } from "../ai";
import type { AIAuthConfig } from "../ai/utils";
import type {
  ClassifierMode,
  CommandIntent,
  PermissionTier,
  ToolClassification,
} from "./types";

export const COMMAND_CLASSIFIER_VERSION = "command-intent-v1";
export const DEFAULT_CLASSIFIER_TIMEOUT_MS = 1_000;
export const DEFAULT_CLASSIFIER_CACHE_TTL_MS = 10 * 60 * 1000;
export const DEFAULT_CLASSIFIER_CACHE_MAX_ENTRIES = 1_000;
export const DEFAULT_MIN_CLASSIFIER_CONFIDENCE = 0.65;

const intentTier: Record<CommandIntent, PermissionTier> = {
  passive: 1,
  active: 2,
  probing: 3,
  intrusive: 4,
  destructive: 5,
  exploit: 5,
};

const tierIntent: Record<PermissionTier, CommandIntent> = {
  1: "passive",
  2: "active",
  3: "probing",
  4: "intrusive",
  5: "exploit",
};

const LlmClassificationSchema = z.object({
  intent: z.enum([
    "passive",
    "active",
    "probing",
    "intrusive",
    "destructive",
    "exploit",
  ]),
  tier: z.union([
    z.literal(1),
    z.literal(2),
    z.literal(3),
    z.literal(4),
    z.literal(5),
  ]),
  confidence: z.number().min(0).max(1),
  reasoning: z.string().min(1).max(300),
});

type LlmClassificationOutput = z.infer<typeof LlmClassificationSchema>;

type RuleClassification = Omit<
  ToolClassification,
  | "source"
  | "classifierMode"
  | "classifierVersion"
  | "model"
  | "confidence"
  | "cacheHit"
  | "latencyMs"
>;

export interface CommandClassifierOptions {
  mode?: ClassifierMode;
  classifierModel?: AIModel;
  authConfig?: AIAuthConfig;
  timeoutMs?: number;
  p99BudgetMs?: number;
  minConfidence?: number;
  cacheTtlMs?: number;
  cacheMaxEntries?: number;
  cacheScope?: string;
  now?: () => number;
}

/**
 * Base tier mapping for each tool
 */
const TOOL_BASE_TIERS: Record<string, PermissionTier> = {
  // Tier 1 - Passive (read-only, no network to target)
  scratchpad: 1,
  document_vulnerability: 4,
  analyze_scan: 1,
  generate_report: 1,
  store_plan: 1,
  get_plan: 1,
  check_testing_coverage: 1,
  validate_completeness: 1,
  record_test_result: 1,
  // Sidebar-updating tools (UI state only, no network)
  update_attack_surface: 1,
  record_credential: 1,
  update_endpoint_status: 1,
  record_verified_finding: 1,

  // Tier 2 - Low-risk Active (light network interaction)
  http_request: 2, // Escalates based on method
  enumerate_endpoints: 2,
  get_attack_surface: 2,

  // Tier 3 - Probing (parameter testing)
  fuzz_endpoint: 3,
  test_parameter: 3,
  run_auth_subagent: 3, // Auth probing - T3 requires approval
  delegate_to_auth_subagent: 3, // Auth delegation - T3 requires approval

  // Tier 4 - Intrusive (heavy testing, shell commands)
  execute_command: 4,
  run_pentest_workflow: 4,

  // Tier 5 - Exploit (handled dynamically via content analysis)

  // Browser tools (Playwright MCP) - Operator mode only
  browser_navigate: 2, // T2 - Low-risk Active (navigation only)
  browser_screenshot: 2, // T2 - Low-risk Active (evidence capture)
  browser_console: 2, // T2 - Low-risk Active (reading console logs)
  browser_click: 3, // T3 - Probing (user interaction simulation)
  browser_fill: 3, // T3 - Probing (form filling with payloads)
  browser_evaluate: 4, // T4 - Intrusive (JavaScript execution)
};

/**
 * HTTP methods and their risk escalation
 */
const HTTP_METHOD_TIERS: Record<string, PermissionTier> = {
  GET: 2,
  HEAD: 2,
  OPTIONS: 2,
  POST: 3,
  PUT: 4,
  PATCH: 4,
  DELETE: 4,
};

/**
 * Patterns that indicate exploit-level risk (tier 5)
 */
const EXPLOIT_PATTERNS = [
  // Command injection
  /;\s*(rm|cat|wget|curl|nc|bash|sh|python|perl|ruby)\b/i,
  /\|\s*(bash|sh|nc)\b/i,
  /`[^`]+`/, // Backtick execution
  /\$\([^)]+\)/, // $() execution

  // SQL injection with dangerous payloads
  /;\s*DROP\s+TABLE/i,
  /;\s*DELETE\s+FROM/i,
  /;\s*UPDATE\s+.*SET/i,
  /;\s*INSERT\s+INTO/i,
  /UNION\s+SELECT.*FROM\s+information_schema/i,

  // File system access
  /\/etc\/passwd/,
  /\/etc\/shadow/,
  /\.\.\/.*\.\.\//, // Path traversal

  // Fetch-and-execute or suspicious remote script patterns are covered by
  // shell control operators plus command execution checks.
];

/**
 * Patterns that indicate probing-level payloads (tier 3)
 */
const PROBING_PATTERNS = [
  // Basic SQL injection probes
  /['"]?\s*(OR|AND)\s+['"]?\d+['"]?\s*=\s*['"]?\d+/i,
  /['"]?\s*;\s*--/,
  /UNION\s+SELECT/i,

  // XSS probes
  /<script\b/i,
  /javascript:/i,
  /on\w+\s*=/i,

  // Template injection
  /\{\{.*\}\}/,
  /\$\{.*\}/,
  /<%= .* %>/,
];

/**
 * Context for tool classification
 */
export interface ToolClassificationContext {
  toolName: string;
  args: Record<string, unknown>;
}

interface CacheEntry {
  result: ToolClassification;
  expiresAt: number;
}

const classificationCache = new Map<string, CacheEntry>();
const inFlightClassifications = new Map<string, Promise<ToolClassification>>();

/**
 * Classify a tool call into a permission tier
 */
export function classifyToolCall(
  ctx: ToolClassificationContext,
): PermissionTier {
  return classifyToolCallWithRules(ctx).tier;
}

export function classifyToolCallWithRules(
  ctx: ToolClassificationContext,
): ToolClassification {
  const startedAt = Date.now();
  const result = classifyWithRules(ctx);
  return {
    ...result,
    source: "rules",
    classifierMode: "rules",
    classifierVersion: COMMAND_CLASSIFIER_VERSION,
    cacheHit: false,
    latencyMs: Date.now() - startedAt,
  };
}

export async function classifyToolCallDetailed(
  ctx: ToolClassificationContext,
  options: CommandClassifierOptions = {},
): Promise<ToolClassification> {
  const startedAt = Date.now();
  const mode = options.mode ?? "rules";
  const rules = classifyToolCallWithRules(ctx);

  if (mode === "rules" || !options.classifierModel) {
    return {
      ...rules,
      classifierMode: mode,
      latencyMs: Date.now() - startedAt,
    };
  }

  const now = options.now ?? Date.now;
  const key = buildCacheKey(ctx, options);
  const cached = getCachedClassification(key, now());
  if (cached) {
    return {
      ...cached,
      cacheHit: true,
      latencyMs: Date.now() - startedAt,
    };
  }

  const existing = inFlightClassifications.get(key);
  if (existing) {
    const result = await existing;
    return {
      ...result,
      cacheHit: true,
      latencyMs: Date.now() - startedAt,
    };
  }

  const promise = classifyWithLlm(ctx, rules, options, startedAt)
    .then((result) => {
      setCachedClassification(key, result, options, now());
      return result;
    })
    .finally(() => {
      inFlightClassifications.delete(key);
    });

  inFlightClassifications.set(key, promise);
  return promise;
}

export function clearClassificationCache(): void {
  classificationCache.clear();
  inFlightClassifications.clear();
}

function classifyWithRules(ctx: ToolClassificationContext): RuleClassification {
  const { toolName, args } = ctx;
  const baseTier = TOOL_BASE_TIERS[toolName] ?? 3;

  switch (toolName) {
    case "http_request":
      return classifyHttpRequest(args, baseTier);

    case "execute_command":
      return classifyExecuteCommand(args, baseTier);

    case "fuzz_endpoint":
    case "test_parameter":
      return classifyFuzzingTool(args, baseTier);

    case "document_finding":
    case "document_vulnerability": {
      const pocContent = String(args.pocContent || "");
      if (containsExploitPatterns(pocContent)) {
        return classification(
          5,
          "exploit",
          "POC content contains exploit-level patterns",
        );
      }
      break;
    }
  }

  return classification(
    baseTier,
    tierIntent[baseTier],
    `${toolName} is classified as tier ${baseTier} by default`,
  );
}

/**
 * Classify http_request based on method and body
 */
function classifyHttpRequest(
  args: Record<string, unknown>,
  baseTier: PermissionTier,
): RuleClassification {
  let tier = baseTier;

  // Escalate based on HTTP method
  const method = String(args.method || "GET").toUpperCase();
  const methodTier = HTTP_METHOD_TIERS[method] ?? 3;
  tier = Math.max(tier, methodTier) as PermissionTier;

  // Check body/url for dangerous patterns
  const body = String(args.body || "");
  const url = String(args.url || "");
  const combined = body + url;

  if (containsExploitPatterns(combined)) {
    return classification(
      5,
      "exploit",
      "HTTP request contains potentially dangerous payload patterns",
    );
  }
  if (containsProbingPatterns(combined)) {
    tier = Math.max(tier, 3) as PermissionTier;
  }

  const intent =
    method === "PUT" || method === "PATCH" || method === "DELETE"
      ? "destructive"
      : tierIntent[tier];
  return classification(tier, intent, getHttpReason(method, baseTier, tier));
}

/**
 * Classify execute_command based on command content
 */
function classifyExecuteCommand(
  args: Record<string, unknown>,
  baseTier: PermissionTier,
): RuleClassification {
  const command = normalizeCommand(String(args.command || ""));

  if (!command) {
    return classification(
      baseTier,
      "intrusive",
      "Empty or missing shell command defaults to intrusive",
    );
  }

  // Escalation checks must run before allowlists.
  if (containsExploitPatterns(command)) {
    return classification(
      5,
      "exploit",
      "Command contains potentially dangerous patterns",
    );
  }

  if (containsDestructiveCommandPatterns(command)) {
    return classification(
      5,
      "destructive",
      "Command contains destructive or state-changing patterns",
    );
  }

  if (containsShellControlOperators(command)) {
    return classification(
      Math.max(baseTier, 4) as PermissionTier,
      "intrusive",
      "Command uses shell control operators and requires review",
    );
  }

  if (matchesCommand(command, INTRUSIVE_COMMANDS)) {
    return classification(
      4,
      "intrusive",
      "Command runs an intrusive scanner or fuzzer",
    );
  }

  if (matchesCommand(command, ACTIVE_COMMANDS)) {
    return classification(
      2,
      "active",
      "Command is light active reconnaissance",
    );
  }

  if (matchesCommand(command, PASSIVE_COMMANDS)) {
    return classification(
      1,
      "passive",
      "Command is passive local/recon activity",
    );
  }

  return classification(
    baseTier,
    tierIntent[baseTier],
    "Shell command execution defaults to intrusive unless allowlisted",
  );
}

/**
 * Classify fuzzing tools
 */
function classifyFuzzingTool(
  args: Record<string, unknown>,
  baseTier: PermissionTier,
): RuleClassification {
  // Check payloads for dangerous content
  const payloads = args.payloads as string[] | undefined;
  const values = args.values as string[] | undefined;
  const allPayloads = [...(payloads || []), ...(values || [])];

  for (const payload of allPayloads) {
    if (containsExploitPatterns(payload)) {
      return classification(5, "exploit", "Payload contains exploit patterns");
    }
  }

  return classification(
    baseTier,
    tierIntent[baseTier],
    "Fuzzing tool uses controlled payloads",
  );
}

const PASSIVE_COMMANDS = [
  /^dig(\s|$)/i,
  /^whois(\s|$)/i,
  /^host(\s|$)/i,
  /^nslookup(\s|$)/i,
  /^pwd$/i,
  /^ls(\s+-[a-zA-Z]+)*(\s+[./~\w-]+)?$/i,
  /^cat\s+([./~\w-]+)$/i,
];

const ACTIVE_COMMANDS = [
  /^curl\s+(-I|--head)(\s|$)/i,
  /^openssl\s+s_client(\s|$)/i,
  /^nmap\s+.*(-sV|-sC|--version-all)/i,
];

const INTRUSIVE_COMMANDS = [
  /\b(sqlmap|hydra|nikto|dirb|gobuster|ffuf|wfuzz|dirsearch)\b/i,
  /\bnmap\b.*(-p-|--script|--min-rate|-A|-O)/i,
];

const DESTRUCTIVE_COMMAND_PATTERNS = [
  /\brm\s+(-[rfRiIvV-]*\s+)*[./~\w-]+/i,
  /\b(mv|cp|chmod|chown|truncate|dd)\b/i,
  />\s*[./~\w-]+/,
  /\b(curl|http)\b.*\s-X\s*(PUT|PATCH|DELETE)\b/i,
  /\bsqlmap\b.*\s--dump\b/i,
];

const SHELL_CONTROL_OPERATORS = [
  /(^|[^|])\|([^|]|$)/,
  /&&/,
  /\|\|/,
  /;/,
  />/,
  /<\s*[./~\w-]+/,
];

/**
 * Check if content contains exploit-level patterns
 */
function containsExploitPatterns(content: string): boolean {
  return EXPLOIT_PATTERNS.some((pattern) => pattern.test(content));
}

/**
 * Check if content contains probing-level patterns
 */
function containsProbingPatterns(content: string): boolean {
  return PROBING_PATTERNS.some((pattern) => pattern.test(content));
}

function containsDestructiveCommandPatterns(content: string): boolean {
  return DESTRUCTIVE_COMMAND_PATTERNS.some((pattern) => pattern.test(content));
}

function containsShellControlOperators(content: string): boolean {
  return SHELL_CONTROL_OPERATORS.some((pattern) => pattern.test(content));
}

function normalizeCommand(command: string): string {
  return command.trim().replace(/\s+/g, " ");
}

function matchesCommand(command: string, patterns: RegExp[]): boolean {
  return patterns.some((pattern) => pattern.test(command));
}

function classification(
  tier: PermissionTier,
  intent: CommandIntent,
  reasoning: string,
) {
  return { tier, intent, reasoning };
}

function getHttpReason(
  method: string,
  baseTier: PermissionTier,
  tier: PermissionTier,
): string {
  if (["POST", "PUT", "PATCH", "DELETE"].includes(method)) {
    return `${method} request escalated from tier ${baseTier} to ${tier}`;
  }
  return `HTTP ${method} request classified as tier ${tier}`;
}

function buildCacheKey(
  ctx: ToolClassificationContext,
  options: CommandClassifierOptions,
): string {
  return JSON.stringify({
    classifierVersion: COMMAND_CLASSIFIER_VERSION,
    mode: options.mode ?? "rules",
    model: String(options.classifierModel ?? ""),
    minConfidence: options.minConfidence ?? DEFAULT_MIN_CLASSIFIER_CONFIDENCE,
    timeoutMs: options.timeoutMs ?? DEFAULT_CLASSIFIER_TIMEOUT_MS,
    p99BudgetMs: options.p99BudgetMs ?? DEFAULT_CLASSIFIER_TIMEOUT_MS,
    cacheScope: options.cacheScope ?? "global",
    toolName: ctx.toolName,
    args: stableValue(ctx.args),
  });
}

function stableValue(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(stableValue);
  if (value && typeof value === "object") {
    const obj = value as Record<string, unknown>;
    return Object.keys(obj)
      .sort()
      .reduce<Record<string, unknown>>((acc, key) => {
        acc[key] = stableValue(obj[key]);
        return acc;
      }, {});
  }
  return value;
}

function getCachedClassification(
  key: string,
  now: number,
): ToolClassification | null {
  const entry = classificationCache.get(key);
  if (!entry) return null;
  if (entry.expiresAt <= now) {
    classificationCache.delete(key);
    return null;
  }
  return entry.result;
}

function setCachedClassification(
  key: string,
  result: ToolClassification,
  options: CommandClassifierOptions,
  now: number,
): void {
  const maxEntries =
    options.cacheMaxEntries ?? DEFAULT_CLASSIFIER_CACHE_MAX_ENTRIES;
  if (classificationCache.size >= maxEntries) {
    const first = classificationCache.keys().next().value as string | undefined;
    if (first) classificationCache.delete(first);
  }
  classificationCache.set(key, {
    result,
    expiresAt: now + (options.cacheTtlMs ?? DEFAULT_CLASSIFIER_CACHE_TTL_MS),
  });
}

async function classifyWithLlm(
  ctx: ToolClassificationContext,
  rules: ToolClassification,
  options: CommandClassifierOptions,
  startedAt: number,
): Promise<ToolClassification> {
  const timeoutMs = Math.min(
    options.timeoutMs ?? DEFAULT_CLASSIFIER_TIMEOUT_MS,
    options.p99BudgetMs ?? DEFAULT_CLASSIFIER_TIMEOUT_MS,
  );
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), timeoutMs);
  if (typeof timeout === "object" && "unref" in timeout) timeout.unref();

  try {
    const llm = await generateObjectResponse({
      model: options.classifierModel!,
      schema: LlmClassificationSchema,
      system:
        "You classify pentest tool calls into a closed risk taxonomy. Return only schema-valid output. Never classify destructive, exploit, or intrusive behavior as lower risk.",
      prompt: buildLlmPrompt(ctx, rules),
      maxTokens: 180,
      temperature: 0,
      authConfig: options.authConfig,
      abortSignal: controller.signal,
    });
    const parsed = validateLlmClassification(llm, options);
    if (!parsed) {
      return fallbackClassification(
        rules,
        startedAt,
        "LLM classification was invalid or low confidence",
      );
    }

    const llmTier = Math.max(
      parsed.tier,
      intentTier[parsed.intent],
    ) as PermissionTier;
    const rulesPrevailed = rules.tier >= llmTier;
    const finalTier = (rulesPrevailed ? rules.tier : llmTier) as PermissionTier;
    const finalIntent = rulesPrevailed ? rules.intent : parsed.intent;

    return {
      tier: finalTier,
      intent: finalIntent,
      reasoning:
        rulesPrevailed && finalTier > llmTier
          ? `${rules.reasoning}; LLM suggested lower risk but rules guardrail prevailed`
          : parsed.reasoning,
      source: "llm",
      classifierMode: "llm",
      classifierVersion: COMMAND_CLASSIFIER_VERSION,
      model: String(options.classifierModel),
      confidence: parsed.confidence,
      cacheHit: false,
      latencyMs: Date.now() - startedAt,
    };
  } catch {
    return fallbackClassification(
      rules,
      startedAt,
      "LLM classification failed; using rules fallback",
    );
  } finally {
    clearTimeout(timeout);
  }
}

function validateLlmClassification(
  value: LlmClassificationOutput,
  options: CommandClassifierOptions,
): LlmClassificationOutput | null {
  const minConfidence =
    options.minConfidence ?? DEFAULT_MIN_CLASSIFIER_CONFIDENCE;
  if (value.confidence < minConfidence) return null;
  return value;
}

function fallbackClassification(
  rules: ToolClassification,
  startedAt: number,
  reasoning: string,
): ToolClassification {
  return {
    ...rules,
    source: "fallback",
    classifierMode: "llm",
    reasoning: `${rules.reasoning}; ${reasoning}`,
    cacheHit: false,
    latencyMs: Date.now() - startedAt,
  };
}

function buildLlmPrompt(
  ctx: ToolClassificationContext,
  rules: ToolClassification,
): string {
  return [
    "Classify this tool call for approval policy.",
    "",
    "Labels:",
    "- passive/T1: read-only, no target interaction",
    "- active/T2: light target interaction, observational",
    "- probing/T3: controlled testing or parameter probing",
    "- intrusive/T4: heavy scanning/fuzzing or likely alerts",
    "- destructive/T5: state-changing or data extraction",
    "- exploit/T5: exploitation, RCE, command injection, credential access",
    "",
    `Tool: ${ctx.toolName}`,
    `Arguments: ${JSON.stringify(stableValue(ctx.args)).slice(0, 1500)}`,
    `Rules baseline: T${rules.tier} ${rules.intent} — ${rules.reasoning}`,
  ].join("\n");
}

/**
 * Get a human-readable description of why a tool was classified at a certain tier
 */
export function getClassificationReason(
  ctx: ToolClassificationContext,
  tier: PermissionTier,
): string {
  const classification = classifyToolCallWithRules(ctx);
  if (classification.tier === tier) return classification.reasoning;
  return `Classified as tier ${tier}`;
}
