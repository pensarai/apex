import type { PermissionTier } from "./types";

/**
 * Base tier mapping for each tool
 */
const TOOL_BASE_TIERS: Record<string, PermissionTier> = {
  // Tier 1 - Passive (read-only, no network to target)
  scratchpad: 1,
  document_finding: 1,
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
  enumerate_endpoints: 2,
  get_attack_surface: 2,

  // Tier 3 - Probing (parameter testing)
  fuzz_endpoint: 3,
  test_parameter: 3,
  run_auth_subagent: 3, // Auth probing - T3 requires approval
  delegate_to_auth_subagent: 3, // Auth delegation - T3 requires approval

  // Tier 4 - Intrusive (heavy testing, shell commands)
  execute_command: 4,

  // Tier 5 - Exploit (handled dynamically)
  create_poc: 4, // POC creation is tier 4, execution could be 5

  // Browser tools (Playwright MCP) - Operator mode only
  browser_navigate: 2, // T2 - Low-risk Active (navigation only)
  browser_screenshot: 2, // T2 - Low-risk Active (evidence capture)
  browser_console: 2, // T2 - Low-risk Active (reading console logs)
  browser_click: 3, // T3 - Probing (user interaction simulation)
  browser_fill: 3, // T3 - Probing (form filling with payloads)
  browser_evaluate: 4, // T4 - Intrusive (JavaScript execution)
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

  // Network exfiltration
  /\b(wget|curl)\s+.*\s+http/i,
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

/**
 * Classify a tool call into a permission tier
 */
export function classifyToolCall(
  ctx: ToolClassificationContext,
): PermissionTier {
  const { toolName, args } = ctx;

  // Get base tier (default to 3 for unknown tools)
  let tier = TOOL_BASE_TIERS[toolName] ?? 3;

  // Dynamic escalation based on tool and args
  switch (toolName) {
    case "execute_command":
      tier = classifyExecuteCommand(args, tier);
      break;

    case "fuzz_endpoint":
    case "test_parameter":
      tier = classifyFuzzingTool(args, tier);
      break;

    case "create_poc": {
      // If POC contains dangerous patterns, escalate
      const pocContent = String(args.script || args.content || "");
      if (containsExploitPatterns(pocContent)) {
        tier = 5;
      }
      break;
    }
  }

  return tier;
}

/**
 * Classify execute_command based on command content
 */
function classifyExecuteCommand(
  args: Record<string, unknown>,
  baseTier: PermissionTier,
): PermissionTier {
  const command = String(args.command || "");

  // Check for exploit patterns
  if (containsExploitPatterns(command)) {
    return 5;
  }

  // Certain commands are inherently more risky
  const riskyCommands = [
    "sqlmap",
    "hydra",
    "nikto",
    "dirb",
    "gobuster",
    "ffuf",
    "wfuzz",
  ];
  if (riskyCommands.some((cmd) => command.includes(cmd))) {
    return Math.max(baseTier, 4) as PermissionTier;
  }

  // Safe recon commands stay at tier 2
  const safeCommands = [
    "nmap -sV",
    "dig",
    "whois",
    "host",
    "curl -I",
    "openssl s_client",
  ];
  if (safeCommands.some((cmd) => command.startsWith(cmd.split(" ")[0]))) {
    // Still tier 4 because it's a shell command, but could be lowered in config
  }

  return baseTier;
}

/**
 * Classify fuzzing tools
 */
function classifyFuzzingTool(
  args: Record<string, unknown>,
  baseTier: PermissionTier,
): PermissionTier {
  // Check payloads for dangerous content
  const payloads = args.payloads as string[] | undefined;
  const values = args.values as string[] | undefined;
  const allPayloads = [...(payloads || []), ...(values || [])];

  for (const payload of allPayloads) {
    if (containsExploitPatterns(payload)) {
      return 5;
    }
  }

  return baseTier;
}

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

/**
 * Get a human-readable description of why a tool was classified at a certain tier
 */
export function getClassificationReason(
  ctx: ToolClassificationContext,
  tier: PermissionTier,
): string {
  const { toolName, args } = ctx;
  const baseTier = TOOL_BASE_TIERS[toolName] ?? 3;

  if (tier === baseTier) {
    return `${toolName} is classified as tier ${tier} by default`;
  }

  if (toolName === "execute_command") {
    if (tier === 5) {
      return `Command contains potentially dangerous patterns`;
    }
    return `Shell command execution is tier ${tier}`;
  }

  if (tier === 5) {
    return `Contains exploit-level patterns`;
  }

  return `Escalated from tier ${baseTier} to tier ${tier} based on content analysis`;
}
