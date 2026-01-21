/**
 * Toolset System
 *
 * Manages tool availability during penetration testing sessions.
 * Allows users to enable/disable specific tools via UI.
 */

import { z } from "zod";

// ============================================================================
// Tool Definition
// ============================================================================

/**
 * Tool categories for organization and filtering
 */
export type ToolCategory =
  | "reconnaissance"
  | "exploitation"
  | "browser"
  | "reporting"
  | "utility";

/**
 * Definition of an individual tool
 */
export interface ToolDefinition {
  /** Unique tool identifier (matches tool name in code) */
  id: string;
  /** Human-readable display name */
  name: string;
  /** Brief description (shown in list) */
  description: string;
  /** Detailed description (shown in detail view) */
  detail?: string;
  /** Tool category for grouping */
  category: ToolCategory;
  /** Whether this tool is enabled by default */
  defaultEnabled: boolean;
}

// ============================================================================
// Master Tool List
// ============================================================================

/**
 * All available tools organized by category
 */
export const ALL_TOOLS: ToolDefinition[] = [
  // Reconnaissance tools
  {
    id: "http_request",
    name: "HTTP Request",
    description: "Send HTTP requests",
    detail: "Make HTTP/HTTPS requests with custom headers, methods, and bodies. Supports GET, POST, PUT, DELETE and other methods. Used for probing endpoints and testing responses.",
    category: "reconnaissance",
    defaultEnabled: true,
  },
  {
    id: "execute_command",
    name: "Execute Command",
    description: "Run shell commands",
    detail: "Execute shell commands on the local system for reconnaissance tasks like running nmap, curl, or other CLI tools. Commands are sandboxed and require approval.",
    category: "reconnaissance",
    defaultEnabled: true,
  },
  {
    id: "smart_enumerate",
    name: "Smart Enumerate",
    description: "Auto-discover surface",
    detail: "Intelligently discover the attack surface by crawling, directory brute-forcing, and analyzing responses. Automatically categorizes endpoints and identifies interesting targets.",
    category: "reconnaissance",
    defaultEnabled: true,
  },
  {
    id: "cve_lookup",
    name: "CVE Lookup",
    description: "Search CVE database",
    detail: "Search for known vulnerabilities (CVEs) based on software name, version, or keywords. Returns CVE IDs, descriptions, CVSS scores, and available exploits.",
    category: "reconnaissance",
    defaultEnabled: true,
  },
  {
    id: "analyze_scan",
    name: "Analyze Scan",
    description: "Parse scan results",
    detail: "Analyze and parse results from vulnerability scanners like Nmap, Nikto, or custom scans. Extracts actionable findings and prioritizes by severity.",
    category: "reconnaissance",
    defaultEnabled: true,
  },
  {
    id: "enumerate_endpoints",
    name: "Enumerate Endpoints",
    description: "Find API routes",
    detail: "Discover API endpoints and routes through directory enumeration, crawling, and analysis of JavaScript files. Identifies parameters and HTTP methods.",
    category: "reconnaissance",
    defaultEnabled: true,
  },
  {
    id: "get_attack_surface",
    name: "Get Attack Surface",
    description: "View discoveries",
    detail: "Retrieve the current discovered attack surface including all endpoints, parameters, authentication requirements, and testing status.",
    category: "reconnaissance",
    defaultEnabled: true,
  },

  // Exploitation tools
  {
    id: "test_parameter",
    name: "Test Parameter",
    description: "Inject test payloads",
    detail: "Test individual parameters for vulnerabilities like SQLi, XSS, command injection, etc. Uses intelligent payload selection based on context and response analysis.",
    category: "exploitation",
    defaultEnabled: true,
  },
  {
    id: "fuzz_endpoint",
    name: "Fuzz Endpoint",
    description: "Fuzz with payloads",
    detail: "Fuzz endpoints with a range of values to discover IDOR, parameter tampering, and boundary issues. Supports numeric ranges and wordlists.",
    category: "exploitation",
    defaultEnabled: true,
  },
  {
    id: "mutate_payload",
    name: "Mutate Payload",
    description: "Bypass WAF/filters",
    detail: "Generate payload variations using encoding, obfuscation, and evasion techniques to bypass WAF rules and input filters.",
    category: "exploitation",
    defaultEnabled: true,
  },
  {
    id: "create_poc",
    name: "Create POC",
    description: "Build & run exploits",
    detail: "Create and execute proof-of-concept scripts in Bash, Python, or JavaScript. Automatically validates exploitation success and captures evidence.",
    category: "exploitation",
    defaultEnabled: true,
  },

  // Browser tools (Playwright MCP)
  {
    id: "browser_navigate",
    name: "Browser Navigate",
    description: "Open URL in browser",
    detail: "Navigate a headless browser to a URL. Used for testing client-side vulnerabilities, SPAs, and capturing rendered content.",
    category: "browser",
    defaultEnabled: true,
  },
  {
    id: "browser_screenshot",
    name: "Browser Screenshot",
    description: "Capture evidence",
    detail: "Take screenshots of the current browser state for evidence collection and documentation of vulnerabilities.",
    category: "browser",
    defaultEnabled: true,
  },
  {
    id: "browser_click",
    name: "Browser Click",
    description: "Click elements",
    detail: "Click on page elements by selector or description. Used for interacting with buttons, links, and form controls.",
    category: "browser",
    defaultEnabled: true,
  },
  {
    id: "browser_fill",
    name: "Browser Fill",
    description: "Fill form fields",
    detail: "Fill form fields with values including XSS payloads. Supports text inputs, textareas, and other form elements.",
    category: "browser",
    defaultEnabled: true,
  },
  {
    id: "browser_evaluate",
    name: "Browser Evaluate",
    description: "Execute JavaScript",
    detail: "Execute arbitrary JavaScript in the browser context. Used for DOM manipulation, XSS validation, and extracting page data.",
    category: "browser",
    defaultEnabled: true,
  },
  {
    id: "browser_console",
    name: "Browser Console",
    description: "Read console logs",
    detail: "Read browser console messages including errors, warnings, and XSS payload execution confirmations.",
    category: "browser",
    defaultEnabled: true,
  },

  // Reporting tools
  {
    id: "document_finding",
    name: "Document Finding",
    description: "Record vuln finding",
    detail: "Document a confirmed vulnerability with title, description, severity, POC path, and evidence. Calculates CVSS score automatically.",
    category: "reporting",
    defaultEnabled: true,
  },
  {
    id: "generate_report",
    name: "Generate Report",
    description: "Create final report",
    detail: "Generate a comprehensive penetration test report in Markdown format with executive summary, findings, and remediation guidance.",
    category: "reporting",
    defaultEnabled: true,
  },
  {
    id: "record_test_result",
    name: "Record Test Result",
    description: "Log test outcome",
    detail: "Record the result of an individual test case including what was tested, the outcome, and any observations.",
    category: "reporting",
    defaultEnabled: true,
  },
  {
    id: "update_attack_surface",
    name: "Update Attack Surface",
    description: "Add endpoints",
    detail: "Add newly discovered endpoints to the attack surface tracking. Updates the sidebar and enables systematic testing.",
    category: "reporting",
    defaultEnabled: true,
  },
  {
    id: "record_credential",
    name: "Record Credential",
    description: "Save found creds",
    detail: "Record discovered credentials (usernames, passwords, API keys, tokens) for tracking and potential reuse in testing.",
    category: "reporting",
    defaultEnabled: true,
  },
  {
    id: "update_endpoint_status",
    name: "Update Endpoint Status",
    description: "Mark test status",
    detail: "Update the testing status of an endpoint (untested, tested, vulnerable, not vulnerable) in the attack surface tracker.",
    category: "reporting",
    defaultEnabled: true,
  },
  {
    id: "record_verified_finding",
    name: "Record Verified Finding",
    description: "Confirm vulnerability",
    detail: "Record a verified vulnerability after successful exploitation. Links to POC and evidence for the final report.",
    category: "reporting",
    defaultEnabled: true,
  },

  // Utility tools
  {
    id: "run_auth_subagent",
    name: "Auth Subagent",
    description: "Run authentication",
    detail: "Run the authentication subagent to obtain an authenticated session. Handles complex auth flows including OAuth, SAML, CSRF tokens, and SPA logins. Call when you need to access authenticated endpoints or the current session is expired.",
    category: "utility",
    defaultEnabled: true,
  },
  {
    id: "scratchpad",
    name: "Scratchpad",
    description: "Store temp notes",
    detail: "Store temporary notes, observations, and intermediate data during testing. Persists across agent turns for context retention.",
    category: "utility",
    defaultEnabled: true,
  },
  {
    id: "store_plan",
    name: "Store Plan",
    description: "Save test plan",
    detail: "Save the current testing plan to disk for persistence. Includes objectives, approach, and progress tracking.",
    category: "utility",
    defaultEnabled: true,
  },
  {
    id: "get_plan",
    name: "Get Plan",
    description: "Load test plan",
    detail: "Retrieve the stored testing plan to resume work or review the current strategy and objectives.",
    category: "utility",
    defaultEnabled: true,
  },
  {
    id: "check_testing_coverage",
    name: "Check Coverage",
    description: "View test progress",
    detail: "Check the current testing coverage showing which endpoints and vulnerability types have been tested vs remaining.",
    category: "utility",
    defaultEnabled: true,
  },
  {
    id: "validate_completeness",
    name: "Validate Completeness",
    description: "Verify test scope",
    detail: "Validate that testing is complete by checking coverage against the original scope and identifying any gaps.",
    category: "utility",
    defaultEnabled: true,
  },
];

// ============================================================================
// Toolset Definitions
// ============================================================================

/**
 * Predefined toolset configuration
 */
export interface ToolsetDefinition {
  /** Unique toolset identifier */
  id: string;
  /** Human-readable name */
  name: string;
  /** Description of the toolset */
  description: string;
  /** Tool IDs to enable (null = all tools) */
  enabledTools: string[] | null;
}

/**
 * Predefined toolsets for common use cases
 */
export const TOOLSETS: ToolsetDefinition[] = [
  {
    id: "web-pentest",
    name: "Web Pentest (Full)",
    description: "All tools enabled for comprehensive web application testing",
    enabledTools: null, // All tools
  },
  {
    id: "recon-only",
    name: "Reconnaissance Only",
    description: "Only reconnaissance and utility tools - no active exploitation",
    enabledTools: [
      // Reconnaissance
      "http_request",
      "execute_command",
      "smart_enumerate",
      "cve_lookup",
      "analyze_scan",
      "enumerate_endpoints",
      "get_attack_surface",
      // Browser (passive)
      "browser_navigate",
      "browser_screenshot",
      "browser_console",
      // Reporting
      "document_finding",
      "generate_report",
      "record_test_result",
      "update_attack_surface",
      "update_endpoint_status",
      // Utility
      "scratchpad",
      "store_plan",
      "get_plan",
      "check_testing_coverage",
      "validate_completeness",
    ],
  },
  {
    id: "minimal",
    name: "Minimal",
    description: "Basic tools for lightweight testing",
    enabledTools: [
      "http_request",
      "execute_command",
      "scratchpad",
      "document_finding",
    ],
  },
];

// ============================================================================
// Toolset State
// ============================================================================

/**
 * Runtime toolset state schema for session config
 */
export const ToolsetStateSchema = z.object({
  /** Base toolset ID that was used to initialize */
  baseToolsetId: z.string(),
  /** Map of tool ID -> enabled status */
  enabledTools: z.record(z.string(), z.boolean()),
  /** Last modification timestamp */
  lastModified: z.number(),
});

export type ToolsetState = z.infer<typeof ToolsetStateSchema>;

// ============================================================================
// Helper Functions
// ============================================================================

/**
 * Create initial toolset state from a toolset definition
 */
export function createToolsetState(toolsetId: string = "web-pentest"): ToolsetState {
  const toolset = TOOLSETS.find((t) => t.id === toolsetId) || TOOLSETS[0]!;

  const enabledTools: Record<string, boolean> = {};

  if (toolset.enabledTools === null) {
    // All tools enabled
    for (const tool of ALL_TOOLS) {
      enabledTools[tool.id] = true;
    }
  } else {
    // Specific tools enabled
    for (const tool of ALL_TOOLS) {
      enabledTools[tool.id] = toolset.enabledTools.includes(tool.id);
    }
  }

  return {
    baseToolsetId: toolset.id,
    enabledTools,
    lastModified: Date.now(),
  };
}

/**
 * Get list of active tool names from toolset state
 */
export function getActiveToolNames(state: ToolsetState | undefined): string[] {
  if (!state) {
    // No state = all tools enabled (fallback)
    return ALL_TOOLS.map((t) => t.id);
  }

  return Object.entries(state.enabledTools)
    .filter(([_, enabled]) => enabled)
    .map(([toolId]) => toolId);
}

/**
 * Toggle a tool's enabled state
 */
export function toggleTool(state: ToolsetState, toolId: string, enabled: boolean): ToolsetState {
  return {
    ...state,
    enabledTools: {
      ...state.enabledTools,
      [toolId]: enabled,
    },
    lastModified: Date.now(),
  };
}

/**
 * Get tools grouped by category
 */
export function getToolsByCategory(): Map<ToolCategory, ToolDefinition[]> {
  const grouped = new Map<ToolCategory, ToolDefinition[]>();

  for (const tool of ALL_TOOLS) {
    const existing = grouped.get(tool.category) || [];
    existing.push(tool);
    grouped.set(tool.category, existing);
  }

  return grouped;
}

/**
 * Get human-readable category name
 */
export function getCategoryDisplayName(category: ToolCategory): string {
  const names: Record<ToolCategory, string> = {
    reconnaissance: "Reconnaissance",
    exploitation: "Exploitation",
    browser: "Browser",
    reporting: "Reporting",
    utility: "Utility",
  };
  return names[category];
}

/**
 * Count enabled tools in a state
 */
export function countEnabledTools(state: ToolsetState | undefined): { enabled: number; total: number } {
  if (!state) {
    return { enabled: ALL_TOOLS.length, total: ALL_TOOLS.length };
  }

  const enabled = Object.values(state.enabledTools).filter(Boolean).length;
  return { enabled, total: ALL_TOOLS.length };
}
