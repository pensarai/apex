export { type ToolContext } from "./types";
export {
  type UnifiedSandbox,
  type SandboxType,
  type SandboxExecuteOptions,
  type SandboxExecutionResult,
} from "./sandbox";

// Browser automation tools
export { createBrowserToolset, BROWSER_TOOL_NAMES } from "./browserTools";
export type { BrowserToolName } from "./browserTools";

// Sandbox Playwright helpers (check / install Playwright in a sandbox)
export {
  checkSandboxPlaywright,
  installSandboxPlaywright,
  ensureSandboxPlaywright,
  ensureSandboxBrowser,
} from "./sandboxPlaywright";

// Core pentest tools
export { executeCommand } from "./executeCommand";
export { httpRequest } from "./httpRequest";
export { documentVulnerability } from "./documentFinding";
export { createPoc } from "./createPoc";

// Filesystem / search tools
export { readFile } from "./readFile";
export { listFiles } from "./listFiles";
export { grep } from "./grep";
export { createFile } from "./createFile";
export { updateFile } from "./updateFile";

// Attack surface / recon tools
export { documentAsset } from "./documentAsset";
export { authenticateSession } from "./authenticateSession";
export { delegateAuth } from "./delegateAuth";
export { extractJsEndpoints } from "./extractJsEndpoints";
export { crawlAuthenticated } from "./crawlAuthenticated";
export { testEndpointVariations } from "./testEndpointVariations";
export { validateDiscovery } from "./validateDiscovery";
export { createAttackSurfaceReport } from "./createAttackSurfaceReport";

// Authentication tools
export { completeAuthentication } from "./completeAuthentication";
export { detectAuthScheme } from "./detectAuthScheme";
export { probeAuthEndpoints } from "./probeAuthEndpoints";

// Orchestration tools
export { runAttackSurface } from "./runAttackSurface";
export { spawnPentestSwarm } from "./spawnPentestSwarm";
export { spawnCodingAgent } from "./spawnCodingAgent";

// Reporting / benchmark tools
// export { generateReport } from "./generateReport";
export { provideComparisonResults } from "./provideComparisonResults";

// Memory tools
export { addMemory } from "./addMemory";
export { listMemories } from "./listMemories";
export { getMemory } from "./getMemory";

// Email tools
export { createEmailToolset, EMAIL_TOOL_NAMES } from "./email";
export type { EmailToolName } from "./email";

// Web search tools (requires Pensar account)
export { webSearch } from "./webSearch";
export { getPage } from "./getPage";

// ---------------------------------------------------------------------------
// Tool registry
// ---------------------------------------------------------------------------

import type { ToolContext } from "./types";
import { createBrowserToolset } from "./browserTools";
import { executeCommand } from "./executeCommand";
import { httpRequest } from "./httpRequest";
import { documentVulnerability } from "./documentFinding";
import { createPoc } from "./createPoc";
import { readFile } from "./readFile";
import { listFiles } from "./listFiles";
import { grep } from "./grep";
import { createFile } from "./createFile";
import { updateFile } from "./updateFile";
import { documentAsset } from "./documentAsset";
import { authenticateSession } from "./authenticateSession";
import { delegateAuth } from "./delegateAuth";
import { extractJsEndpoints } from "./extractJsEndpoints";
import { crawlAuthenticated } from "./crawlAuthenticated";
import { testEndpointVariations } from "./testEndpointVariations";
import { validateDiscovery } from "./validateDiscovery";
import { createAttackSurfaceReport } from "./createAttackSurfaceReport";
import { completeAuthentication } from "./completeAuthentication";
import { detectAuthScheme } from "./detectAuthScheme";
import { probeAuthEndpoints } from "./probeAuthEndpoints";
import { runAttackSurface } from "./runAttackSurface";
import { spawnPentestSwarm } from "./spawnPentestSwarm";
import { spawnCodingAgent } from "./spawnCodingAgent";
// import { generateReport } from "./generateReport";
import { provideComparisonResults } from "./provideComparisonResults";
import { addMemory } from "./addMemory";
import { listMemories } from "./listMemories";
import { getMemory } from "./getMemory";
import { createEmailToolset } from "./email";
import { emailListInboxes } from "./email/listInboxes";
import { emailListMessages } from "./email/listMessages";
import { emailSearchMessages } from "./email/searchMessages";
import { emailGetMessage } from "./email/getMessage";
import { webSearch } from "./webSearch";
import { getPage } from "./getPage";

/**
 * Create the full toolset for the OffensiveSecurityAgent.
 *
 * Every tool the harness knows about is created here. Specific agents
 * pick which ones to activate via the `activeTools` string array — the
 * AI SDK handles the filtering at the model level.
 */
export function createAllTools(ctx: ToolContext & { subagentId?: string }) {
  return {
    // Browser automation tools (8 tools from Playwright MCP)
    ...createBrowserToolset(ctx),

    // Core pentest tools
    execute_command: executeCommand(ctx),
    http_request: httpRequest(ctx),
    document_vulnerability: documentVulnerability(ctx),
    create_poc: createPoc(ctx),

    // Filesystem / search tools
    read_file: readFile(ctx),
    list_files: listFiles(ctx),
    grep: grep(ctx),
    create_file: createFile(ctx),
    update_file: updateFile(ctx),

    // Attack surface / recon tools
    document_asset: documentAsset(ctx),
    authenticate_session: authenticateSession(ctx),
    delegate_to_auth_subagent: delegateAuth(ctx),
    extract_js_endpoints: extractJsEndpoints(ctx),
    crawl_authenticated_area: crawlAuthenticated(ctx),
    test_endpoint_variations: testEndpointVariations(ctx),
    validate_discovery_completeness: validateDiscovery(ctx),
    create_attack_surface_report: createAttackSurfaceReport(ctx),

    // Authentication tools
    complete_authentication: completeAuthentication(ctx),
    detect_auth_scheme: detectAuthScheme(ctx),
    probe_auth_endpoints: probeAuthEndpoints(ctx),

    // Orchestration tools
    run_attack_surface: runAttackSurface(ctx),
    spawn_pentest_swarm: spawnPentestSwarm(ctx),
    spawn_coding_agent: spawnCodingAgent(ctx),

    // Reporting / benchmark tools
    // generate_report: generateReport(ctx),
    provide_comparison_results: provideComparisonResults(ctx),

    // Memory tools (persistent cross-session knowledge)
    add_memory: addMemory(ctx),
    list_memories: listMemories(ctx),
    get_memory: getMemory(ctx),

    // Email tools (read-only inbox access)
    ...createEmailToolset(ctx),
    email_list_inboxes: emailListInboxes(ctx),
    email_list_messages: emailListMessages(ctx),
    email_search_messages: emailSearchMessages(ctx),
    email_get_message: emailGetMessage(ctx),

    // Web search tools (requires Pensar account)
    web_search: webSearch(ctx),
    get_page: getPage(ctx),
  } as const;
}

/** Union of all available tool names. */
export type ToolName = keyof ReturnType<typeof createAllTools>;

/** All tool names as a runtime array (useful for "give me everything"). */
export const ALL_TOOL_NAMES: ToolName[] = [
  // Browser automation
  "browser_navigate",
  "browser_snapshot",
  "browser_screenshot",
  "browser_click",
  "browser_fill",
  "browser_evaluate",
  "browser_console",
  "browser_get_cookies",
  // Core pentest
  "execute_command",
  "http_request",
  "document_vulnerability",
  "create_poc",
  // Filesystem / search
  "read_file",
  "list_files",
  "grep",
  "create_file",
  "update_file",
  "document_asset",
  "authenticate_session",
  "delegate_to_auth_subagent",
  "create_attack_surface_report",
  "complete_authentication",
  "run_attack_surface",
  "spawn_pentest_swarm",
  "spawn_coding_agent",
  // "generate_report",
  "provide_comparison_results",
  // Memory
  "add_memory",
  "list_memories",
  "get_memory",
  // Email
  "email_list_inboxes",
  "email_list_messages",
  "email_get_message",
  "email_search_messages",
  "email_get_attachments",
  "email_mark_read",
  // Web search (requires Pensar account)
  "web_search",
  "get_page",
];

/**
 * Tool names available in plan mode (read-only / non-mutating).
 *
 * Excludes: create_file, update_file, create_poc, document_vulnerability,
 * document_asset. These are the mutation tools that should not be available
 * when the operator is in plan (read-only) mode.
 */
export const PLAN_MODE_TOOL_NAMES: ToolName[] = [
  // Browser automation (read-only navigation and inspection)
  "browser_navigate",
  "browser_snapshot",
  "browser_screenshot",
  "browser_click",
  "browser_fill",
  "browser_evaluate",
  "browser_console",
  "browser_get_cookies",
  // Core pentest (read-only)
  "execute_command",
  "http_request",
  // Filesystem / search (read-only)
  "read_file",
  "list_files",
  "grep",
  // Attack surface / recon
  "authenticate_session",
  "delegate_to_auth_subagent",
  "create_attack_surface_report",
  "complete_authentication",
  "run_attack_surface",
  "spawn_pentest_swarm",
  "spawn_coding_agent",
  "provide_comparison_results",
  // Memory
  "add_memory",
  "list_memories",
  "get_memory",
  // Email
  "email_list_inboxes",
  "email_list_messages",
  "email_get_message",
  "email_search_messages",
  "email_get_attachments",
  "email_mark_read",
  // Web search
  "web_search",
  "get_page",
];

/** Email tool names — auto-appended to activeTools by the base class when inboxes are configured. */
export { EMAIL_TOOL_NAMES as EMAIL_TOOL_NAMES_ACTIVE } from "./email";
