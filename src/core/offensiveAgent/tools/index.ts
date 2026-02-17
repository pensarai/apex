export { type ToolContext } from "./types";

// Browser automation tools
export { createBrowserToolset, BROWSER_TOOL_NAMES } from "./browserTools";
export type { BrowserToolName } from "./browserTools";

// Core pentest tools
export { executeCommand } from "./executeCommand";
export { httpRequest } from "./httpRequest";
export { documentFinding } from "./documentFinding";
export { createPoc } from "./createPoc";

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

// Reporting / benchmark tools
export { generateReport } from "./generateReport";
export { provideComparisonResults } from "./provideComparisonResults";

// ---------------------------------------------------------------------------
// Tool registry
// ---------------------------------------------------------------------------

import type { ToolContext } from "./types";
import { createBrowserToolset } from "./browserTools";
import { executeCommand } from "./executeCommand";
import { httpRequest } from "./httpRequest";
import { documentFinding } from "./documentFinding";
import { createPoc } from "./createPoc";
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
import { generateReport } from "./generateReport";
import { provideComparisonResults } from "./provideComparisonResults";

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
    document_finding: documentFinding(ctx),
    create_poc: createPoc(ctx),

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

    // Reporting / benchmark tools
    generate_report: generateReport(ctx),
    provide_comparison_results: provideComparisonResults(ctx),
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
  "document_finding",
  "create_poc",
  "document_asset",
  "authenticate_session",
  "delegate_to_auth_subagent",
  "extract_js_endpoints",
  "crawl_authenticated_area",
  "test_endpoint_variations",
  "validate_discovery_completeness",
  "create_attack_surface_report",
  "complete_authentication",
  "detect_auth_scheme",
  "probe_auth_endpoints",
  "run_attack_surface",
  "spawn_pentest_swarm",
  "generate_report",
  "provide_comparison_results",
] as const;
