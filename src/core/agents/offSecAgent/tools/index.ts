export { type ToolContext } from "./types";
export {
  type UnifiedSandbox,
  type SandboxType,
  type SandboxExecuteOptions,
  type SandboxExecutionResult,
} from "./sandbox";

// Scope guard utilities
export {
  ScopeViolationError,
  getAllowedHosts,
  isHostAllowed,
  extractHostname,
  assertUrlInScope,
  assertCommandInScope,
  extractHostsFromCommand,
} from "./scopeGuard";

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

// Filesystem / search tools
export { readFile } from "./readFile";
export { listFiles } from "./listFiles";
export { grep } from "./grep";
export { createFile } from "./createFile";
export { updateFile } from "./updateFile";

// Attack surface / recon tools
export { documentApp } from "./documentApp";
export { documentEndpoint } from "./documentEndpoint";
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
export { runPentestWorkflow } from "./runPentestWorkflow";

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

// Skill tools
export { readSkill } from "./readSkill";

// Observability tools
export { checkpointState } from "./checkpointState";

// Task decomposition tools
export { createTask } from "./createTask";
export { updateTask } from "./updateTask";
export { listTasksTool } from "./listTasks";

// Plan mode tools
export { writePlan } from "./writePlan";
export { submitPlan } from "./submitPlan";

// ---------------------------------------------------------------------------
// Tool registry
// ---------------------------------------------------------------------------

import type { ToolContext } from "./types";
import { createBrowserToolset } from "./browserTools";
import { executeCommand } from "./executeCommand";
import { httpRequest } from "./httpRequest";
import { documentVulnerability } from "./documentFinding";

import { readFile } from "./readFile";
import { listFiles } from "./listFiles";
import { grep } from "./grep";
import { createFile } from "./createFile";
import { updateFile } from "./updateFile";
import { documentApp } from "./documentApp";
import { documentEndpoint } from "./documentEndpoint";
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
import { runPentestWorkflow } from "./runPentestWorkflow";
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
import { readSkill } from "./readSkill";
import { checkpointState } from "./checkpointState";
import { createTask } from "./createTask";
import { updateTask } from "./updateTask";
import { listTasksTool } from "./listTasks";
import { writePlan } from "./writePlan";
import { submitPlan } from "./submitPlan";
import {
  askUserQuestions,
  ASK_USER_QUESTIONS_TOOL_NAME,
} from "./askUserQuestions";
export { ASK_USER_QUESTIONS_TOOL_NAME } from "./askUserQuestions";

// ── Test-case workflow tools ──────────────────────────────────────────
import { emitDetectionEvent } from "./emitDetectionEvent";
import { checkFileSignature } from "./checkFileSignature";
import { extractArchive } from "./extractArchive";
import { observeProcesses } from "./observeProcesses";
import { observeNetwork } from "./observeNetwork";
import { uploadArtifactToUrl } from "./uploadArtifactToUrl";
import { httpProbeMulti } from "./httpProbeMulti";
import { httpBurst } from "./httpBurst";
export {
  emitDetectionEvent,
  checkFileSignature,
  extractArchive,
  observeProcesses,
  observeNetwork,
  uploadArtifactToUrl,
  httpProbeMulti,
  httpBurst,
};
export { createSafetyCapState, hostnameFor } from "./_safetyCaps";
export type { SafetyCapState, SafetyCapsConfig, SafetyCapViolation } from "./_safetyCaps";

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

    // Filesystem / search tools
    read_file: readFile(ctx),
    list_files: listFiles(ctx),
    grep: grep(ctx),
    create_file: createFile(ctx),
    update_file: updateFile(ctx),

    // Attack surface / recon tools
    document_app: documentApp(ctx),
    document_endpoint: documentEndpoint(ctx),
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
    run_pentest_workflow: runPentestWorkflow(ctx),

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

    // Skill tools (conditional — only when registry is provided)
    ...(ctx.skillsRegistry ? { read_skill: readSkill(ctx) } : {}),

    [ASK_USER_QUESTIONS_TOOL_NAME]: askUserQuestions(ctx),

    // Observability tools (conditional — only when trace writer is provided)
    ...(ctx.traceWriter ? { checkpoint_state: checkpointState(ctx) } : {}),

    // Task decomposition tools (conditional — only when tasksDir is configured)
    ...(ctx.tasksDir
      ? {
          create_task: createTask(ctx),
          update_task: updateTask(ctx),
          list_tasks: listTasksTool(ctx),
        }
      : {}),

    // Plan mode tools
    write_plan: writePlan(ctx),
    submit_plan: submitPlan(ctx),

    // Test-case workflow tools
    emit_detection_event: emitDetectionEvent(ctx),
    check_file_signature: checkFileSignature(ctx),
    extract_archive: extractArchive(ctx),
    observe_processes: observeProcesses(ctx),
    observe_network: observeNetwork(ctx),
    upload_artifact_to_url: uploadArtifactToUrl(ctx),
    http_probe_multi: httpProbeMulti(ctx),
    http_burst: httpBurst(ctx),
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
  // Filesystem / search
  "read_file",
  "list_files",
  "grep",
  "create_file",
  "update_file",
  "document_app",
  "document_endpoint",
  "authenticate_session",
  "delegate_to_auth_subagent",
  "detect_auth_scheme",
  "probe_auth_endpoints",
  "create_attack_surface_report",
  "complete_authentication",
  "run_attack_surface",
  "spawn_pentest_swarm",
  "spawn_coding_agent",
  "run_pentest_workflow",
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
  // Observability
  "checkpoint_state",
  // Task decomposition
  "create_task",
  "update_task",
  "list_tasks",
  // Plan mode
  "write_plan",
  "submit_plan",
  ASK_USER_QUESTIONS_TOOL_NAME,
  // Test-case workflow
  "emit_detection_event",
  "check_file_signature",
  "extract_archive",
  "observe_processes",
  "observe_network",
  "upload_artifact_to_url",
  "http_probe_multi",
  "http_burst",
];

/**
 * The subset of tools that a TestCaseAgent runs with. By design, the
 * agent does NOT carry auth tooling — the workflow orchestrates a
 * pre-run AuthenticationAgent phase before this agent spawns, and the
 * resulting cookies/headers are injected into the agent's user prompt
 * via `auth-data.json`. See `runTestCaseWorkflow` in workflows/testCase.ts
 * for the orchestration, and `buildAuthSection` in specialized/testCase/prompts.ts
 * for the injection pattern (mirrors pentest/agent.ts:558-600).
 */
export const TEST_CASE_TOOL_NAMES: ToolName[] = [
  // Target-facing HTTP
  "http_request",
  "upload_artifact_to_url",
  "http_probe_multi",
  "http_burst",
  // Browser automation — full set (superset of pentest, parity with recon).
  // The MCP browser context is pre-authenticated by the workflow's auth
  // phase (same sandbox), so these tools inherit the logged-in session.
  "browser_navigate",
  "browser_snapshot",
  "browser_screenshot",
  "browser_click",
  "browser_fill",
  "browser_evaluate",
  "browser_console",
  "browser_get_cookies",
  // Email — for probing scenarios that touch email (inbox enumeration,
  // targeted email abuse). NOT for auth-phase MFA codes — the auth
  // subagent owns that before this agent starts.
  "email_list_inboxes",
  "email_list_messages",
  "email_search_messages",
  "email_get_message",
  // Web research — look up target technologies, known exploits, CVEs.
  "web_search",
  "get_page",
  // Sandbox-local (pre-flight, observation)
  "extract_archive",
  "check_file_signature",
  "observe_processes",
  "observe_network",
  "execute_command",
  "read_file",
  "list_files",
  "grep",
  // Emission
  "emit_detection_event",
];

/**
 * Tool names available in plan mode (read-only / non-mutating).
 *
 * Excludes: create_file, update_file, document_vulnerability,
 * document_app, document_endpoint. These are the mutation tools that should not be available
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
  // Recon (read-only probing and discovery)
  "authenticate_session",
  "delegate_to_auth_subagent",
  "complete_authentication",
  "extract_js_endpoints",
  "crawl_authenticated_area",
  "detect_auth_scheme",
  "probe_auth_endpoints",
  "provide_comparison_results",
  // Memory
  "add_memory",
  "list_memories",
  "get_memory",
  // Email (read-only)
  "email_list_inboxes",
  "email_list_messages",
  "email_get_message",
  "email_search_messages",
  "email_get_attachments",
  // Web search
  "web_search",
  "get_page",
  // Plan mode tools
  "write_plan",
  "submit_plan",
  "create_task",
  "update_task",
  "list_tasks",
];

/** Skill tool names — conditionally included when a skills registry is provided. */
export const SKILL_TOOL_NAMES = ["read_skill"] as const;

/** Email tool names — auto-appended to activeTools by the base class when inboxes are configured. */
export { EMAIL_TOOL_NAMES as EMAIL_TOOL_NAMES_ACTIVE } from "./email";
