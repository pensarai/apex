export { type ToolContext } from "./types";
export {
  type UnifiedSandbox,
  type SandboxType,
  type SandboxExecuteOptions,
  type SandboxExecutionResult,
} from "./sandbox";

// Browser automation tools — public types consumed by the harness.
export type { BrowserToolName } from "./browserTools";

// Sandbox Playwright helpers (check / install Playwright in a sandbox).
// Consumed by external scripts via the offSecAgent barrel.
export {
  checkSandboxPlaywright,
  installSandboxPlaywright,
  ensureSandboxPlaywright,
  ensureSandboxBrowser,
  createSandboxBrowserTools,
} from "./sandboxPlaywright";

// Email tool name list — exposed for activeTools filtering.
export type { EmailToolName } from "./email";
export { SEND_EMAIL_TOOL_NAME } from "./email";

// Response (structured final-output) tool — used by sub-agents that emit
// validated result objects.
export { createResponseTool, RESPONSE_TOOL_NAME } from "./response";

// Persistent shell — long-lived shell session shared across tool calls.
// PersistentShell is consumed by external scripts via the offSecAgent barrel.
export { PersistentShell, type ShellExecuteResult } from "./persistentShell";

// Playwright MCP browser session helpers — public types and class.
export {
  PlaywrightMcpSession,
  type BrowserToolMode,
  type BrowserNavigateResult,
  type BrowserScreenshotResult,
  type BrowserClickResult,
  type BrowserFillResult,
  type BrowserEvaluateResult,
  type BrowserConsoleResult,
} from "./playwrightMcp";

// askUserQuestions — schema + types consumed by the TUI for the
// question-prompt UX.
export {
  type AskUserQuestion,
  type AskUserQuestionAnswer,
  type AskUserQuestionsResult,
} from "./askUserQuestions";

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
import {
  createEmailToolset,
  emailListInboxes,
  emailListMessages,
  emailSearchMessages,
  emailGetMessage,
} from "./email";
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

    // Email tools (inbox + outbound — gated at activeTools level by base class)
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
  "send_email",
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

/** Email inbox tool names — filtered out by the base class when no inboxes are configured. */
export { EMAIL_TOOL_NAMES as EMAIL_TOOL_NAMES_ACTIVE } from "./email";
