// Memory tools
export { addMemory } from "./addMemory";
export { applyPatch } from "./applyPatch";
// askUserQuestions schema/types — used by TUI for the question-prompt UX.
export {
  type AskUserQuestion,
  type AskUserQuestionAnswer,
  AskUserQuestionSchema,
  type AskUserQuestionsResult,
} from "./askUserQuestions";
// Browser automation tools
export { BROWSER_TOOL_NAMES, createBrowserToolset } from "./browserTools";
// Observability tools
export { checkpointState } from "./checkpointState";
// Authentication tools
export { completeAuthentication } from "./completeAuthentication";
export { crawlAuthenticated } from "./crawlAuthenticated";
export { createAttackSurfaceReport } from "./createAttackSurfaceReport";
export { createFile } from "./createFile";
// Task decomposition tools
export { createTask } from "./createTask";
export { delegateAuth } from "./delegateAuth";
export { deleteFile } from "./deleteFile";
export { detectAuthScheme } from "./detectAuthScheme";
export { documentAgentRedTeamFinding } from "./documentAgentRedTeamFinding";
// Attack surface / recon tools
export { documentApp } from "./documentApp";
export { documentEndpoint } from "./documentEndpoint";
export { documentVulnerability } from "./documentFinding";
// Email tools
export {
  createEmailToolset,
  EMAIL_TOOL_NAMES,
  SEND_EMAIL_TOOL_NAME,
} from "./email";
export { evaluateAgentRedTeamAttempt } from "./evaluateAgentRedTeamAttempt";
// Core pentest tools
export { executeCommand } from "./executeCommand";
export { extractJsEndpoints } from "./extractJsEndpoints";
export { finalizeAgentRedTeamCampaign } from "./finalizeAgentRedTeamCampaign";
export { getMemory } from "./getMemory";
export { getPage } from "./getPage";
export { gitDiff } from "./gitDiff";
export { gitStatus } from "./gitStatus";
export { globFiles } from "./glob";
export { grep } from "./grep";
export { httpRequest } from "./httpRequest";
export { listFiles } from "./listFiles";
export { listMemories } from "./listMemories";
export { listPromptInjections } from "./listPromptInjections";
export { listTasksTool } from "./listTasks";
// Persistent shell — long-lived shell session shared across tool calls.
export {
  extractFallbackStdout,
  getApexTmpRoot,
  PersistentShell,
  readTempfileCapped,
  type ShellExecuteResult,
} from "./persistentShell";
// Playwright MCP browser session helpers.
export {
  type BrowserClickResult,
  type BrowserConsoleResult,
  type BrowserEvaluateResult,
  type BrowserFillResult,
  type BrowserNavigateResult,
  type BrowserScreenshotResult,
  type BrowserStorageState,
  type BrowserToolMode,
  createBrowserTools,
  PlaywrightMcpSession,
  parseStorageStateResult,
  setHeadlessMode,
  setUserAgent,
  setViewportSize,
  transformScriptToFunction,
} from "./playwrightMcp";
export { probeAuthEndpoints } from "./probeAuthEndpoints";
export { profileCodebase } from "./profileCodebase";
// Reporting / benchmark tools
// export { generateReport } from "./generateReport";
export { provideComparisonResults } from "./provideComparisonResults";
// Filesystem / search tools
export { queryWhiteboxCatalog } from "./queryWhiteboxCatalog";
export { readFile } from "./readFile";
// Skill tools
export { readSkill } from "./readSkill";
// Terminal blocking-error tool — ends the run and surfaces a failure.
export {
  createReportErrorTool,
  PentestReportedError,
  REPORT_ERROR_TOOL_NAME,
  ReportErrorReasonSchema,
  type ReportedError,
} from "./reportError";
// Response (structured final-output) tool — used by sub-agents that emit
// validated result objects.
export { createResponseTool, RESPONSE_TOOL_NAME } from "./response";
export { runAgentRedTeamWorkflow } from "./runAgentRedTeamWorkflow";
// Orchestration tools
export { runAttackSurface } from "./runAttackSurface";
export { runCodeQuery } from "./runCodeQuery";
export { runPentestWorkflow } from "./runPentestWorkflow";
export { runWhiteboxScan } from "./runWhiteboxScan";
export type {
  SandboxExecuteOptions,
  SandboxExecutionResult,
  SandboxType,
  UnifiedSandbox,
} from "./sandbox";
// Sandbox Playwright helpers (check / install Playwright in a sandbox)
export {
  checkSandboxPlaywright,
  createSandboxBrowserTools,
  ensureSandboxBrowser,
  ensureSandboxPlaywright,
  installSandboxPlaywright,
} from "./sandboxPlaywright";
// Scope guard utilities
export {
  assertCommandInScope,
  assertUrlInScope,
  extractHostname,
  extractHostsFromCommand,
  getAllowedHosts,
  isHostAllowed,
  resolverSessionFromCtx,
  ScopeViolationError,
} from "./scopeGuard";
export { spawnCodingAgent } from "./spawnCodingAgent";
export { spawnPentestAgent } from "./spawnPentestAgent";
export { spawnPentestSwarm } from "./spawnPentestSwarm";
export { submitPlan } from "./submitPlan";
export { testEndpointVariations } from "./testEndpointVariations";
export type { ToolContext } from "./types";
export { updateFile } from "./updateFile";
export { updateTask } from "./updateTask";
export { validateDiscovery } from "./validateDiscovery";
// Web search tools (requires Pensar account)
export { webSearch } from "./webSearch";
export {
  createWhiteboxCandidate,
  listWhiteboxCandidates,
  updateWhiteboxCandidate,
} from "./whiteboxCandidates";
export {
  pollWhiteboxJob,
  readWhiteboxArtifact,
  startWhiteboxJob,
  stopWhiteboxJob,
} from "./whiteboxJobs";
// Authenticated Pensar workspace tools
export {
  createWorkspaceApp,
  createWorkspaceEndpoint,
  listWorkspaceApps,
  listWorkspaceEndpoints,
  updateWorkspaceApp,
  updateWorkspaceEndpoint,
} from "./workspaceApps";
export {
  createWorkspaceDomain,
  listWorkspaceDomains,
} from "./workspaceDomains";
// Plan mode tools
export { writePlan } from "./writePlan";

// ---------------------------------------------------------------------------
// Tool registry
// ---------------------------------------------------------------------------

import { addMemory } from "./addMemory";
import { applyPatch } from "./applyPatch";
import {
  ASK_USER_QUESTIONS_TOOL_NAME,
  askUserQuestions,
} from "./askUserQuestions";
import { createBrowserToolset } from "./browserTools";
import { checkpointState } from "./checkpointState";
import { completeAuthentication } from "./completeAuthentication";
import { crawlAuthenticated } from "./crawlAuthenticated";
import { createAttackSurfaceReport } from "./createAttackSurfaceReport";
import { createFile } from "./createFile";
import { createTask } from "./createTask";
import { delegateAuth } from "./delegateAuth";
import { deleteFile } from "./deleteFile";
import { detectAuthScheme } from "./detectAuthScheme";
import { documentAgentRedTeamFinding } from "./documentAgentRedTeamFinding";
import { documentApp } from "./documentApp";
import { documentEndpoint } from "./documentEndpoint";
import { documentVulnerability } from "./documentFinding";
import {
  createEmailToolset,
  emailGetMessage,
  emailListInboxes,
  emailListMessages,
  emailSearchMessages,
} from "./email";
import { evaluateAgentRedTeamAttempt } from "./evaluateAgentRedTeamAttempt";
import { executeCommand } from "./executeCommand";
import { extractJsEndpoints } from "./extractJsEndpoints";
import { finalizeAgentRedTeamCampaign } from "./finalizeAgentRedTeamCampaign";
import { getMemory } from "./getMemory";
import { getPage } from "./getPage";
import { gitDiff } from "./gitDiff";
import { gitStatus } from "./gitStatus";
import { globFiles } from "./glob";
import { grep } from "./grep";
import { httpRequest } from "./httpRequest";
import { listFiles } from "./listFiles";
import { listMemories } from "./listMemories";
import { listPromptInjections } from "./listPromptInjections";
import { listTasksTool } from "./listTasks";
import { probeAuthEndpoints } from "./probeAuthEndpoints";
import { profileCodebase } from "./profileCodebase";
// import { generateReport } from "./generateReport";
import { provideComparisonResults } from "./provideComparisonResults";
import { queryWhiteboxCatalog } from "./queryWhiteboxCatalog";
import { readFile } from "./readFile";
import { readSkill } from "./readSkill";
import { runAgentRedTeamWorkflow } from "./runAgentRedTeamWorkflow";
import { runAttackSurface } from "./runAttackSurface";
import { runCodeQuery } from "./runCodeQuery";
import { runPentestWorkflow } from "./runPentestWorkflow";
import { runWhiteboxScan } from "./runWhiteboxScan";
import { spawnCodingAgent } from "./spawnCodingAgent";
import { spawnPentestAgent } from "./spawnPentestAgent";
import { spawnPentestSwarm } from "./spawnPentestSwarm";
import { submitPlan } from "./submitPlan";
import { testEndpointVariations } from "./testEndpointVariations";
import type { ToolContext } from "./types";
import { updateFile } from "./updateFile";
import { updateTask } from "./updateTask";
import { validateDiscovery } from "./validateDiscovery";
import { webSearch } from "./webSearch";
import {
  createWhiteboxCandidate,
  listWhiteboxCandidates,
  updateWhiteboxCandidate,
} from "./whiteboxCandidates";
import {
  pollWhiteboxJob,
  readWhiteboxArtifact,
  startWhiteboxJob,
  stopWhiteboxJob,
} from "./whiteboxJobs";
import {
  createWorkspaceApp,
  createWorkspaceEndpoint,
  listWorkspaceApps,
  listWorkspaceEndpoints,
  updateWorkspaceApp,
  updateWorkspaceEndpoint,
} from "./workspaceApps";
import {
  createWorkspaceDomain,
  listWorkspaceDomains,
} from "./workspaceDomains";
import { writePlan } from "./writePlan";

export { ASK_USER_QUESTIONS_TOOL_NAME } from "./askUserQuestions";

/**
 * Create the full toolset for the OffensiveSecurityAgent.
 *
 * Every tool the harness knows about is created here. Specific agents
 * pick which ones to activate via the `activeTools` string array — the
 * AI SDK handles the filtering at the model level.
 */
export function createAllTools(ctx: ToolContext) {
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
    glob: globFiles(ctx),
    grep: grep(ctx),
    profile_codebase: profileCodebase(ctx),
    query_whitebox_catalog: queryWhiteboxCatalog(ctx),
    run_code_query: runCodeQuery(ctx),
    create_file: createFile(ctx),
    update_file: updateFile(ctx),
    delete_file: deleteFile(ctx),
    apply_patch: applyPatch(ctx),
    git_status: gitStatus(ctx),
    git_diff: gitDiff(ctx),

    // Attack surface / recon tools
    document_app: documentApp(ctx),
    document_endpoint: documentEndpoint(ctx),
    list_workspace_domains: listWorkspaceDomains(ctx),
    create_workspace_domain: createWorkspaceDomain(ctx),
    list_workspace_apps: listWorkspaceApps(ctx),
    create_workspace_app: createWorkspaceApp(ctx),
    update_workspace_app: updateWorkspaceApp(ctx),
    list_workspace_endpoints: listWorkspaceEndpoints(ctx),
    create_workspace_endpoint: createWorkspaceEndpoint(ctx),
    update_workspace_endpoint: updateWorkspaceEndpoint(ctx),
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
    run_agent_redteam_workflow: runAgentRedTeamWorkflow(ctx),
    evaluate_agent_redteam_attempt: evaluateAgentRedTeamAttempt(ctx),
    document_agent_redteam_finding: documentAgentRedTeamFinding(ctx),
    finalize_agent_redteam_campaign: finalizeAgentRedTeamCampaign(ctx),
    spawn_pentest_swarm: spawnPentestSwarm(ctx),
    spawn_pentest_agent: spawnPentestAgent(ctx),
    spawn_coding_agent: spawnCodingAgent(ctx),
    run_pentest_workflow: runPentestWorkflow(ctx),
    run_whitebox_scan: runWhiteboxScan(ctx),
    create_whitebox_candidate: createWhiteboxCandidate(ctx),
    update_whitebox_candidate: updateWhiteboxCandidate(ctx),
    list_whitebox_candidates: listWhiteboxCandidates(ctx),
    start_whitebox_job: startWhiteboxJob(ctx),
    poll_whitebox_job: pollWhiteboxJob(ctx),
    stop_whitebox_job: stopWhiteboxJob(ctx),
    read_whitebox_artifact: readWhiteboxArtifact(ctx),

    // Reporting / benchmark tools
    // generate_report: generateReport(ctx),
    provide_comparison_results: provideComparisonResults(ctx),

    // Memory tools (persistent cross-session knowledge)
    add_memory: addMemory(ctx),
    list_memories: listMemories(ctx),
    get_memory: getMemory(ctx),

    // Prompt-injection test catalog (safe metadata only; no raw payloads)
    list_prompt_injections: listPromptInjections(ctx),

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

export const WORKSPACE_TOOL_NAMES: readonly ToolName[] = [
  "list_workspace_domains",
  "create_workspace_domain",
  "list_workspace_apps",
  "create_workspace_app",
  "update_workspace_app",
  "list_workspace_endpoints",
  "create_workspace_endpoint",
  "update_workspace_endpoint",
];

/**
 * Subset of {@link WORKSPACE_TOOL_NAMES} that mutate the connected Console
 * workspace. Gated more strictly than the read-only `list_*` tools: only an
 * explicit mutation request may expose them (see `filterWorkspaceToolsForRun`).
 */
export const WORKSPACE_WRITE_TOOL_NAMES: readonly ToolName[] = [
  "create_workspace_domain",
  "create_workspace_app",
  "update_workspace_app",
  "create_workspace_endpoint",
  "update_workspace_endpoint",
];

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
  "glob",
  "grep",
  "profile_codebase",
  "query_whitebox_catalog",
  "run_code_query",
  "create_file",
  "update_file",
  "delete_file",
  "apply_patch",
  "git_status",
  "git_diff",
  "document_app",
  "document_endpoint",
  ...WORKSPACE_TOOL_NAMES,
  "delegate_to_auth_subagent",
  "create_attack_surface_report",
  "complete_authentication",
  "run_attack_surface",
  "run_agent_redteam_workflow",
  "evaluate_agent_redteam_attempt",
  "document_agent_redteam_finding",
  "finalize_agent_redteam_campaign",
  "spawn_pentest_swarm",
  "spawn_pentest_agent",
  "spawn_coding_agent",
  "run_pentest_workflow",
  "run_whitebox_scan",
  "create_whitebox_candidate",
  "update_whitebox_candidate",
  "list_whitebox_candidates",
  "start_whitebox_job",
  "poll_whitebox_job",
  "stop_whitebox_job",
  "read_whitebox_artifact",
  // "generate_report",
  "provide_comparison_results",
  // Memory
  "add_memory",
  "list_memories",
  "get_memory",
  // Prompt-injection testing
  "list_prompt_injections",
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

/** Orchestration/ceremony tools excluded from fast-strike mode (registry minus this list). */
export const FAST_STRIKE_EXCLUDED_TOOL_NAMES: ToolName[] = [
  // Sub-agents / workflow
  "run_attack_surface",
  "run_agent_redteam_workflow",
  "evaluate_agent_redteam_attempt",
  "document_agent_redteam_finding",
  "finalize_agent_redteam_campaign",
  "spawn_pentest_swarm",
  "spawn_pentest_agent",
  "spawn_coding_agent",
  "run_pentest_workflow",
  "delegate_to_auth_subagent",
  // Whitebox jobs
  "run_whitebox_scan",
  "create_whitebox_candidate",
  "update_whitebox_candidate",
  "list_whitebox_candidates",
  "start_whitebox_job",
  "poll_whitebox_job",
  "stop_whitebox_job",
  "read_whitebox_artifact",
  // Planning / tasks
  "write_plan",
  "submit_plan",
  "create_task",
  "update_task",
  "list_tasks",
  // Reporting / interactive
  "create_attack_surface_report",
  "provide_comparison_results",
  ASK_USER_QUESTIONS_TOOL_NAME,
];

/**
 * Tool names available in plan mode (read-only / non-mutating).
 *
 * Excludes: create_file, update_file, document_vulnerability,
 * document_app, document_endpoint, create_workspace_domain,
 * create_workspace_app, update_workspace_app, create_workspace_endpoint,
 * update_workspace_endpoint, profile_codebase, run_code_query,
 * run_whitebox_scan (they persist session artifacts). These should not be available
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
  "glob",
  "grep",
  "query_whitebox_catalog",
  "git_status",
  "git_diff",
  // Recon (read-only probing and discovery)
  "delegate_to_auth_subagent",
  "complete_authentication",
  "extract_js_endpoints",
  "crawl_authenticated_area",
  "detect_auth_scheme",
  "probe_auth_endpoints",
  "provide_comparison_results",
  "list_whitebox_candidates",
  "poll_whitebox_job",
  "read_whitebox_artifact",
  // Memory
  "add_memory",
  "list_memories",
  "get_memory",
  // Prompt-injection testing (safe metadata only)
  "list_prompt_injections",
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
