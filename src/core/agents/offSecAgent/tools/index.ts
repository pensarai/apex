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
export {
  BROWSER_TOOL_NAMES,
  type BrowserToolsetFactories,
  createBrowserToolset,
  createBrowserToolsetFactories,
} from "./browserTools";
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
// Attack surface / recon tools
export { documentApp } from "./documentApp";
export { documentEndpoint } from "./documentEndpoint";
export { documentEndpoints } from "./documentEndpoints";
export { documentVulnerability } from "./documentFinding";
// Email tools
export {
  createEmailToolset,
  EMAIL_TOOL_NAMES,
  SEND_EMAIL_TOOL_NAME,
} from "./email";
// Core pentest tools
export { executeCommand } from "./executeCommand";
export { extractJsEndpoints } from "./extractJsEndpoints";
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
// Pure patch primitives — reused by the durable runtime's sandbox backend to
// run apex-faithful apply_patch orchestration worker-side (no format drift).
export {
  applyFileDiff,
  type EolAdaptation,
  PatchApplyError,
} from "./patchApply";
export { type ParsedFileDiff, parseUnifiedDiff } from "./patchParse";
// Per-command executor — one fresh process group per tool invocation.
export {
  PerCommandShell,
  readSandboxAgentEnv,
  type ShellExecuteOptions,
  type ShellExecuteResult,
} from "./perCommandShell";
// Playwright MCP browser session helpers.
export {
  type BrowserClickResult,
  type BrowserConsoleResult,
  type BrowserEngine,
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
  SandboxBrowserBackend,
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
export {
  SMS_LIST_MESSAGES_TOOL_NAME,
  SMS_TOOL_NAMES,
  sessionHasSmsPasswordless,
  smsListMessages,
} from "./smsListMessages";
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

import type { ToolSet } from "ai";
import { addMemory } from "./addMemory";
import { applyPatch } from "./applyPatch";
import {
  ASK_USER_QUESTIONS_TOOL_NAME,
  askUserQuestions,
} from "./askUserQuestions";
import {
  type BrowserToolsetFactories,
  type createBrowserToolset,
  createBrowserToolsetFactories,
} from "./browserTools";
import { checkpointState } from "./checkpointState";
import { completeAuthentication } from "./completeAuthentication";
import { crawlAuthenticated } from "./crawlAuthenticated";
import { createAttackSurfaceReport } from "./createAttackSurfaceReport";
import { createFile } from "./createFile";
import { createTask } from "./createTask";
import { delegateAuth } from "./delegateAuth";
import { deleteFile } from "./deleteFile";
import { detectAuthScheme } from "./detectAuthScheme";
import { documentApp } from "./documentApp";
import { documentEndpoint } from "./documentEndpoint";
import { documentEndpoints } from "./documentEndpoints";
import { documentVulnerability } from "./documentFinding";
import {
  emailGetAttachments,
  emailGetMessage,
  emailListInboxes,
  emailListMessages,
  emailMarkRead,
  emailSearchMessages,
  sendEmail,
} from "./email";
import { executeCommand } from "./executeCommand";
import { extractJsEndpoints } from "./extractJsEndpoints";
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
import { runAttackSurface } from "./runAttackSurface";
import { runCodeQuery } from "./runCodeQuery";
import { runPentestWorkflow } from "./runPentestWorkflow";
import { runWhiteboxScan } from "./runWhiteboxScan";
import { smsListMessages } from "./smsListMessages";
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
 * Canonical ordered tool registry: entry order is the provider schema order
 * and must match the historical `createAllTools` layout. Browser members
 * share one group state per construction call; each member's tool is built
 * individually, so an unselected sibling is never constructed.
 */
type ToolFactoryEntry = {
  name: string;
  factory?: (ctx: ToolContext) => unknown;
  /** Group provider for member tools that share construction state. */
  group?: (ctx: ToolContext) => Record<string, () => unknown>;
  member?: string;
  /** When false the factory is never invoked (conditional availability). */
  available?: (ctx: ToolContext) => boolean;
};

function browserEntry<N extends string & keyof BrowserToolsetFactories>(
  name: N,
) {
  return {
    name,
    group: createBrowserToolsetFactories,
    member: name,
  };
}

const TOOL_REGISTRY = [
  // Browser automation tools (8 tools from Playwright MCP)
  browserEntry("browser_navigate"),
  browserEntry("browser_snapshot"),
  browserEntry("browser_screenshot"),
  browserEntry("browser_click"),
  browserEntry("browser_fill"),
  browserEntry("browser_evaluate"),
  browserEntry("browser_console"),
  browserEntry("browser_get_cookies"),

  // Core pentest tools
  { name: "execute_command", factory: executeCommand },
  { name: "http_request", factory: httpRequest },
  { name: "document_vulnerability", factory: documentVulnerability },

  // Filesystem / search tools
  { name: "read_file", factory: readFile },
  { name: "list_files", factory: listFiles },
  { name: "glob", factory: globFiles },
  { name: "grep", factory: grep },
  { name: "profile_codebase", factory: profileCodebase },
  { name: "query_whitebox_catalog", factory: queryWhiteboxCatalog },
  { name: "run_code_query", factory: runCodeQuery },
  { name: "create_file", factory: createFile },
  { name: "update_file", factory: updateFile },
  { name: "delete_file", factory: deleteFile },
  { name: "apply_patch", factory: applyPatch },
  { name: "git_status", factory: gitStatus },
  { name: "git_diff", factory: gitDiff },

  // Attack surface / recon tools
  { name: "document_app", factory: documentApp },
  { name: "document_endpoint", factory: documentEndpoint },
  { name: "document_endpoints", factory: documentEndpoints },
  { name: "list_workspace_domains", factory: listWorkspaceDomains },
  { name: "create_workspace_domain", factory: createWorkspaceDomain },
  { name: "list_workspace_apps", factory: listWorkspaceApps },
  { name: "create_workspace_app", factory: createWorkspaceApp },
  { name: "update_workspace_app", factory: updateWorkspaceApp },
  { name: "list_workspace_endpoints", factory: listWorkspaceEndpoints },
  { name: "create_workspace_endpoint", factory: createWorkspaceEndpoint },
  { name: "update_workspace_endpoint", factory: updateWorkspaceEndpoint },
  { name: "delegate_to_auth_subagent", factory: delegateAuth },
  { name: "extract_js_endpoints", factory: extractJsEndpoints },
  { name: "crawl_authenticated_area", factory: crawlAuthenticated },
  { name: "test_endpoint_variations", factory: testEndpointVariations },
  { name: "validate_discovery_completeness", factory: validateDiscovery },
  { name: "create_attack_surface_report", factory: createAttackSurfaceReport },

  // Authentication tools
  { name: "complete_authentication", factory: completeAuthentication },
  { name: "detect_auth_scheme", factory: detectAuthScheme },
  { name: "probe_auth_endpoints", factory: probeAuthEndpoints },

  // Orchestration tools
  { name: "run_attack_surface", factory: runAttackSurface },
  { name: "spawn_pentest_swarm", factory: spawnPentestSwarm },
  { name: "spawn_pentest_agent", factory: spawnPentestAgent },
  { name: "spawn_coding_agent", factory: spawnCodingAgent },
  { name: "run_pentest_workflow", factory: runPentestWorkflow },
  { name: "run_whitebox_scan", factory: runWhiteboxScan },
  { name: "create_whitebox_candidate", factory: createWhiteboxCandidate },
  { name: "update_whitebox_candidate", factory: updateWhiteboxCandidate },
  { name: "list_whitebox_candidates", factory: listWhiteboxCandidates },
  { name: "start_whitebox_job", factory: startWhiteboxJob },
  { name: "poll_whitebox_job", factory: pollWhiteboxJob },
  { name: "stop_whitebox_job", factory: stopWhiteboxJob },
  { name: "read_whitebox_artifact", factory: readWhiteboxArtifact },

  // Reporting / benchmark tools
  { name: "provide_comparison_results", factory: provideComparisonResults },

  // Memory tools (persistent cross-session knowledge)
  { name: "add_memory", factory: addMemory },
  { name: "list_memories", factory: listMemories },
  { name: "get_memory", factory: getMemory },

  // Prompt-injection test catalog (safe metadata only; no raw payloads)
  { name: "list_prompt_injections", factory: listPromptInjections },

  // Email tools (inbox + outbound — gated at activeTools level by base class)
  { name: "email_list_inboxes", factory: emailListInboxes },
  { name: "email_list_messages", factory: emailListMessages },
  { name: "email_get_message", factory: emailGetMessage },
  { name: "email_search_messages", factory: emailSearchMessages },
  { name: "email_get_attachments", factory: emailGetAttachments },
  { name: "email_mark_read", factory: emailMarkRead },
  { name: "send_email", factory: sendEmail },

  // Inbound SMS list (gated at activeTools level when no Mobile OTP cred)
  { name: "sms_list_messages", factory: smsListMessages },

  // Web search tools (requires Pensar account)
  { name: "web_search", factory: webSearch },
  { name: "get_page", factory: getPage },

  // Skill tools (conditional — only when registry is provided)
  {
    name: "read_skill",
    factory: readSkill,
    available: (ctx) => Boolean(ctx.skillsRegistry),
  },

  { name: ASK_USER_QUESTIONS_TOOL_NAME, factory: askUserQuestions },

  // Observability tools (conditional — only when trace writer is provided)
  {
    name: "checkpoint_state",
    factory: checkpointState,
    available: (ctx) => Boolean(ctx.traceWriter),
  },

  // Task decomposition tools (conditional — only when tasksDir is configured)
  {
    name: "create_task",
    factory: createTask,
    available: (ctx) => Boolean(ctx.tasksDir),
  },
  {
    name: "update_task",
    factory: updateTask,
    available: (ctx) => Boolean(ctx.tasksDir),
  },
  {
    name: "list_tasks",
    factory: listTasksTool,
    available: (ctx) => Boolean(ctx.tasksDir),
  },

  // Plan mode tools
  { name: "write_plan", factory: writePlan },
  { name: "submit_plan", factory: submitPlan },
] as const satisfies readonly ToolFactoryEntry[];

/** Registry order is the canonical schema order; grouped factories appear once per member. */
const REGISTRY_VIEW: readonly ToolFactoryEntry[] = TOOL_REGISTRY;

export function listToolRegistryNames(ctx: ToolContext): string[] {
  return REGISTRY_VIEW.filter((entry) =>
    entry.available ? entry.available(ctx) : true,
  ).map((entry) => entry.name);
}

/** Per-entry tool type: direct factories keep their ReturnType; group members resolve through the group. */
type ToolOf<E extends ToolFactoryEntry> = E extends {
  group: (ctx: ToolContext) => infer G;
  member: infer M;
}
  ? G extends Record<string, () => unknown>
    ? M extends keyof G
      ? ReturnType<G[M]>
      : never
    : never
  : E extends { factory: (ctx: ToolContext) => infer T }
    ? T
    : never;

type RegistryEntry = (typeof TOOL_REGISTRY)[number];

type EntryName<E> = E extends { name: infer N extends string } ? N : never;

/** Unconditional entries: always present with their factory's tool type. */
type UnconditionalTools = {
  [E in Exclude<
    RegistryEntry,
    { available: (ctx: ToolContext) => boolean }
  > as EntryName<E>]: ToolOf<E>;
};

/**
 * Full catalog record. Conditional entries are optional keys, matching the
 * parent's conditional spreads; the browser block comes from the compat
 * wrapper's inferred record so it stays assignable to the baseline shape.
 */
export type AllToolsRecord = Omit<
  UnconditionalTools,
  keyof ReturnType<typeof createBrowserToolset>
> &
  ReturnType<typeof createBrowserToolset> &
  Partial<{
    [E in Extract<
      RegistryEntry,
      { available: (ctx: ToolContext) => boolean }
    > as EntryName<E>]: ToolOf<E>;
  }>;

export function createAllTools(ctx: ToolContext): AllToolsRecord {
  return createToolsForNames(ctx, undefined) as AllToolsRecord;
}

/**
 * Construct only the requested tools, in registry order; duplicates and
 * unknown names are ignored, unavailable entries are never constructed, and
 * DefineOwnProperty keeps prototype-shaped names own keys.
 */
export function createToolsForNames(
  ctx: ToolContext,
  requested: readonly string[] | undefined,
): ToolSet {
  const groupCache = new Map<
    (ctx: ToolContext) => Record<string, () => unknown>,
    Record<string, () => unknown>
  >();
  const wanted = requested ? new Set(requested) : null;
  const tools: Record<string, unknown> = {};
  for (const entry of REGISTRY_VIEW) {
    if (wanted && !wanted.has(entry.name)) continue;
    if (entry.available && !entry.available(ctx)) continue;
    const tool = entry.group
      ? memberTool(groupCache, entry.group, ctx, entry.member ?? entry.name)
      : entry.factory?.(ctx);
    if (tool !== undefined) {
      Object.defineProperty(tools, entry.name, {
        value: tool,
        enumerable: true,
        writable: true,
        configurable: true,
      });
    }
  }
  return tools as ToolSet;
}

function memberTool(
  groupCache: Map<
    (ctx: ToolContext) => Record<string, () => unknown>,
    Record<string, () => unknown>
  >,
  group: (ctx: ToolContext) => Record<string, () => unknown>,
  ctx: ToolContext,
  member: string,
): unknown {
  let members = groupCache.get(group);
  if (!members) {
    members = group(ctx);
    groupCache.set(group, members);
  }
  return members[member]?.();
}

/** Union of all registered tool names (finite literal union). */
export type ToolName = RegistryEntry["name"];

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
  "document_endpoints",
  ...WORKSPACE_TOOL_NAMES,
  "delegate_to_auth_subagent",
  "create_attack_surface_report",
  "complete_authentication",
  "run_attack_surface",
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
  "sms_list_messages",
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
 * document_app, document_endpoint, document_endpoints, create_workspace_domain,
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
  // Email / SMS (read-only)
  "email_list_inboxes",
  "email_list_messages",
  "email_get_message",
  "email_search_messages",
  "email_get_attachments",
  "sms_list_messages",
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

/** SMS list tool names — filtered out by the base class when no Mobile OTP credential is present. */
export { SMS_TOOL_NAMES as SMS_TOOL_NAMES_ACTIVE } from "./smsListMessages";
