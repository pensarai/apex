// ---------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------

export type { AgentEventMap } from "../../eventBus";
// ---------------------------------------------------------------------------
// Event Bus
// ---------------------------------------------------------------------------
export { AgentEventBus } from "../../eventBus";
export { OffensiveSecurityAgent } from "./offensiveSecurityAgent";
// ---------------------------------------------------------------------------
// System prompts
// ---------------------------------------------------------------------------
export {
  BASE_SYSTEM_PROMPT,
  type BaseSystemPromptOptions,
  buildBaseSystemPrompt,
  buildProvidedFilesSection,
  buildSessionWorkspaceSection,
} from "./prompt";
// ---------------------------------------------------------------------------
// Tools — re-exported via the tools barrel.
// ---------------------------------------------------------------------------
export {
  addMemory,
  ALL_TOOL_NAMES,
  ASK_USER_QUESTIONS_TOOL_NAME,
  AskUserQuestionSchema,
  assertCommandInScope,
  assertUrlInScope,
  authenticateSession,
  BROWSER_TOOL_NAMES,
  checkpointState,
  checkSandboxPlaywright,
  completeAuthentication,
  crawlAuthenticated,
  createAllTools,
  createAttackSurfaceReport,
  createBrowserTools,
  createBrowserToolset,
  createEmailToolset,
  createFile,
  createResponseTool,
  createSandboxBrowserTools,
  createTask,
  delegateAuth,
  detectAuthScheme,
  documentApp,
  documentEndpoint,
  documentVulnerability,
  EMAIL_TOOL_NAMES,
  EMAIL_TOOL_NAMES_ACTIVE,
  ensureSandboxBrowser,
  ensureSandboxPlaywright,
  executeCommand,
  extractFallbackStdout,
  extractHostname,
  extractHostsFromCommand,
  extractJsEndpoints,
  getAllowedHosts,
  getApexTmpRoot,
  getMemory,
  getPage,
  grep,
  httpRequest,
  installSandboxPlaywright,
  isHostAllowed,
  listFiles,
  listMemories,
  listTasksTool,
  PersistentShell,
  PLAN_MODE_TOOL_NAMES,
  PlaywrightMcpSession,
  probeAuthEndpoints,
  provideComparisonResults,
  readFile,
  readSkill,
  readTempfileCapped,
  RESPONSE_TOOL_NAME,
  runAttackSurface,
  runPentestWorkflow,
  ScopeViolationError,
  SEND_EMAIL_TOOL_NAME,
  setHeadlessMode,
  setUserAgent,
  setViewportSize,
  SKILL_TOOL_NAMES,
  spawnCodingAgent,
  spawnPentestSwarm,
  submitPlan,
  testEndpointVariations,
  transformScriptToFunction,
  updateFile,
  updateTask,
  validateDiscovery,
  webSearch,
  writePlan,
} from "./tools";
export type {
  AskUserQuestion,
  AskUserQuestionAnswer,
  AskUserQuestionsResult,
  BrowserClickResult,
  BrowserConsoleResult,
  BrowserEvaluateResult,
  BrowserFillResult,
  BrowserNavigateResult,
  BrowserScreenshotResult,
  BrowserToolMode,
  BrowserToolName,
  EmailToolName,
  SandboxExecuteOptions,
  SandboxExecutionResult,
  SandboxType,
  ShellExecuteResult,
  ToolContext,
  ToolName,
  UnifiedSandbox,
} from "./tools";
export type {
  CheckpointInput,
  InitRecord,
  StateCheckpoint,
  StepRecord,
  StepTraceWriterOpts,
  ToolOutputType,
  TraceRecord,
} from "./trace";
// ---------------------------------------------------------------------------
// Trace
// ---------------------------------------------------------------------------
export { StepTraceWriter } from "./trace";
export {
  type AgentMode,
  ApexFindingObject,
  type CommandCancelHandle,
  type CreateAgentInput,
  type Finding,
  type OffensiveSecurityAgentInput,
  type SpecializedAgentInput,
} from "./types";
