// The package's public API surface.
//
// Two consumers:
// 1. External programmatic users — should import from "./core/api" (this barrel).
// 2. src/cli.ts — uses dynamic per-feature imports
//    (await import("./core/api/<feature>")) so `bun build --splitting`
//    produces per-feature chunks. Routing those through this barrel would
//    eliminate the split. The lint rule for module barriers exempts this.

export type {
  AppDetail,
  AppSummary,
  ApplicationType,
  CreateAppInput,
  CreateEndpointInput,
  DeleteResult,
  EndpointDetail,
  EndpointSummary,
  EndpointType,
  ListAppsOptions,
  ListAppsPage,
  ListEndpointsFilters,
  ListEndpointsPage,
  SearchAppsOptions,
  SearchAppsResult,
  SearchEndpointsOptions,
  SearchEndpointsResult,
  UpdateAppInput,
  UpdateEndpointInput,
} from "./apps";
export {
  createApp,
  createEndpoint,
  deleteApp,
  deleteEndpoint,
  getApp,
  getEndpoint,
  listApps,
  listAppsAll,
  listEndpoints,
  listEndpointsAll,
  searchApps,
  searchEndpoints,
  updateApp,
  updateEndpoint,
} from "./apps";
export { runAttackSurfaceAgent } from "./attackSurface";
export type { AttackSurfaceInput } from "./attackSurface";
export { runAuthenticationAgent } from "./authentication";
export type { AuthenticationAgentInput } from "./authentication";
export { runBenchmarkComparisonAgent } from "./benchmark";
export { runPentestAgent } from "./blackboxPentest";
export {
  getPensarApiUrl,
  getPensarConsoleUrl,
  getPensarGatewayUrl,
  PENSAR_API_BASE_URL,
  PENSAR_CONSOLE_BASE_URL,
} from "./constants";
export { runEnvironmentAgent } from "./environment";
export type { EnvironmentAgentInput, EnvironmentResult } from "./environment";
export {
  dispatchPentest,
  getFix,
  getIssue,
  getScan,
  listAgentLogs,
  listFixes,
  listIssues,
  listProjects,
  listScans,
  searchAgentLogs,
  updateIssue,
} from "./issues";
export type {
  AgentLogEntry,
  DispatchPentestResult,
  FixDetail,
  FixSummary,
  IssueDetail,
  IssueSummary,
  ListAgentLogsResult,
  ProjectSummary,
  ScanDetail,
  ScanSummary,
  SearchAgentLogsResult,
  UpdateIssueResult,
} from "./issues";
export { runOffensiveSecurityAgent } from "./offesecAgent";
export type { RunAgentResult } from "./offesecAgent";
export { runPatchingAgent } from "./patching";
export type { PatchResult, PatchingAgentInput } from "./patching";
export { runTargetedPentestAgent } from "./targetedPentest";
export { runThreatModelWorkflow } from "./threatModel";
export type {
  ThreatModelWorkflowInput,
  ThreatModelWorkflowResult,
} from "./threatModel";
