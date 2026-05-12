// The package's public API surface — intentionally narrow.
//
// This barrel exposes only light symbols (URL/config getters + the
// Pensar Issues REST client). Heavy feature wrappers that construct
// agent classes — runOffensiveSecurityAgent, runAttackSurfaceAgent,
// runPatchingAgent, runEnvironmentAgent, runAuthenticationAgent,
// runBenchmarkComparisonAgent, runPentestAgent, runTargetedPentestAgent,
// runThreatModelWorkflow — must be imported from their per-feature path:
//
//   import { runOffensiveSecurityAgent } from "@pensar/apex/src/core/api/offesecAgent";
//
// Re-exporting these wrappers from the barrel would drag each agent's
// full transitive tree (~50+ tool/prompt/schema files) into any consumer
// that imports anything from `core/api`, even for unrelated symbols.
// See apex#749 for the root-cause investigation.
//
// Consumers:
// 1. External programmatic users (e.g. pensarai/console).
// 2. src/cli.ts — already uses dynamic per-feature imports
//    (await import("./core/api/<feature>")) so `bun build --splitting`
//    produces per-feature chunks. The lint rule for module barriers
//    exempts this file.

export {
  getPensarApiUrl,
  getPensarConsoleUrl,
  getPensarGatewayUrl,
  PENSAR_API_BASE_URL,
  PENSAR_CONSOLE_BASE_URL,
} from "./constants";
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
