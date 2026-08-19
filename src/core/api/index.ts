// The package's public API surface.
//
// Two consumers:
// 1. External programmatic users — should import from "./core/api" (this barrel).
// 2. src/cli.ts — uses dynamic per-feature imports
//    (await import("./core/api/<feature>")) so `bun build --splitting`
//    produces per-feature chunks. Routing those through this barrel would
//    eliminate the split. The lint rule for module barriers exempts this.

export type {
  AgentRedTeamAbuseChain,
  AgentRedTeamArtifact,
  AgentRedTeamAttempt,
  AgentRedTeamAttemptVariant,
  AgentRedTeamCampaign,
  AgentRedTeamCampaignSummary,
  AgentRedTeamCarrier,
  AgentRedTeamCarrierFeature,
  AgentRedTeamCarrierFeatureKind,
  AgentRedTeamCoverageMatrix,
  AgentRedTeamEvaluation,
  AgentRedTeamEvaluationVerdict,
  AgentRedTeamEvent,
  AgentRedTeamEventKind,
  AgentRedTeamEvidenceStrength,
  AgentRedTeamFindingClass,
  AgentRedTeamFindingMetadata,
  AgentRedTeamGoal,
  AgentRedTeamImpact,
  AgentRedTeamMutation,
  AgentRedTeamMutationId,
  AgentRedTeamObservation,
  AgentRedTeamObservationInput,
  AgentRedTeamOracle,
  AgentRedTeamOracleKind,
  AgentRedTeamPrimitive,
  AgentRedTeamPrimitiveId,
  AgentRedTeamPrimitiveVariant,
  AgentRedTeamSeed,
  AgentRedTeamSeedAttemptInput,
  AgentRedTeamSeedProviderStatus,
  AgentRedTeamSeedSource,
  AgentRedTeamSemanticJudge,
  AgentRedTeamSemanticJudgeResult,
  AgentRedTeamSignal,
  AgentRedTeamSignalKind,
  AgentRedTeamSurface,
  AgentRedTeamTechnique,
  AgentRedTeamTechniqueId,
  AgentRedTeamTurn,
  AgentRedTeamVector,
  AgentRedTeamWorkflowInput,
  AgentRedTeamWorkflowResult,
  CoverageItem,
  CoverageStatus,
  CreateAgentRedTeamCampaignInput,
  DecodedView,
  EvaluateAgentRedTeamAttemptInput,
  PromptInjectionLibrarySeedOptions,
  RecordAgentRedTeamObservationInput,
} from "./agentRedTeam";
export {
  AGENT_RED_TEAM_IMPACTS,
  AGENT_RED_TEAM_MUTATIONS,
  AGENT_RED_TEAM_SURFACES,
  AGENT_RED_TEAM_TECHNIQUES,
  AGENT_RED_TEAM_VECTORS,
  AGENT_REDTEAM_DIR,
  AgentRedTeamAttemptLedger,
  AgentRedTeamCarrierRegistry,
  AgentRedTeamFindingMetadataSchema,
  AgentRedTeamMutationRegistry,
  ATTEMPT_LEDGER_FILE,
  BUILTIN_AGENT_RED_TEAM_ABUSE_CHAINS,
  BUILTIN_AGENT_RED_TEAM_CARRIERS,
  BUILTIN_AGENT_RED_TEAM_PRIMITIVES,
  BUILTIN_AGENT_RED_TEAM_TECHNIQUES,
  canaryHash,
  composePrimitivePrompt,
  createAgentRedTeamCampaign,
  createArtifact,
  createCampaignSeed,
  createCoverageMatrix,
  createPromptInjectionLibrarySeedAttempts,
  DEFAULT_AGENT_RED_TEAM_GOALS,
  decodeUnicodeTags,
  decodeViews,
  detectAgentRedTeamCarrierFeatures,
  detectAgentRedTeamSignals,
  EVALUATION_LEDGER_FILE,
  evaluateAgentRedTeamAttempt,
  expectedDetectorBlindSpotForStack,
  finalizeAgentRedTeamCampaign,
  getAgentRedTeamPrimitive,
  hiddenTextView,
  normalizedView,
  OBSERVATION_LEDGER_FILE,
  primitiveStackForTechnique,
  primitiveVariantsForTechnique,
  recordAgentRedTeamObservation,
  runAgentRedTeamWorkflow,
  sha256,
  stableAgentRedTeamId,
  updateCoverageMatrix,
  visibleTextView,
} from "./agentRedTeam";
export type {
  AppDetail,
  ApplicationType,
  AppSummary,
  CreateAppInput,
  CreateEndpointInput,
  DeleteResult,
  EndpointDetail,
  EndpointSummary,
  EndpointTransport,
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
  ENDPOINT_TRANSPORTS,
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
export type { AttackSurfaceInput } from "./attackSurface";
export { runAttackSurfaceAgent } from "./attackSurface";
export type { AuthenticationAgentInput } from "./authentication";
export { runAuthenticationAgent } from "./authentication";
export { runBenchmarkComparisonAgent } from "./benchmark";
export { runPentestAgent } from "./blackboxPentest";
export {
  getPensarApiUrl,
  getPensarConsoleUrl,
  getPensarGatewayUrl,
  PENSAR_API_BASE_URL,
  PENSAR_CONSOLE_BASE_URL,
} from "./constants";
export type {
  CreateDomainInput,
  DomainSummary,
  ListDomainsResult,
} from "./domains";
export { createDomain, listDomains } from "./domains";
export type { EnvironmentAgentInput, EnvironmentResult } from "./environment";
export { runEnvironmentAgent } from "./environment";
export type {
  AgentLogEntry,
  DispatchPentestResult,
  FixDetail,
  FixSummary,
  IssueDetail,
  IssueSummary,
  LinkPullRequestResult,
  ListAgentLogsResult,
  ListTargetLogsResult,
  PentestTargetSummary,
  PullRequestSummary,
  RetestIssueResult,
  ScanDetail,
  ScanSummary,
  SearchAgentLogsResult,
  SearchTargetLogsResult,
  UpdateIssueResult,
} from "./issues";
export {
  dispatchPentest,
  getFix,
  getIssue,
  getScan,
  linkPullRequest,
  listAgentLogs,
  listFixes,
  listIssuePullRequests,
  listIssues,
  listPentestTargets,
  listScans,
  listTargetLogs,
  retestIssue,
  searchAgentLogs,
  searchTargetLogs,
  updateIssue,
} from "./issues";
export type { RunAgentResult } from "./offesecAgent";
export { runOffensiveSecurityAgent } from "./offesecAgent";
export type { PatchingAgentInput, PatchResult } from "./patching";
export { runPatchingAgent } from "./patching";
export { runTargetedPentestAgent } from "./targetedPentest";
export type {
  ThreatModelWorkflowInput,
  ThreatModelWorkflowResult,
} from "./threatModel";
export { runThreatModelWorkflow } from "./threatModel";
