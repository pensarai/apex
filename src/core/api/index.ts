// The package's public API surface.
//
// Two consumers:
// 1. External programmatic users — should import from "./core/api" (this barrel).
// 2. src/cli.ts — uses dynamic per-feature imports
//    (await import("./core/api/<feature>")) so `bun build --splitting`
//    produces per-feature chunks. Routing those through this barrel would
//    eliminate the split. The lint rule for module barriers exempts this.

export type {
  LanceMetrics,
  LanceOptions,
  ObjectiveCandidate,
  ObjectiveVerification,
} from "../agents/lance";
export { LANCE_CONFIG, LANCE_DESCRIPTION } from "../agents/lance";
export type {
  FindingPolicy,
  OffensiveSecurityAgentInput,
} from "../agents/offSecAgent";
export { EXTERNAL_FINDING_POLICY_CAPABILITY } from "../agents/offSecAgent";
export type {
  CreateNativeRolloutEvidenceCaptureInput,
  NativeRolloutCaptureLimits,
  NativeRolloutCaptureReportV1,
  NativeRolloutEvidenceCapture,
  NativeRolloutEvidenceEnvelopeV1,
  NativeRolloutEvidenceSink,
  NativeRolloutModelContext,
} from "../ai";
export {
  createNativeRolloutEvidenceCapture,
  DEFAULT_NATIVE_ROLLOUT_CAPTURE_LIMITS,
} from "../ai";
export type {
  RunCheckpointStore,
  SessionEvidence,
} from "../runtime/runCheckpointStore";
export type { ContextReference, ContextStore } from "../runtime/runContext";
export type {
  ApprovalDecision,
  RecordedApproval,
  RunControlIntent,
  RunControlRecord,
  RunControlStore,
} from "../runtime/runControlStore";
export { inspectSessionEvidence } from "../runtime/runEvidence";
export type {
  RecordedModelAttempt,
  RecordedRetry,
  RunModelStore,
} from "../runtime/runModelStore";
export type { RecordedRunSpec, RunRecord, RunStore } from "../runtime/runStore";
export type {
  RecordedToolInput,
  RecordedToolOperation,
  RecordedToolPolicy,
  RunToolStore,
} from "../runtime/runToolStore";
export { openSqliteRunStore } from "../runtime/sqliteRunStore";
export type {
  EngagementContextProvider,
  EngagementTarget,
} from "../workflows/engagementPlan";
export type {
  PentestWorkflowInput,
  PentestWorkflowResult,
} from "../workflows/pentest";
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
export type { EngagementPentestInput } from "./engagementPentest";
export { runEngagementPentest } from "./engagementPentest";
export type { EnvironmentAgentInput, EnvironmentResult } from "./environment";
export { runEnvironmentAgent } from "./environment";
export type {
  AgentLogEntry,
  ClosedDisposition,
  CommentAuthor,
  DispatchPentestInput,
  DispatchPentestResult,
  FixDetail,
  FixSummary,
  IssueCommentPage,
  IssueCommentSummary,
  IssueDetail,
  IssueEvidence,
  IssueRetest,
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
  CLOSED_DISPOSITIONS,
  createIssueComment,
  dispatchPentest,
  getFix,
  getIssue,
  getIssueEvidence,
  getScan,
  linkPullRequest,
  listAgentLogs,
  listFixes,
  listIssueComments,
  listIssuePullRequests,
  listIssueRetests,
  listIssues,
  listPentestTargets,
  listScans,
  listTargetLogs,
  retestIssue,
  searchAgentLogs,
  searchTargetLogs,
  updateIssue,
} from "./issues";
export type {
  KnowledgeCategory,
  KnowledgeEntry,
  KnowledgeInput,
  KnowledgeStatus,
} from "./knowledge";
export {
  archiveKnowledge,
  createKnowledge,
  getKnowledge,
  KNOWLEDGE_CATEGORIES,
  KNOWLEDGE_STATUSES,
  listKnowledge,
  updateKnowledge,
} from "./knowledge";
export { type RunLanceInput, runLance } from "./lance";
export { serveLocalRunWorker } from "./localWorker";
export type {
  OffensiveSecurityAgentClientInput,
  RunAgentResult,
} from "./offesecAgent";
export {
  createOffensiveSecurityAgentClient,
  runOffensiveSecurityAgent,
} from "./offesecAgent";
export type { PatchingAgentInput, PatchResult } from "./patching";
export { runPatchingAgent } from "./patching";
export type {
  RecordedRunAgentInput,
  RecordedRunOutcome,
  ResumeRecordedAgentInput,
} from "./recordedRun";
export {
  RunRecoveryBlockedError,
  resumeRecordedAgent,
  runRecordedAgent,
} from "./recordedRun";
export { runTargetedPentestAgent } from "./targetedPentest";
export type {
  ThreatModelWorkflowInput,
  ThreatModelWorkflowResult,
} from "./threatModel";
export { runThreatModelWorkflow } from "./threatModel";
export type {
  TrajectoryEvidenceFile,
  TrajectoryExportErrorCode,
  TrajectoryExportFile,
  TrajectoryExportInput,
  TrajectoryExportResult,
} from "./trajectoryExport";
export {
  exportTrajectoryBundle,
  TrajectoryExportError,
} from "./trajectoryExport";
export type {
  VulnerabilityReportAnswerKey,
  VulnerabilityReproductionAgentInput,
  VulnerabilityReproductionHandle,
  VulnerabilityReproductionResult,
} from "./vulnerabilityReproduction";
export {
  runVulnerabilityReproductionAgent,
  startVulnerabilityReproductionAgent,
  VulnerabilityReproductionResultSchema,
  VulnerabilityReproductionStepSchema,
  VulnerabilityReproductionVerdictSchema,
} from "./vulnerabilityReproduction";
