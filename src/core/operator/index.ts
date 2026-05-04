/**
 * Operator Module
 *
 * Provides approval gates, permission tiers, and stage management
 * for interactive pentesting sessions.
 */

// Types
export type {
  PermissionTier,
  CommandIntent,
  ClassifierMode,
  ClassificationSource,
  ToolClassification,
  TierDefinition,
  OperatorMode,
  OperatorStage,
  StageDefinition,
  PendingApproval,
  ApprovalDecision,
  ActionHistoryEntry,
  StageProgress,
  OperatorSessionState,
  OperatorSettings,
  OperatorEvent,
} from "./types";

export {
  PERMISSION_TIERS,
  OPERATOR_MODES,
  OPERATOR_MODE_CYCLE,
  OPERATOR_STAGES,
  getStagesInOrder,
  getNextStage,
  createInitialOperatorState,
  OperatorSettingsObject,
} from "./types";

// Tool Classifier
export {
  COMMAND_CLASSIFIER_VERSION,
  DEFAULT_CLASSIFIER_TIMEOUT_MS,
  DEFAULT_CLASSIFIER_CACHE_TTL_MS,
  DEFAULT_CLASSIFIER_CACHE_MAX_ENTRIES,
  DEFAULT_MIN_CLASSIFIER_CONFIDENCE,
  classifyToolCall,
  classifyToolCallDetailed,
  classifyToolCallWithRules,
  clearClassificationCache,
  getClassificationReason,
  type ToolClassificationContext,
  type CommandClassifierOptions,
} from "./toolClassifier";

// Permission Policy
export {
  checkPermission,
  shouldAutoApprove,
  getApprovalRequirement,
  getPolicySummary,
  type PermissionPolicyConfig,
  type PermissionCheckResult,
} from "./permissionPolicy";

// Approval Gate
export {
  ApprovalGate,
  ApprovalBlockedError,
  ApprovalDeniedError,
  ApprovalTimeoutError,
  DEFAULT_DECISION_TIMEOUT_MS,
  wrapToolWithApproval,
  type ApprovalGateConfig,
} from "./approvalGate";

// Stage Manager
export { StageManager } from "./stageManager";

// Stage Inference
export {
  inferStageFromDirective,
  type StageInferenceResult,
} from "./stageInference";
