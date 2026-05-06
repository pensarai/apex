/**
 * Operator Module
 *
 * Provides approval gates, permission tiers, and stage management
 * for interactive pentesting sessions.
 */

// Approval Gate
export {
  ApprovalBlockedError,
  ApprovalDeniedError,
  ApprovalGate,
  type ApprovalGateConfig,
  ApprovalTimeoutError,
  DEFAULT_DECISION_TIMEOUT_MS,
  INTERNAL_ID_PATTERN,
  wrapToolWithApproval,
} from "./approvalGate";
// Permission Policy
export {
  checkPermission,
  getApprovalRequirement,
  getPolicySummary,
  type PermissionCheckResult,
  type PermissionPolicyConfig,
  shouldAutoApprove,
} from "./permissionPolicy";
// Stage Inference
export {
  inferStageFromDirective,
  type StageInferenceResult,
} from "./stageInference";
// Stage Manager
export { StageManager } from "./stageManager";
// Tool Classifier
export {
  classifyToolCall,
  getClassificationReason,
  type ToolClassificationContext,
} from "./toolClassifier";
// Types
export type {
  ActionHistoryEntry,
  ApprovalDecision,
  OperatorEvent,
  OperatorMode,
  OperatorSessionState,
  OperatorSettings,
  OperatorStage,
  PendingApproval,
  PermissionTier,
  StageDefinition,
  StageProgress,
  TierDefinition,
} from "./types";
export {
  createInitialOperatorState,
  getNextStage,
  getStagesInOrder,
  OPERATOR_MODE_CYCLE,
  OPERATOR_MODES,
  OPERATOR_STAGES,
  OperatorSettingsObject,
  PERMISSION_TIERS,
} from "./types";
