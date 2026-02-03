/**
 * Operator Module
 *
 * Provides approval gates, permission tiers, and stage management
 * for interactive pentesting sessions.
 */

// Types
export type {
  PermissionTier,
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
  OPERATOR_STAGES,
  getStagesInOrder,
  getNextStage,
  createInitialOperatorState,
  OperatorSettingsObject,
} from "./types";

// Tool Classifier
export {
  classifyToolCall,
  getClassificationReason,
  type ToolClassificationContext,
} from "./toolClassifier";

// Permission Policy
export {
  checkPermission,
  shouldBlockAction,
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
