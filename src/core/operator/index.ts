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
  shouldAutoApprove,
} from "./permissionPolicy";
// Stage Inference
export { inferStageFromDirective } from "./stageInference";
// Stage Manager
export { StageManager } from "./stageManager";
// Tool Classifier
export {
  classifyToolCall,
  getClassificationReason,
} from "./toolClassifier";
// Types
export type {
  ActionHistoryEntry,
  ApprovalDecision,
  OperatorEvent,
  OperatorMode,
  OperatorSessionState,
  OperatorStage,
  PendingApproval,
  PermissionTier,
  StageDefinition,
  StageProgress,
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
