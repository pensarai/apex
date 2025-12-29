/**
 * HITL (Human-in-the-Loop) Module
 *
 * Provides approval gates, permission tiers, and stage management
 * for interactive pentesting sessions.
 */

// Types
export type {
  PermissionTier,
  TierDefinition,
  HITLMode,
  HITLStage,
  StageDefinition,
  PendingApproval,
  ApprovalDecision,
  ActionHistoryEntry,
  StageProgress,
  HITLSessionState,
  HITLSettings,
  HITLEvent,
} from "./types";

export {
  PERMISSION_TIERS,
  HITL_MODES,
  HITL_STAGES,
  getStagesInOrder,
  getNextStage,
  createInitialHITLState,
  HITLSettingsObject,
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
