/**
 * Operator Module
 *
 * Provides approval gates, permission tiers, and stage management
 * for interactive pentesting sessions.
 */

// Approval Gate
export {
  ApprovalDeniedError,
  ApprovalGate,
  type ApprovalGateConfig,
  INTERNAL_ID_PATTERN,
} from "./approvalGate";
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
} from "./types";
export {
  createInitialOperatorState,
  OPERATOR_MODE_CYCLE,
  OPERATOR_MODES,
} from "./types";
