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
  OPERATOR_MODES,
  OPERATOR_MODE_CYCLE,
  createInitialOperatorState,
} from "./types";

// Approval Gate
export {
  ApprovalGate,
  ApprovalDeniedError,
  INTERNAL_ID_PATTERN,
} from "./approvalGate";
