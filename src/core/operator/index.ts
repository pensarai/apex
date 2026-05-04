/**
 * Operator Module
 *
 * Provides approval gates, command classification, and stage management
 * for interactive pentesting sessions.
 */

// Types
export type {
  CommandIntent,
  ToolClassification,
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
