import { EventEmitter } from "events";
import { randomBytes } from "crypto";
import type {
  OperatorMode,
  OperatorStage,
  PermissionTier,
  PendingApproval,
  ApprovalDecision,
  ActionHistoryEntry,
  OperatorEvent,
} from "./types";
import { classifyToolCall } from "./toolClassifier";
import { checkPermission, shouldBlockAction } from "./permissionPolicy";

/**
 * Approval gate configuration
 */
export interface ApprovalGateConfig {
  mode: OperatorMode;
  autoApproveTier: PermissionTier;
  /** Current operator stage - used for stage-aware auto-approval */
  currentStage?: OperatorStage;
  /** Tools to auto-approve in test/validate stages (offensive mode) */
  offensiveStageTools?: string[];
}

/**
 * Deferred promise for pending approvals
 */
interface DeferredApproval {
  approval: PendingApproval;
  resolve: (decision: ApprovalDecision) => void;
  reject: (error: Error) => void;
}

/**
 * ApprovalGate intercepts tool calls and manages the approval workflow
 */
export class ApprovalGate extends EventEmitter {
  private config: ApprovalGateConfig;
  private pendingApprovals: Map<string, DeferredApproval> = new Map();
  private actionHistory: ActionHistoryEntry[] = [];

  constructor(config: ApprovalGateConfig) {
    super();
    this.config = config;
  }

  /**
   * Update the gate configuration (e.g., when mode changes)
   */
  updateConfig(config: Partial<ApprovalGateConfig>): void {
    this.config = { ...this.config, ...config };
    this.emit("config-changed", this.config);
  }

  /**
   * Get current configuration
   */
  getConfig(): ApprovalGateConfig {
    return { ...this.config };
  }

  /**
   * Get pending approvals
   */
  getPendingApprovals(): PendingApproval[] {
    return Array.from(this.pendingApprovals.values()).map((d) => d.approval);
  }

  /**
   * Get action history
   */
  getActionHistory(): ActionHistoryEntry[] {
    return [...this.actionHistory];
  }

  /**
   * Check if a tool call is allowed and handle approval if needed
   * Returns a promise that resolves when approved or rejects when denied/blocked
   */
  async check(
    toolName: string,
    toolCallId: string,
    args: Record<string, unknown>
  ): Promise<ApprovalDecision> {
    const tier = classifyToolCall({ toolName, args });

    // Check if action should be blocked entirely (plan mode)
    if (shouldBlockAction(tier, this.config.mode)) {
      const entry = this.recordAction(toolName, toolCallId, tier, "denied");
      this.emitEvent({ type: "action-completed", entry });
      throw new ApprovalBlockedError(
        `Action blocked in plan mode (tier ${tier})`,
        tier
      );
    }

    // Stage-aware auto-approval: Auto-approve offensive tools in test/validate stages
    const isOffensiveStage = ["test", "validate"].includes(this.config.currentStage || "");
    const isOffensiveTool = this.config.offensiveStageTools?.includes(toolName);
    if (isOffensiveStage && isOffensiveTool && tier <= 3) {
      const entry = this.recordAction(toolName, toolCallId, tier, "auto-approved");
      this.emitEvent({ type: "action-completed", entry });
      return "auto-approved";
    }

    // Check permission policy
    const result = checkPermission(tier, this.config);

    if (result.autoApproved) {
      const entry = this.recordAction(toolName, toolCallId, tier, "auto-approved");
      this.emitEvent({ type: "action-completed", entry });
      return "auto-approved";
    }

    // Need manual approval - create pending approval
    return this.requestApproval(toolName, toolCallId, args, tier);
  }

  /**
   * Request manual approval for a tool call
   */
  private requestApproval(
    toolName: string,
    toolCallId: string,
    args: Record<string, unknown>,
    tier: PermissionTier
  ): Promise<ApprovalDecision> {
    const approval: PendingApproval = {
      id: `apr_${Date.now()}_${randomBytes(4).toString("hex")}`,
      toolName,
      toolCallId,
      args,
      tier,
      timestamp: Date.now(),
    };

    return new Promise((resolve, reject) => {
      const deferred: DeferredApproval = { approval, resolve, reject };
      this.pendingApprovals.set(approval.id, deferred);

      // Emit event for UI to show approval prompt
      this.emitEvent({ type: "approval-needed", approval });
    });
  }

  /**
   * Approve a pending approval
   */
  approve(approvalId: string): void {
    const deferred = this.pendingApprovals.get(approvalId);
    if (!deferred) {
      throw new Error(`No pending approval with id: ${approvalId}`);
    }

    this.pendingApprovals.delete(approvalId);
    const entry = this.recordAction(
      deferred.approval.toolName,
      deferred.approval.toolCallId,
      deferred.approval.tier,
      "approved"
    );

    this.emitEvent({ type: "approval-resolved", id: approvalId, decision: "approved" });
    this.emitEvent({ type: "action-completed", entry });

    deferred.resolve("approved");
  }

  /**
   * Deny a pending approval
   */
  deny(approvalId: string): void {
    const deferred = this.pendingApprovals.get(approvalId);
    if (!deferred) {
      throw new Error(`No pending approval with id: ${approvalId}`);
    }

    this.pendingApprovals.delete(approvalId);
    const entry = this.recordAction(
      deferred.approval.toolName,
      deferred.approval.toolCallId,
      deferred.approval.tier,
      "denied"
    );

    this.emitEvent({ type: "approval-resolved", id: approvalId, decision: "denied" });
    this.emitEvent({ type: "action-completed", entry });

    deferred.reject(new ApprovalDeniedError("Action denied by user"));
  }

  /**
   * Batch approve multiple pending approvals
   */
  batchApprove(approvalIds: string[]): void {
    for (const id of approvalIds) {
      if (this.pendingApprovals.has(id)) {
        this.approve(id);
      }
    }
  }

  /**
   * Approve all pending approvals up to a certain tier
   */
  approveUpToTier(maxTier: PermissionTier): void {
    for (const [id, deferred] of this.pendingApprovals) {
      if (deferred.approval.tier <= maxTier) {
        this.approve(id);
      }
    }
  }

  /**
   * Deny all pending approvals
   */
  denyAll(): void {
    for (const id of this.pendingApprovals.keys()) {
      this.deny(id);
    }
  }

  /**
   * Record an action in the history
   */
  private recordAction(
    toolName: string,
    toolCallId: string,
    tier: PermissionTier,
    decision: ApprovalDecision
  ): ActionHistoryEntry {
    const entry: ActionHistoryEntry = {
      id: `act_${Date.now()}_${randomBytes(4).toString("hex")}`,
      toolName,
      toolCallId,
      tier,
      decision,
      timestamp: Date.now(),
    };

    this.actionHistory.push(entry);

    // Keep history bounded (last 100 entries)
    if (this.actionHistory.length > 100) {
      this.actionHistory.shift();
    }

    return entry;
  }

  /**
   * Emit a typed Operator event
   */
  private emitEvent(event: OperatorEvent): void {
    this.emit(event.type, event);
    this.emit("operator-event", event);
  }
}

/**
 * Error thrown when an action is blocked (e.g., in plan mode)
 */
export class ApprovalBlockedError extends Error {
  tier: PermissionTier;

  constructor(message: string, tier: PermissionTier) {
    super(message);
    this.name = "ApprovalBlockedError";
    this.tier = tier;
  }
}

/**
 * Error thrown when an action is denied by the user
 */
export class ApprovalDeniedError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ApprovalDeniedError";
  }
}

/**
 * Create a tool wrapper that integrates with the approval gate
 */
export function wrapToolWithApproval<TArgs extends Record<string, unknown>, TResult>(
  gate: ApprovalGate,
  toolName: string,
  originalTool: (args: TArgs) => Promise<TResult>
): (args: TArgs & { toolCallId?: string }) => Promise<TResult> {
  return async (args) => {
    const toolCallId = args.toolCallId || `tc_${Date.now()}_${randomBytes(4).toString("hex")}`;
    const { toolCallId: _, ...toolArgs } = args;

    // Check approval
    await gate.check(toolName, toolCallId, toolArgs as Record<string, unknown>);

    // Execute the tool
    return originalTool(toolArgs as TArgs);
  };
}
