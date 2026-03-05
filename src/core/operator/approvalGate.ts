import { EventEmitter } from "events";
import { randomBytes } from "crypto";
import type {
  PendingApproval,
  ApprovalDecision,
  ActionHistoryEntry,
  OperatorEvent,
} from "./types";

/**
 * Approval gate configuration — simple boolean toggle.
 */
export interface ApprovalGateConfig {
  requireApproval: boolean;
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
 * ApprovalGate intercepts tool calls and manages the approval workflow.
 *
 * When `requireApproval` is true every tool call is held until the
 * operator explicitly approves or denies it.  When false, all calls
 * are auto-approved immediately.
 */
export class ApprovalGate extends EventEmitter {
  private config: ApprovalGateConfig;
  private pendingApprovals: Map<string, DeferredApproval> = new Map();
  private actionHistory: ActionHistoryEntry[] = [];

  constructor(config: ApprovalGateConfig) {
    super();
    this.config = config;
  }

  updateConfig(config: Partial<ApprovalGateConfig>): void {
    this.config = { ...this.config, ...config };
    this.emit("config-changed", this.config);
  }

  getConfig(): ApprovalGateConfig {
    return { ...this.config };
  }

  getPendingApprovals(): PendingApproval[] {
    return Array.from(this.pendingApprovals.values()).map((d) => d.approval);
  }

  getActionHistory(): ActionHistoryEntry[] {
    return [...this.actionHistory];
  }

  /**
   * Check whether a tool call should proceed.
   *
   * If approval is required the call is held until the operator acts.
   * Otherwise it is auto-approved immediately.
   */
  async check(
    toolName: string,
    toolCallId: string,
    args: Record<string, unknown>,
  ): Promise<ApprovalDecision> {
    if (!this.config.requireApproval) {
      const entry = this.recordAction(toolName, toolCallId, "auto-approved");
      this.emitEvent({ type: "action-completed", entry });
      return "auto-approved";
    }

    return this.requestApproval(toolName, toolCallId, args);
  }

  private requestApproval(
    toolName: string,
    toolCallId: string,
    args: Record<string, unknown>,
  ): Promise<ApprovalDecision> {
    const approval: PendingApproval = {
      id: `apr_${Date.now()}_${randomBytes(4).toString("hex")}`,
      toolName,
      toolCallId,
      args,
      tier: 1,
      timestamp: Date.now(),
    };

    return new Promise((resolve, reject) => {
      const deferred: DeferredApproval = { approval, resolve, reject };
      this.pendingApprovals.set(approval.id, deferred);
      this.emitEvent({ type: "approval-needed", approval });
    });
  }

  approve(approvalId: string): void {
    const deferred = this.pendingApprovals.get(approvalId);
    if (!deferred) {
      throw new Error(`No pending approval with id: ${approvalId}`);
    }

    this.pendingApprovals.delete(approvalId);
    const entry = this.recordAction(
      deferred.approval.toolName,
      deferred.approval.toolCallId,
      "approved",
    );

    this.emitEvent({
      type: "approval-resolved",
      id: approvalId,
      decision: "approved",
    });
    this.emitEvent({ type: "action-completed", entry });
    deferred.resolve("approved");
  }

  deny(approvalId: string): void {
    const deferred = this.pendingApprovals.get(approvalId);
    if (!deferred) return;

    this.pendingApprovals.delete(approvalId);
    const entry = this.recordAction(
      deferred.approval.toolName,
      deferred.approval.toolCallId,
      "denied",
    );

    this.emitEvent({
      type: "approval-resolved",
      id: approvalId,
      decision: "denied",
    });
    this.emitEvent({ type: "action-completed", entry });
    deferred.reject(new ApprovalDeniedError("Action denied by user"));
  }

  batchApprove(approvalIds: string[]): void {
    for (const id of approvalIds) {
      if (this.pendingApprovals.has(id)) {
        this.approve(id);
      }
    }
  }

  denyAll(): void {
    for (const id of this.pendingApprovals.keys()) {
      this.deny(id);
    }
  }

  private recordAction(
    toolName: string,
    toolCallId: string,
    decision: ApprovalDecision,
  ): ActionHistoryEntry {
    const entry: ActionHistoryEntry = {
      id: `act_${Date.now()}_${randomBytes(4).toString("hex")}`,
      toolName,
      toolCallId,
      tier: 1,
      decision,
      timestamp: Date.now(),
    };

    this.actionHistory.push(entry);
    if (this.actionHistory.length > 100) {
      this.actionHistory.shift();
    }

    return entry;
  }

  private emitEvent(event: OperatorEvent): void {
    this.emit(event.type, event);
    this.emit("operator-event", event);
  }
}

export class ApprovalBlockedError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ApprovalBlockedError";
  }
}

export class ApprovalDeniedError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ApprovalDeniedError";
  }
}

/**
 * Wrap a tool's execute function with approval-gate logic.
 *
 * When the gate requires approval the wrapped function will block
 * until the operator approves the call.
 */
export function wrapToolWithApproval<
  TArgs extends Record<string, unknown>,
  TResult,
>(
  gate: ApprovalGate,
  toolName: string,
  originalTool: (args: TArgs) => Promise<TResult>,
): (args: TArgs & { toolCallId?: string }) => Promise<TResult> {
  return async (args) => {
    const toolCallId =
      args.toolCallId || `tc_${Date.now()}_${randomBytes(4).toString("hex")}`;
    const { toolCallId: _, ...toolArgs } = args;

    await gate.check(toolName, toolCallId, toolArgs as Record<string, unknown>);
    return originalTool(toolArgs as TArgs);
  };
}
