import { EventEmitter } from "events";
import { randomBytes } from "crypto";
import type {
  PendingApproval,
  ApprovalDecision,
  ActionHistoryEntry,
  OperatorEvent,
  ToolClassification,
} from "./types";
import { classifyToolCall } from "./toolClassifier";

/**
 * Approval gate configuration.
 *
 * Three-field binary model:
 *   - `requireApproval: false` — auto-approve every tool call.
 *   - `requireApproval: true, autoApproveSafe: true` — auto-approve `safe`,
 *     prompt on `destructive` (the "auto" operator mode).
 *   - `requireApproval: true, autoApproveSafe: false` — prompt on everything
 *     (the "manual" operator mode).
 *
 * `decisionTimeoutMs` sets the operator decision SLA: when the operator
 * does not respond within this window, the pending approval is resolved
 * by the default-safe action (currently `"deny"`). `undefined` disables
 * the timeout (operator decides when to act).
 */
export interface ApprovalGateConfig {
  requireApproval: boolean;
  autoApproveSafe?: boolean;
  decisionTimeoutMs?: number;
}

/** Default operator decision SLA when `requireApproval` is true. */
export const DEFAULT_DECISION_TIMEOUT_MS = 15 * 60 * 1000;

interface DeferredApproval {
  approval: PendingApproval;
  resolve: (decision: ApprovalDecision) => void;
  reject: (error: Error) => void;
  timeoutHandle?: ReturnType<typeof setTimeout>;
}

/**
 * ApprovalGate intercepts tool calls and manages the approval workflow.
 *
 * Every call is classified once by the binary `safe | destructive` rules
 * classifier; the 2-branch policy below decides whether it runs immediately
 * or is held for operator review. No separate policy module — under binary,
 * the decision is small enough to live here.
 */
export class ApprovalGate extends EventEmitter {
  private config: ApprovalGateConfig;
  private pendingApprovals: Map<string, DeferredApproval> = new Map();
  private actionHistory: ActionHistoryEntry[] = [];

  constructor(config: ApprovalGateConfig) {
    super();
    this.config = {
      decisionTimeoutMs: DEFAULT_DECISION_TIMEOUT_MS,
      ...config,
    };
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
   * 1. `requireApproval: false` -> auto-approve every call.
   * 2. `autoApproveSafe` + classification === "safe" -> auto-approve.
   * 3. Everything else -> queue for operator approval.
   */
  async check(
    toolName: string,
    toolCallId: string,
    args: Record<string, unknown>,
  ): Promise<ApprovalDecision> {
    const classification = classifyToolCall({ toolName, args });

    if (!this.config.requireApproval) {
      return this.autoApprove(toolName, toolCallId, classification);
    }

    if (this.config.autoApproveSafe && classification.intent === "safe") {
      return this.autoApprove(toolName, toolCallId, classification);
    }

    return this.requestApproval(toolName, toolCallId, args, classification);
  }

  private autoApprove(
    toolName: string,
    toolCallId: string,
    classification: ToolClassification,
  ): ApprovalDecision {
    const entry = this.recordAction(
      toolName,
      toolCallId,
      "auto-approved",
      classification,
    );
    entry.resultSummary = classification.reasoning;
    this.emitEvent({ type: "action-completed", entry });
    return "auto-approved";
  }

  private requestApproval(
    toolName: string,
    toolCallId: string,
    args: Record<string, unknown>,
    classification: ToolClassification,
  ): Promise<ApprovalDecision> {
    const approval: PendingApproval = {
      id: `apr_${Date.now()}_${randomBytes(4).toString("hex")}`,
      toolName,
      toolCallId,
      args,
      classification,
      timestamp: Date.now(),
    };

    return new Promise((resolve, reject) => {
      const deferred: DeferredApproval = { approval, resolve, reject };
      this.pendingApprovals.set(approval.id, deferred);

      // Enforce the operator decision SLA: on timeout, resolve to the
      // default-safe action (deny) so the agent never hangs on an
      // unresponsive operator.
      const timeoutMs = this.config.decisionTimeoutMs;
      if (timeoutMs !== undefined && timeoutMs > 0) {
        deferred.timeoutHandle = setTimeout(() => {
          this.timeoutApproval(approval.id, timeoutMs);
        }, timeoutMs);
      }

      this.emitEvent({ type: "approval-needed", approval });
    });
  }

  approve(approvalId: string): void {
    if (!this.pendingApprovals.has(approvalId)) {
      throw new Error(`No pending approval with id: ${approvalId}`);
    }
    const settled = this.settleApproval(approvalId, "approved");
    settled!.deferred.resolve("approved");
  }

  deny(approvalId: string): void {
    const settled = this.settleApproval(approvalId, "denied");
    if (!settled) return;
    settled.deferred.reject(new ApprovalDeniedError("Action denied by user"));
  }

  private timeoutApproval(approvalId: string, timeoutMs: number): void {
    const settled = this.settleApproval(
      approvalId,
      "denied",
      `decision_timeout:${timeoutMs}ms`,
    );
    if (!settled) return;
    settled.deferred.reject(
      new ApprovalTimeoutError(
        `Operator decision timeout after ${timeoutMs}ms for ${settled.deferred.approval.toolName} — default-safe deny`,
      ),
    );
  }

  // Shared cleanup for approve/deny/timeout: removes the deferred from the
  // pending map, records history, and emits resolved+completed events.
  // Callers handle the final resolve/reject so the rejection error is local
  // to each path. Returns null when the id is unknown (idempotent denies).
  private settleApproval(
    approvalId: string,
    decision: ApprovalDecision,
    resultSummary?: string,
  ): { entry: ActionHistoryEntry; deferred: DeferredApproval } | null {
    const deferred = this.pendingApprovals.get(approvalId);
    if (!deferred) return null;

    // clearTimeout on an already-fired handle is a documented no-op,
    // so this is safe from the timeout path too.
    if (deferred.timeoutHandle) clearTimeout(deferred.timeoutHandle);
    this.pendingApprovals.delete(approvalId);

    const entry = this.recordAction(
      deferred.approval.toolName,
      deferred.approval.toolCallId,
      decision,
      deferred.approval.classification,
    );
    if (resultSummary) entry.resultSummary = resultSummary;

    this.emitEvent({ type: "approval-resolved", id: approvalId, decision });
    this.emitEvent({ type: "action-completed", entry });
    return { entry, deferred };
  }

  batchApprove(approvalIds: string[]): void {
    for (const id of approvalIds) {
      if (this.pendingApprovals.has(id)) {
        this.approve(id);
      }
    }
  }

  denyAll(): void {
    for (const id of [...this.pendingApprovals.keys()]) {
      this.deny(id);
    }
  }

  private recordAction(
    toolName: string,
    toolCallId: string,
    decision: ApprovalDecision,
    classification: ToolClassification,
  ): ActionHistoryEntry {
    const entry: ActionHistoryEntry = {
      id: `act_${Date.now()}_${randomBytes(4).toString("hex")}`,
      toolName,
      toolCallId,
      classification,
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
 * Raised when an approval request exceeds the operator decision SLA.
 * Extends `ApprovalDeniedError` so callers that already treat denial as
 * fail-closed will treat a timeout the same way.
 */
export class ApprovalTimeoutError extends ApprovalDeniedError {
  constructor(message: string) {
    super(message);
    this.name = "ApprovalTimeoutError";
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
