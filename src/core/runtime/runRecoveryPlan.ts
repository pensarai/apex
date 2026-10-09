import { createHash } from "node:crypto";
import { isDeepStrictEqual } from "node:util";
import type { ModelMessage, ToolResultPart } from "ai";
import { getClaudeCapabilities, getModelInfo } from "../ai";
import type { RecordedApproval } from "./runControlStore";
import type { RecordedModelAttempt, RecordedRetry } from "./runModelStore";
import type {
  RecoveryReconstructionSummary,
  RecoveryRecord,
} from "./runRecoveryStore";
import type { RunRecord } from "./runStore";
import type { RecordedToolOperation } from "./runToolStore";

/** Canonical head as returned by the checkpoint store's getContext. */
export interface RecoveryPlanContext {
  epoch: number;
  revision: number;
  messages: ModelMessage[];
  system: string | null;
}

export interface RecoveryPlanInput {
  record: RunRecord;
  context: RecoveryPlanContext;
  attempts: RecordedModelAttempt[];
  operations: RecordedToolOperation[];
  approvals: RecordedApproval[];
  retries: RecordedRetry[];
  recoveries: RecoveryRecord[];
}

export type RecoveryPlan =
  | { ok: false; blockers: string[] }
  | {
      ok: true;
      messages: ModelMessage[];
      reconstruction: RecoveryReconstructionSummary;
    };

// Deterministic blocked shape from C2 (runControl.ts) — the denial a denied
// approval produced live, reproduced without executing anything.
const DENIED_BY_OPERATOR = {
  type: "json",
  value: { blocked: true, reason: "Denied by operator" },
} as const;

const RECOVERY_NOTE =
  "[Recovery note: the previous execution attempt was interrupted. " +
  "Tool results above are the settled outcomes durably recorded before the " +
  "interruption; uncommitted assistant output from the interrupted request " +
  "was discarded. This is a reconstruction, not a byte-for-byte continuation. " +
  "Continue the task from this state.]";

interface ObservedCall {
  toolCallId: string;
  toolName: string;
  emissionOrder: number;
  attempt: RecordedModelAttempt["attempt"];
  attemptContext: { epoch: number; revision: number } | null;
  attemptIndex: number;
}

const sameContextLink = (
  a: { epoch: number; revision: number },
  b: { epoch: number; revision: number },
) => a.epoch === b.epoch && a.revision === b.revision;

// Owners valid at the current context: the current attempt plus every
// historical fromAttemptId linked through recovery claims ending at it.
// A crash between claim and reconstructed-context commit leaves historical
// operations at the head; those remain reconstructable. Ambiguous or cyclic
// history blocks.
function resolveOwnerLineage(
  runId: string,
  currentAttemptId: string,
  recoveries: RecoveryRecord[],
): { order: Set<string>; blockers: string[] } {
  const blockers: string[] = [];
  const order = new Set([currentAttemptId]);
  const seen = new Set([currentAttemptId]);
  let cursor = currentAttemptId;
  for (;;) {
    const links = recoveries.filter((r) => r.toAttemptId === cursor);
    for (const link of links) {
      if (link.runId !== runId) {
        blockers.push(
          `recovery record ${link.recoveryId} belongs to another run (${link.runId})`,
        );
      }
    }
    if (links.length === 0) break;
    if (links.length > 1) {
      blockers.push(
        `recovery history is ambiguous at execution attempt ${cursor}`,
      );
      break;
    }
    if (links.length > 1) {
      blockers.push(
        `recovery history is ambiguous at execution attempt ${cursor}`,
      );
      break;
    }
    const from = links[0].fromAttemptId;
    if (seen.has(from)) {
      blockers.push("recovery history is cyclic");
      break;
    }
    order.add(from);
    seen.add(from);
    cursor = from;
  }
  return { order, blockers };
}

/**
 * Pure recovery planner: validates the canonical history and, only when the
 * current-revision exchange is provably reconstructible, synthesizes the
 * saved settled tool exchanges (plus an explicit interruption note) onto
 * the canonical head. Never executes tools, never fabricates approvals,
 * never silently drops ambiguity — anything unprovable becomes a blocker.
 */
export function planRunRecovery(input: RecoveryPlanInput): RecoveryPlan {
  const { record, context, attempts, operations, approvals, retries } = input;
  const blockers: string[] = [];

  if (retries.length > 0) {
    blockers.push(
      `run-level retry rows are present (${retries.length}); retry counters cannot be reconstructed`,
    );
  }

  const lineage = resolveOwnerLineage(
    record.spec.runId,
    record.attemptId,
    input.recoveries,
  );
  blockers.push(...lineage.blockers);

  // Duplicates are ambiguous, never silently resolved: a toolCallId seen on
  // multiple model attempts cannot be attributed to one exchange.
  const observed = new Map<string, ObservedCall>();
  const duplicateCalls = new Set<string>();
  attempts.forEach((entry, attemptIndex) => {
    const { attempt } = entry;
    if (attempt.lifecycle === "retried") {
      blockers.push(
        `model attempt ${attempt.attemptId} was part of an SDK retry lineage`,
      );
    }
    if (attempt.lifecycle === "failed") {
      blockers.push(`model attempt ${attempt.attemptId} failed`);
    }
    if (attempt.lineage.sequence > 1) {
      blockers.push(
        `model attempt ${attempt.attemptId} has retry lineage sequence ${attempt.lineage.sequence}`,
      );
    }
    if (!entry.context) {
      blockers.push(`model attempt ${attempt.attemptId} has no context link`);
    } else if (
      entry.context.epoch > context.epoch ||
      entry.context.revision > context.revision
    ) {
      blockers.push(
        `model attempt ${attempt.attemptId} references a future context (${entry.context.epoch}/${entry.context.revision})`,
      );
    }
    entry.toolCalls.forEach((call, emissionOrder) => {
      if (observed.has(call.toolCallId)) {
        duplicateCalls.add(call.toolCallId);
        return;
      }
      observed.set(call.toolCallId, {
        toolCallId: call.toolCallId,
        toolName: call.toolName,
        emissionOrder,
        attempt,
        attemptContext: entry.context,
        attemptIndex,
      });
    });
  });
  for (const toolCallId of duplicateCalls) {
    blockers.push(
      `observed model call ${toolCallId} appears on multiple attempts; its exchange is ambiguous`,
    );
  }

  const atHead = (link: { epoch: number; revision: number }) =>
    sameContextLink(link, context);

  const operationsById = new Map<string, RecordedToolOperation>();
  for (const op of operations) {
    if (operationsById.has(op.toolCallId)) {
      blockers.push(`tool operation ${op.toolCallId} appears multiple times`);
      continue;
    }
    operationsById.set(op.toolCallId, op);
  }
  const approvalsByToolCall = new Map<string, RecordedApproval>();
  for (const approval of approvals) {
    if (approvalsByToolCall.has(approval.toolCallId)) {
      blockers.push(
        `approval ${approval.approvalId} duplicates a decision for tool call ${approval.toolCallId}`,
      );
      continue;
    }
    approvalsByToolCall.set(approval.toolCallId, approval);
  }

  for (const op of operations) {
    if (op.state !== "settled") {
      blockers.push(
        `tool operation ${op.toolCallId} (${op.toolName}) is ${op.state}; its outcome is not provably settled`,
      );
    }
    if (op.toolName === "execute_command") {
      blockers.push(
        "execute_command was used by this run; shell/background state cannot be reconciled",
      );
    }
    if (
      op.context.epoch > context.epoch ||
      op.context.revision > context.revision
    ) {
      blockers.push(
        `tool operation ${op.toolCallId} references a future context (${op.context.epoch}/${op.context.revision})`,
      );
    }
    const call = observed.get(op.toolCallId);
    if (!call) {
      blockers.push(
        `tool operation ${op.toolCallId} has no matching observed model call`,
      );
    } else if (call.toolName !== op.toolName) {
      blockers.push(
        `tool operation ${op.toolCallId} name (${op.toolName}) does not match the observed call (${call.toolName})`,
      );
    } else if (
      call.attemptContext === null ||
      !sameContextLink(call.attemptContext, op.context)
    ) {
      // The operation must bind the same context the call was issued at;
      // a stale epoch with an equal revision is not a match.
      blockers.push(
        `tool operation ${op.toolCallId} context (${op.context.epoch}/${op.context.revision}) does not match its observed attempt's dispatch context`,
      );
    }
    if (!lineage.order.has(op.executionAttemptId)) {
      blockers.push(
        `tool operation ${op.toolCallId} at the current context belongs to an unrelated execution attempt (${op.executionAttemptId})`,
      );
    }
    if (op.output === undefined && op.state === "settled") {
      blockers.push(`settled tool operation ${op.toolCallId} has no output`);
    }
  }

  const specDigest = createHash("sha256")
    .update(JSON.stringify(record.spec))
    .digest("hex");
  for (const approval of approvals) {
    if (
      approval.runId !== record.spec.runId ||
      approval.specDigest !== specDigest
    ) {
      blockers.push(
        `approval ${approval.approvalId} does not match the admitted run and scope`,
      );
    }
    if (approval.state === "pending") {
      blockers.push(
        `approval ${approval.approvalId} (${approval.toolName}) is still pending`,
      );
    }
    if (
      approval.context.epoch > context.epoch ||
      approval.context.revision > context.revision
    ) {
      blockers.push(
        `approval ${approval.approvalId} references a future context (${approval.context.epoch}/${approval.context.revision})`,
      );
    }
    const call = observed.get(approval.toolCallId);
    if (!call) {
      blockers.push(
        `approval ${approval.approvalId} has no matching observed model call`,
      );
    } else if (call.toolName !== approval.toolName) {
      blockers.push(
        `approval ${approval.approvalId} name (${approval.toolName}) does not match the observed call (${call.toolName})`,
      );
    } else if (
      call.attemptContext === null ||
      !sameContextLink(call.attemptContext, approval.context)
    ) {
      blockers.push(
        `approval ${approval.approvalId} context does not match its observed attempt's dispatch context`,
      );
    }
    if (!lineage.order.has(approval.executionAttemptId)) {
      blockers.push(
        `approval ${approval.approvalId} at the current context belongs to an unrelated execution attempt (${approval.executionAttemptId})`,
      );
    }
    const op = operationsById.get(approval.toolCallId);
    if (approval.state === "approved" && !op) {
      blockers.push(
        `approval ${approval.approvalId} was approved but has no committed operation`,
      );
    }
    if (approval.state === "denied" && op) {
      blockers.push(
        `approval ${approval.approvalId} was denied but operation ${op.operationId} exists`,
      );
    }
    if (op) {
      if (!sameContextLink(approval.context, op.context)) {
        blockers.push(
          `approval ${approval.approvalId} and operation ${op.operationId} have mismatched context links`,
        );
      }
      if (
        !isDeepStrictEqual(approval.input, op.input) ||
        approval.executionAttemptId !== op.executionAttemptId
      ) {
        blockers.push(
          `approval ${approval.approvalId} input does not match operation ${op.operationId}`,
        );
      }
    }
  }

  for (const call of observed.values()) {
    const hasOperation = operationsById.has(call.toolCallId);
    const decision = approvalsByToolCall.get(call.toolCallId);
    const denied = decision?.state === "denied";
    if (!hasOperation && !denied) {
      blockers.push(
        `observed model call ${call.toolCallId} (${call.toolName}) has no operation and no denial`,
      );
    }
  }

  // The exchange to reconstruct: settled operations and denials whose
  // effects were never committed into the head context. Operations below
  // the current revision are already reflected — never backfill twice.
  const currentOps = operations.filter(
    (op) =>
      op.state === "settled" &&
      op.output !== undefined &&
      lineage.order.has(op.executionAttemptId) &&
      atHead(op.context),
  );
  const currentDenied = approvals.filter(
    (approval) => approval.state === "denied" && atHead(approval.context),
  );
  const reconstructionNeeded = currentOps.length + currentDenied.length > 0;

  if (reconstructionNeeded) {
    const issuingAttempts = new Set(
      [...currentOps, ...currentDenied].map(
        (entry) => observed.get(entry.toolCallId)?.attempt.attemptId,
      ),
    );
    if (issuingAttempts.size > 1) {
      blockers.push(
        "multiple model exchanges reference the uncommitted context; their ordering is ambiguous",
      );
    }
    for (const op of currentOps) {
      const call = observed.get(op.toolCallId);
      if (call && call.attempt.operationKind !== "agent.stream") {
        blockers.push(
          `observed model call ${op.toolCallId} belongs to auxiliary attempt ${call.attempt.attemptId} (${call.attempt.operationKind}); its exchange is ambiguous`,
        );
      }
    }
    for (const approval of currentDenied) {
      const call = observed.get(approval.toolCallId);
      if (call && call.attempt.operationKind !== "agent.stream") {
        blockers.push(
          `denied call ${approval.toolCallId} belongs to auxiliary attempt ${call.attempt.attemptId} (${call.attempt.operationKind}); its exchange is ambiguous`,
        );
      }
    }
    const provider = getModelInfo(record.spec.model).provider;
    if (provider !== "anthropic" && provider !== "openai") {
      blockers.push(
        `model ${record.spec.model} (provider ${provider}) lacks reconstruction continuity data; only direct OpenAI/Anthropic are supported`,
      );
    } else if (provider === "anthropic") {
      const caps = getClaudeCapabilities(record.spec.model);
      const thinking =
        caps?.alwaysOnThinking === true || caps?.bindsThinking === true;
      if (thinking) {
        blockers.push(
          `model ${record.spec.model} has always-on or bound thinking; its interrupted exchange cannot be reconstructed`,
        );
      }
    }
  }

  if (blockers.length > 0) return { ok: false, blockers };

  // Zero-effect interrupted requests restart from the head; their
  // reservation stays counted (B3), their uncommitted output is discarded.
  const restartedModelAttempts = attempts
    .filter(
      (entry) =>
        entry.context !== null &&
        entry.toolCalls.length === 0 &&
        atHead(entry.context),
    )
    .map((entry) => entry.attempt.attemptId);

  const messages: ModelMessage[] = [...context.messages];
  const reconstructedToolCalls: RecoveryReconstructionSummary["reconstructedToolCalls"] =
    [];
  const deniedToolCalls: string[] = [];

  if (reconstructionNeeded) {
    const groups = buildExchange({
      currentOps,
      currentDenied,
      observed,
    });
    // One assistant/tool pair per issuing model attempt, chronological;
    // every pair precedes the single trailing recovery note.
    for (const parts of groups) {
      messages.push(
        {
          role: "assistant",
          content: parts.map((part) => ({
            type: "tool-call" as const,
            toolCallId: part.toolCallId,
            toolName: part.toolName,
            input: part.input,
          })),
        },
        {
          role: "tool",
          content: parts.map((part) => ({
            type: "tool-result" as const,
            toolCallId: part.toolCallId,
            toolName: part.toolName,
            output: part.output,
          })),
        },
      );
      for (const part of parts) {
        if (part.operationId) {
          reconstructedToolCalls.push({
            toolCallId: part.toolCallId,
            operationId: part.operationId,
          });
        } else {
          deniedToolCalls.push(part.toolCallId);
        }
      }
    }
    messages.push({ role: "user", content: RECOVERY_NOTE });
  } else if (restartedModelAttempts.length > 0) {
    // A restart-only recovery still discarded uncommitted output; the note
    // must never be limited to reconstructed exchanges.
    messages.push({ role: "user", content: RECOVERY_NOTE });
  }

  const discardedUncommitted =
    reconstructionNeeded || restartedModelAttempts.length > 0;

  return {
    ok: true,
    messages,
    reconstruction: {
      sourceContext: { epoch: context.epoch, revision: context.revision },
      reconstructedToolCalls,
      restartedModelAttempts,
      deniedToolCalls,
      discardedUncommitted,
    },
  };
}

interface ExchangePart {
  toolCallId: string;
  toolName: string;
  input: unknown;
  output: ToolResultPart["output"];
  operationId?: string;
  attemptIndex: number;
  emissionOrder: number;
}

// Group parts by issuing model attempt, chronological between attempts and
// in emission order within one. Every part's observed entry was validated
// unique above; calls whose entry vanished were blocked earlier.
function buildExchange(input: {
  currentOps: RecordedToolOperation[];
  currentDenied: RecordedApproval[];
  observed: Map<string, ObservedCall>;
}): ExchangePart[][] {
  const parts = new Map<string, ExchangePart>();
  for (const op of input.currentOps) {
    const call = input.observed.get(op.toolCallId);
    parts.set(op.toolCallId, {
      toolCallId: op.toolCallId,
      toolName: op.toolName,
      input: structuredClone(op.input),
      output: structuredClone(op.output) as ToolResultPart["output"],
      operationId: op.operationId,
      attemptIndex: call?.attemptIndex ?? 0,
      emissionOrder: call?.emissionOrder ?? 0,
    });
  }
  for (const approval of input.currentDenied) {
    const call = input.observed.get(approval.toolCallId);
    parts.set(approval.toolCallId, {
      toolCallId: approval.toolCallId,
      toolName: approval.toolName,
      input: structuredClone(approval.input),
      output: structuredClone(DENIED_BY_OPERATOR) as ToolResultPart["output"],
      attemptIndex: call?.attemptIndex ?? 0,
      emissionOrder: call?.emissionOrder ?? 0,
    });
  }
  const byAttempt = new Map<number, ExchangePart[]>();
  for (const part of parts.values()) {
    const key = part.attemptIndex;
    const group = byAttempt.get(key);
    if (group) group.push(part);
    else byAttempt.set(key, [part]);
  }
  return [...byAttempt.entries()]
    .sort(([a], [b]) => a - b)
    .map(([, group]) =>
      group.sort((a, b) => a.emissionOrder - b.emissionOrder),
    );
}
