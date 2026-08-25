import {
  ASK_USER_QUESTIONS_TOOL_NAME,
  type AskUserQuestion,
} from "../../../core/agents/offSecAgent";
import type { AgentEventBus, AgentEventMap } from "../../../core/eventBus";
import type { DisplayMessage, WorkflowData } from "../agent-display";
import { tryParsePartialJson } from "../shared/message-utils";
import {
  appendStreamedText,
  applyToolCall,
  applyToolCallDelta,
  applyToolResult,
  markInFlightToolsErrored,
  mergeCommandOutput,
  startStreamingToolCall,
} from "./display-state";
import {
  applyWorkflowPhaseComplete,
  applyWorkflowPhaseStart,
  applyWorkflowSubagentComplete,
  applyWorkflowSubagentSpawn,
  isPentestAgent,
} from "./workflow-data";

// ---------------------------------------------------------------------------
// Run event subscription lifecycle — owns subscription, generation filtering,
// and cleanup for one agent run's bus listeners. Display projections live
// here too (createDisplayEventHandlers); workflow/subagent/question
// projections follow in later slices.
// ---------------------------------------------------------------------------

export interface OperatorRunEventHandlers {
  onTextDelta?: (e: AgentEventMap["text-delta"]) => void;
  onToolCallStart?: (e: AgentEventMap["tool-call-start"]) => void;
  onToolCallDelta?: (e: AgentEventMap["tool-call-delta"]) => void;
  onToolCallComplete?: (e: AgentEventMap["tool-call-complete"]) => void;
  onToolResult?: (e: AgentEventMap["tool-result"]) => void;
  onCommandOutput?: (e: AgentEventMap["command-output"]) => void;
  onError?: (e: AgentEventMap["error"]) => void;
  onSubagentSpawn?: (e: AgentEventMap["subagent-spawn"]) => void;
  onSubagentComplete?: (e: AgentEventMap["subagent-complete"]) => void;
  onWorkflowPhaseStart?: (e: AgentEventMap["workflow-phase-start"]) => void;
  onWorkflowPhaseComplete?: (
    e: AgentEventMap["workflow-phase-complete"],
  ) => void;
}

export interface BindOperatorRunEventsOptions {
  /** Generation guard — stale generations never reach the handlers. */
  isCurrent: () => boolean;
  handlers: OperatorRunEventHandlers;
}

/**
 * Subscribe the provided handlers to the run bus. The generation guard is
 * applied uniformly at ingress, and each handler is isolated: a throwing
 * handler is logged and neither prevents sibling listeners on the same
 * emission nor affects later events or cleanup.
 *
 * Returns an unbind function that detaches every listener; idempotent.
 * Unbinding swaps the error listener for a no-op rather than removing it —
 * Node's EventEmitter throws on an `error` emission with no listeners, and a
 * straggler error (e.g. forwarded from a subagent bus that outlived the run)
 * must be dropped like any other post-run event, not crash the process.
 */
export function bindOperatorRunEvents(
  bus: AgentEventBus,
  options: BindOperatorRunEventsOptions,
): () => void {
  const { isCurrent, handlers } = options;
  const offs: Array<() => void> = [];
  let boundError = false;

  const bind = <K extends keyof AgentEventMap>(
    event: K,
    handler: ((e: AgentEventMap[K]) => void) | undefined,
  ): void => {
    if (!handler) return;
    if (event === "error") boundError = true;
    const wrapped = (e: AgentEventMap[K]): void => {
      if (!isCurrent()) return;
      try {
        handler(e);
      } catch (err) {
        console.error(`[operator] ${event} handler failed:`, err);
      }
    };
    bus.on(event, wrapped);
    offs.push(() => bus.off(event, wrapped));
  };

  bind("text-delta", handlers.onTextDelta);
  bind("tool-call-start", handlers.onToolCallStart);
  bind("tool-call-delta", handlers.onToolCallDelta);
  bind("tool-call-complete", handlers.onToolCallComplete);
  bind("tool-result", handlers.onToolResult);
  bind("command-output", handlers.onCommandOutput);
  bind("error", handlers.onError);
  bind("subagent-spawn", handlers.onSubagentSpawn);
  bind("subagent-complete", handlers.onSubagentComplete);
  bind("workflow-phase-start", handlers.onWorkflowPhaseStart);
  bind("workflow-phase-complete", handlers.onWorkflowPhaseComplete);

  let unbound = false;
  return () => {
    if (unbound) return;
    unbound = true;
    for (const off of offs) off();
    offs.length = 0;
    // Node's EventEmitter throws on an `error` emission with no listeners.
    // Leave a no-op behind so a straggler error on this bus is dropped like
    // any other post-run event instead of crashing the process. The bus is
    // per-run and unreferenced after the run, so the listener dies with it.
    if (boundError) bus.on("error", () => {});
  };
}

// ---------------------------------------------------------------------------
// Display event projections — root-level text, tool, error, and command-output
// projections over a narrow display sink. Subagent routing, questions
// interception, and workflow phases stay with the caller.
// ---------------------------------------------------------------------------

/** Narrow sink: the only ways run events may touch display state. */
export interface DisplayEventSink {
  /** Apply an immutable update to the display message list. */
  updateMessages: (
    updater: (messages: DisplayMessage[]) => DisplayMessage[],
  ) => void;
  setThinking: (thinking: boolean) => void;
  setError: (message: string) => void;
}

export interface DisplayEventAdapter {
  onTextDelta(e: AgentEventMap["text-delta"]): void;
  onToolCallStart(e: AgentEventMap["tool-call-start"]): void;
  onToolCallDelta(e: AgentEventMap["tool-call-delta"]): void;
  onToolCallComplete(e: AgentEventMap["tool-call-complete"]): void;
  onToolResult(e: AgentEventMap["tool-result"]): void;
  onCommandOutput(e: AgentEventMap["command-output"]): void;
  onError(e: AgentEventMap["error"]): void;
  /** Partial streamed assistant text so far — abort recovery reads it. */
  getPartialText(): string;
  resetPartialText(): void;
  /** Flush buffered command output into the display immediately. */
  flushCommandOutput(): void;
  /** Stop the throttled command-output flush timer. */
  stopCommandOutputFlush(): void;
  /** Clear the flush timer (unmount). */
  dispose(): void;
}

const COMMAND_OUTPUT_FLUSH_MS = 150;

/**
 * Root display projections with their accumulation state: the partial text
 * buffer, per-tool-call args-delta buffers, and the throttled command-output
 * buffer. Component-lifetime — create once, hand the handlers to
 * {@link bindOperatorRunEvents}, dispose on unmount.
 */
export function createDisplayEventHandlers(
  sink: DisplayEventSink,
): DisplayEventAdapter {
  let partialText = "";
  const toolArgsDeltas = new Map<string, { accumulated: string }>();
  let commandOutputBuf = "";
  let flushTimer: ReturnType<typeof setInterval> | null = null;

  const flushCommandOutput = (): void => {
    if (!commandOutputBuf) return;
    const buf = commandOutputBuf;
    commandOutputBuf = "";
    sink.updateMessages((messages) => mergeCommandOutput(messages, buf));
  };

  const stopCommandOutputFlush = (): void => {
    if (flushTimer) {
      clearInterval(flushTimer);
      flushTimer = null;
    }
  };

  return {
    onTextDelta(e) {
      sink.setThinking(false);
      partialText += e.text;
      const accumulated = partialText;
      sink.updateMessages((messages) =>
        appendStreamedText(messages, accumulated),
      );
    },
    onToolCallStart(e) {
      sink.setThinking(false);
      partialText = "";
      toolArgsDeltas.set(e.toolCallId, { accumulated: "" });
      sink.updateMessages((messages) =>
        startStreamingToolCall(messages, e.toolCallId, e.toolName),
      );
    },
    onToolCallDelta(e) {
      const entry = toolArgsDeltas.get(e.toolCallId);
      const accumulated = (entry?.accumulated ?? "") + e.argsTextDelta;
      toolArgsDeltas.set(e.toolCallId, { accumulated });

      const parsed = tryParsePartialJson(accumulated);
      if (!parsed) return;

      sink.updateMessages((messages) =>
        applyToolCallDelta(messages, e.toolCallId, parsed),
      );
    },
    onToolCallComplete(e) {
      sink.setThinking(false);
      partialText = "";
      toolArgsDeltas.delete(e.toolCallId);
      const args =
        e.args &&
        typeof e.args === "object" &&
        !Array.isArray(e.args) &&
        e.args !== null
          ? (e.args as Record<string, unknown>)
          : undefined;
      sink.updateMessages((messages) =>
        applyToolCall(messages, e.toolCallId, e.toolName, args),
      );
    },
    onToolResult(e) {
      flushCommandOutput();
      stopCommandOutputFlush();
      sink.setThinking(true);
      partialText = "";
      sink.updateMessages((messages) =>
        applyToolResult(messages, e.toolCallId, e.result),
      );
    },
    onCommandOutput(e) {
      commandOutputBuf += e.data;
      if (!flushTimer) {
        flushTimer = setInterval(flushCommandOutput, COMMAND_OUTPUT_FLUSH_MS);
      }
    },
    onError(e) {
      console.error("Agent error:", e.error);
      const errorMessage =
        e.error instanceof Error ? e.error.message : "Unknown error";
      sink.setError(errorMessage);
      sink.updateMessages((messages) =>
        markInFlightToolsErrored(messages, errorMessage),
      );
    },
    getPartialText() {
      return partialText;
    },
    resetPartialText() {
      partialText = "";
    },
    flushCommandOutput,
    stopCommandOutputFlush,
    dispose: stopCommandOutputFlush,
  };
}

// ---------------------------------------------------------------------------
// Run event projections — the full handler set: root-vs-subagent routing,
// questions interception, workflow phases, and subagent swarm bookkeeping,
// layered over the display projections. Component-specific state changes
// (questions state, command-cancel flag, plan-review gating) stay behind
// injected callbacks.
// ---------------------------------------------------------------------------

/** Structural subset of createSubagentSessionHelpers used by the projections. */
export interface SubagentEventSink {
  appendText(id: string, text: string): void;
  addStreamingToolCall(id: string, toolCallId: string, toolName: string): void;
  appendToolCallDelta(
    id: string,
    toolCallId: string,
    argsTextDelta: string,
  ): void;
  addToolCall(
    id: string,
    toolCallId: string,
    toolName: string,
    args?: Record<string, unknown>,
  ): void;
  updateToolResult(id: string, toolCallId: string, result: unknown): void;
  spawnSession(id: string, name?: string, input?: unknown): void;
  completeSession(id: string, status: "completed" | "failed"): void;
}

export interface RunEventProjectionDeps {
  display: DisplayEventAdapter;
  subagents: SubagentEventSink;
  /** Patch the active run_pentest_workflow tool message's workflowData. */
  updateWorkflowData: (updater: (wd: WorkflowData) => WorkflowData) => void;
  /** Clear all subagent sessions (new discovery phase). */
  clearSubagentSessions: () => void;
  /** Ask-user-questions lifecycle, wired to component state. */
  questions: {
    onAsked: (toolCallId: string, questions: AskUserQuestion[]) => void;
    onCleared: () => void;
  };
  /** A root tool call began executing (resets the command-cancel flag). */
  onRootToolCallStarted?: () => void;
  /** A submit_plan tool result reported success (plan-review gating). */
  onPlanSubmitted?: () => void;
}

function toRecordArgs(args: unknown): Record<string, unknown> | undefined {
  return args &&
    typeof args === "object" &&
    !Array.isArray(args) &&
    args !== null
    ? (args as Record<string, unknown>)
    : undefined;
}

/**
 * The complete run-event handler set for {@link bindOperatorRunEvents}.
 * Routing: events carrying a `subagentId` project into that subagent's
 * session; root events project into the display. Generation filtering and
 * cleanup are owned by the binding, not the projections.
 */
export function createRunEventProjections(deps: RunEventProjectionDeps): {
  handlers: OperatorRunEventHandlers;
} {
  const { display, subagents, updateWorkflowData } = deps;

  return {
    handlers: {
      onTextDelta: (d) => {
        if (d.subagentId) {
          subagents.appendText(d.subagentId, d.text);
          return;
        }
        display.onTextDelta(d);
      },
      onToolCallStart: (d) => {
        if (d.subagentId) {
          subagents.addStreamingToolCall(
            d.subagentId,
            d.toolCallId,
            d.toolName,
          );
          return;
        }
        display.onToolCallStart(d);
      },
      onToolCallDelta: (d) => {
        if (d.subagentId) {
          subagents.appendToolCallDelta(
            d.subagentId,
            d.toolCallId,
            d.argsTextDelta,
          );
          return;
        }
        display.onToolCallDelta(d);
      },
      onToolCallComplete: (d) => {
        if (d.subagentId) {
          subagents.addToolCall(
            d.subagentId,
            d.toolCallId,
            d.toolName,
            toRecordArgs(d.args) ?? {},
          );
          return;
        }
        display.onToolCallComplete(d);
        deps.onRootToolCallStarted?.();

        if (d.toolName === ASK_USER_QUESTIONS_TOOL_NAME) {
          const rawQuestions = toRecordArgs(d.args)?.questions;
          if (Array.isArray(rawQuestions) && rawQuestions.length > 0) {
            deps.questions.onAsked(
              d.toolCallId,
              rawQuestions as AskUserQuestion[],
            );
          }
        }
      },
      onToolResult: (d) => {
        if (d.subagentId) {
          subagents.updateToolResult(d.subagentId, d.toolCallId, d.result);
          return;
        }
        display.onToolResult(d);

        if (
          d.toolName === "submit_plan" &&
          (d.result as Record<string, unknown> | null)?.success === true
        ) {
          deps.onPlanSubmitted?.();
        }
      },
      onCommandOutput: (d) => {
        if (d.subagentId) return;
        display.onCommandOutput(d);
      },
      onError: (d) => {
        if (d.subagentId) {
          const errMsg =
            d.error instanceof Error ? d.error.message : "Unknown error";
          subagents.appendText(d.subagentId, `\nError: ${errMsg}\n`);
          return;
        }
        display.onError(d);
        // Clear pending-questions state so an error after the tool-call event
        // doesn't leave the questions form stuck over a failed conversation.
        deps.questions.onCleared();
      },
      onSubagentSpawn: ({ subagentId, name }) => {
        // Hide whitebox per-app synthetic grouping nodes until #744 lands a hierarchical view.
        if (subagentId.startsWith("app:")) return;
        subagents.spawnSession(subagentId, name);
        if (!isPentestAgent(subagentId)) return;
        // Pentest swarm agents → workflowData.pentesting.subagents
        updateWorkflowData((wd) =>
          applyWorkflowSubagentSpawn(wd, subagentId, name),
        );
      },
      onSubagentComplete: ({ subagentId, status }) => {
        // Mirror the spawn-handler filter: synthetic per-app grouping nodes
        // were never registered as sessions, so don't try to complete them.
        if (subagentId.startsWith("app:")) return;
        subagents.completeSession(subagentId, status);
        if (!isPentestAgent(subagentId)) return;
        // Update workflowData swarm status
        updateWorkflowData((wd) =>
          applyWorkflowSubagentComplete(wd, subagentId, status),
        );
      },
      // Workflow phase events → update workflowData on the tool message
      onWorkflowPhaseStart: (d) => {
        display.resetPartialText();
        // New workflow run — clear old subagent sessions so the hub
        // shows only the current batch.
        if (d.phase === "discovery") {
          deps.clearSubagentSessions();
        }
        updateWorkflowData((wd) =>
          applyWorkflowPhaseStart(
            wd,
            d.phase as WorkflowData["currentPhase"],
            d.label,
          ),
        );
      },
      onWorkflowPhaseComplete: (d) => {
        display.resetPartialText();
        updateWorkflowData((wd) =>
          applyWorkflowPhaseComplete(
            wd,
            d.phase as WorkflowData["currentPhase"],
            d.summary,
          ),
        );
      },
    },
  };
}
