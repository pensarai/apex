import type { AgentEventBus, AgentEventMap } from "../../../core/eventBus";
import type { DisplayMessage } from "../agent-display";
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
