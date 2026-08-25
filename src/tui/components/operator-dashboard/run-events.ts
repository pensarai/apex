import type { AgentEventBus, AgentEventMap } from "../../../core/eventBus";

// ---------------------------------------------------------------------------
// Run event subscription lifecycle — owns subscription, generation filtering,
// and cleanup for one agent run's bus listeners. Handler behavior stays with
// the caller (O4/O5 will move the projections in behind this boundary).
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
 */
export function bindOperatorRunEvents(
  bus: AgentEventBus,
  options: BindOperatorRunEventsOptions,
): () => void {
  const { isCurrent, handlers } = options;
  const offs: Array<() => void> = [];

  const bind = <K extends keyof AgentEventMap>(
    event: K,
    handler: ((e: AgentEventMap[K]) => void) | undefined,
  ): void => {
    if (!handler) return;
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
  };
}
