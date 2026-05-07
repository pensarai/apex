import { EventEmitter } from "events";
import type { TextStreamPart, ToolSet } from "ai";

/**
 * Typed event map for the agent event bus.
 *
 * Events mirror the AI SDK's `TextStreamPart` types with an added
 * `subagentId` for multi-agent delineation.  Lifecycle events
 * (`subagent-spawn`, `subagent-complete`) and side-channel events
 * (`command-output`, `error`) round out the map.
 */
export type AgentEventMap = {
  "text-delta": { text: string; subagentId?: string };
  "tool-call-start": {
    toolCallId: string;
    toolName: string;
    subagentId?: string;
  };
  "tool-call-delta": {
    toolCallId: string;
    argsTextDelta: string;
    subagentId?: string;
  };
  "tool-call-complete": {
    toolCallId: string;
    toolName: string;
    args: unknown;
    subagentId?: string;
  };
  "tool-result": {
    toolCallId: string;
    toolName: string;
    result: unknown;
    subagentId?: string;
  };
  "subagent-spawn": {
    subagentId: string;
    name?: string;
    input: unknown;
    /**
     * The subagent that spawned this subagent. When omitted, the
     * spawned subagent is a top-level child of the root agent /
     * workflow. Populated automatically by {@link AgentEventBus.attachChild}
     * when not explicitly provided by the emitter.
     */
    parentSubagentId?: string;
  };
  "subagent-complete": {
    subagentId: string;
    status: "completed" | "failed";
    /**
     * Mirrors {@link AgentEventMap["subagent-spawn"].parentSubagentId}.
     * Populated automatically by {@link AgentEventBus.attachChild}
     * when not explicitly provided by the emitter.
     */
    parentSubagentId?: string;
  };
  "workflow-phase-start": {
    phase: "discovery" | "pentesting" | "reporting";
    label: string;
    metadata?: Record<string, unknown>;
  };
  "workflow-phase-complete": {
    phase: "discovery" | "pentesting" | "reporting";
    summary: Record<string, unknown>;
  };
  "app-analysis-progress": {
    totalApps: number;
    completedApps: number;
    appName?: string;
  };
  "step-finish": {
    messages: unknown[];
    subagentId?: string;
  };
  "command-output": { data: string; subagentId?: string };
  error: { error: unknown; subagentId?: string };
  "trace-record": {
    record: import("./agents/offSecAgent/trace").TraceRecord;
    subagentId?: string;
  };
};

/**
 * Events forwarded from a child event bus to its parent via
 * {@link AgentEventBus.attachChild}.
 */
const CHILD_BUS_FORWARDED_EVENTS = [
  "text-delta",
  "tool-call-start",
  "tool-call-delta",
  "tool-call-complete",
  "tool-result",
  "subagent-spawn",
  "subagent-complete",
  "command-output",
  "error",
  "step-finish",
] as const satisfies readonly (keyof AgentEventMap)[];

/**
 * Centralized, typed event bus for agent streaming output.
 *
 * Replaces the callback-based `ConsumeCallbacks` / `SubagentConsumeCallbacks`
 * pattern with a publish-subscribe model.  Multiple consumers (TUI rendering,
 * DB persistence, metrics, logging) subscribe independently.
 *
 * Usage:
 * ```ts
 * const bus = new AgentEventBus();
 * bus.on("text-delta", (e) => process.stdout.write(e.text));
 * bus.on("tool-call-complete", (e) => console.log(`→ ${e.toolName}`));
 * await agent.consume();
 * ```
 */
export class AgentEventBus {
  private readonly emitter = new EventEmitter();

  constructor() {
    this.emitter.setMaxListeners(50);
  }

  on<K extends keyof AgentEventMap>(
    event: K,
    handler: (payload: AgentEventMap[K]) => void,
  ): this {
    this.emitter.on(event, handler);
    return this;
  }

  once<K extends keyof AgentEventMap>(
    event: K,
    handler: (payload: AgentEventMap[K]) => void,
  ): this {
    this.emitter.once(event, handler);
    return this;
  }

  off<K extends keyof AgentEventMap>(
    event: K,
    handler: (payload: AgentEventMap[K]) => void,
  ): this {
    this.emitter.off(event, handler);
    return this;
  }

  emit<K extends keyof AgentEventMap>(
    event: K,
    payload: AgentEventMap[K],
  ): boolean {
    return this.emitter.emit(event, payload);
  }

  removeAllListeners(event?: keyof AgentEventMap): this {
    if (event) {
      this.emitter.removeAllListeners(event);
    } else {
      this.emitter.removeAllListeners();
    }
    return this;
  }

  /**
   * Forward selected events from a child bus to a parent bus, ensuring
   * all forwarded payloads carry the given `subagentId`.
   *
   * Tools running inside a subagent emit side-channel events (e.g.
   * `command-output`) without `subagentId`. This method injects the
   * ID so the parent's routing logic (subagent store vs main view)
   * works correctly.
   *
   * For `subagent-spawn` and `subagent-complete` events, the payload
   * already carries the *new* subagent's ID (the one being spawned /
   * completing). To preserve parent/child hierarchy across nested
   * sub-agents, this method also injects `parentSubagentId` (the
   * `subagentId` argument passed here) on those two events when not
   * already set by the emitter.
   */
  static attachChild(
    child: AgentEventBus,
    parent: AgentEventBus | undefined,
    subagentId: string,
  ): void {
    for (const key of CHILD_BUS_FORWARDED_EVENTS) {
      // Re-bind to a fresh local with a parametric type so TS treats
      // `key` and the emitted payload as the same K for the duration
      // of the handler. Without this, the union of payload shapes from
      // AgentEventMap is too wide for `parent.emit(key, payload)` to
      // typecheck on the forwarding branch.
      const forwardKey = key as keyof AgentEventMap;
      child.on(forwardKey, (payload: AgentEventMap[typeof forwardKey]) => {
        if (!parent) return;
        const p = payload as Record<string, unknown>;

        const isLifecycle =
          forwardKey === "subagent-spawn" ||
          forwardKey === "subagent-complete";

        if (isLifecycle) {
          const next = { ...p };
          // The new subagent's id always stays on the payload
          if (!next.parentSubagentId) {
            next.parentSubagentId = subagentId;
          }
          parent.emit(forwardKey, next as never);
          return;
        }

        if (!p.subagentId) {
          parent.emit(forwardKey, { ...p, subagentId } as never);
        } else {
          parent.emit(forwardKey, payload as never);
        }
      });
    }
  }

  /**
   * Emit the appropriate bus event for an AI SDK `fullStream` chunk.
   *
   * Maps Vercel AI SDK `TextStreamPart` types to `AgentEventMap` keys:
   *   text-delta        → text-delta
   *   tool-input-start  → tool-call-start
   *   tool-input-delta  → tool-call-delta
   *   tool-call         → tool-call-complete
   *   tool-result       → tool-result
   *   error             → error
   */
  emitStreamPart(chunk: TextStreamPart<ToolSet>, subagentId?: string): void {
    switch (chunk.type) {
      case "text-delta":
        this.emit("text-delta", { text: chunk.text, subagentId });
        break;
      case "tool-input-start":
        this.emit("tool-call-start", {
          toolCallId: chunk.id,
          toolName: chunk.toolName,
          subagentId,
        });
        break;
      case "tool-input-delta":
        this.emit("tool-call-delta", {
          toolCallId: chunk.id,
          argsTextDelta: chunk.delta,
          subagentId,
        });
        break;
      case "tool-call": {
        const tc = chunk as {
          toolCallId: string;
          toolName: string;
          input?: unknown;
          args?: unknown;
        };
        this.emit("tool-call-complete", {
          toolCallId: tc.toolCallId,
          toolName: tc.toolName,
          args: tc.args ?? tc.input,
          subagentId,
        });
        break;
      }
      case "tool-result": {
        const tr = chunk as {
          toolCallId: string;
          toolName: string;
          result?: unknown;
          output?: unknown;
        };
        this.emit("tool-result", {
          toolCallId: tr.toolCallId,
          toolName: tr.toolName,
          result: tr.result ?? tr.output,
          subagentId,
        });
        break;
      }
      case "error":
        this.emit("error", {
          error: (chunk as { type: "error"; error: unknown }).error,
          subagentId,
        });
        break;
    }
  }
}
