import type { TextStreamPart, ToolSet } from "ai";
import { EventEmitter } from "events";

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
    /** Omitted means top-level. Auto-populated by {@link AgentEventBus.attachChild}. */
    parentSubagentId?: string;
  };
  "subagent-complete": {
    subagentId: string;
    status: "completed" | "failed";
    /** Omitted means top-level. Auto-populated by {@link AgentEventBus.attachChild}. */
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
 * Per-event decision used by {@link AgentEventBus.attachChild}.
 *
 * - `"forward"` — the event may originate inside a subagent; bubble it to the
 *   parent bus so parent-side consumers (W&B uploader, dashboard buffers,
 *   future persistence/metrics layers) receive it.
 * - `"parent-only"` — the event is emitted only by orchestrator-level workflow
 *   code on the parent bus; if it ever appears on a child bus, drop it on the
 *   floor rather than re-emit on the parent (which would either be dead code
 *   or, worse, a double-fire).
 *
 * The map type below is `{ readonly [K in keyof AgentEventMap]: ... }`, so
 * adding a new event to {@link AgentEventMap} without an explicit policy
 * entry is a TypeScript compile error. This invariant is the long-term
 * safety net: hand-curated allowlists silently omit events; an exhaustive
 * mapped type cannot.
 */
type ChildForwardPolicy = "forward" | "parent-only";

const CHILD_BUS_FORWARD_POLICY: {
  readonly [K in keyof AgentEventMap]: ChildForwardPolicy;
} = {
  "text-delta": "forward",
  "tool-call-start": "forward",
  "tool-call-delta": "forward",
  "tool-call-complete": "forward",
  "tool-result": "forward",
  "subagent-spawn": "forward",
  "subagent-complete": "forward",
  "step-finish": "forward",
  "command-output": "forward",
  error: "forward",
  "trace-record": "forward",
  // Emitted only by orchestrator workflow code (pentest.ts,
  // whiteboxAttackSurface.ts) on the parent bus directly. If a future change
  // makes any of these subagent-emitted, flip the value here deliberately.
  "workflow-phase-start": "parent-only",
  "workflow-phase-complete": "parent-only",
  "app-analysis-progress": "parent-only",
};

const CHILD_BUS_FORWARDED_EVENTS = (
  Object.keys(CHILD_BUS_FORWARD_POLICY) as (keyof AgentEventMap)[]
).filter((key) => CHILD_BUS_FORWARD_POLICY[key] === "forward");

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
   * works correctly. For `subagent-spawn` / `subagent-complete` it
   * additionally injects `parentSubagentId` to preserve hierarchy
   * across nested subagents.
   */
  static attachChild(
    child: AgentEventBus,
    parent: AgentEventBus | undefined,
    subagentId: string,
  ): void {
    if (!parent) return;
    for (const key of CHILD_BUS_FORWARDED_EVENTS) {
      // Re-bind so the handler's payload type tracks `key` as a single K —
      // without this, the union of payload shapes is too wide for `emit`.
      const forwardKey = key as keyof AgentEventMap;
      child.on(forwardKey, (payload: AgentEventMap[typeof forwardKey]) => {
        const p = payload as Record<string, unknown>;

        const isLifecycle =
          forwardKey === "subagent-spawn" ||
          forwardKey === "subagent-complete";

        if (isLifecycle) {
          const next = { ...p };
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
