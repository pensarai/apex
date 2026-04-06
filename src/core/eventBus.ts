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
  };
  "subagent-complete": {
    subagentId: string;
    status: "completed" | "failed";
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
 * Ensures a readonly tuple contains every member of a union type.
 * Compile error if any AgentEventName is missing from the array.
 */
type ExhaustiveEventNames<T extends readonly (keyof AgentEventMap)[]> =
  Exclude<keyof AgentEventMap, T[number]> extends never ? T : never;

/**
 * Every event name in AgentEventMap. Adding a new event to the map
 * without adding it here is a compile error.
 */
export const AGENT_EVENT_NAMES = [
  "text-delta",
  "tool-call-start",
  "tool-call-delta",
  "tool-call-complete",
  "tool-result",
  "subagent-spawn",
  "subagent-complete",
  "workflow-phase-start",
  "workflow-phase-complete",
  "step-finish",
  "command-output",
  "error",
  "trace-record",
] as const satisfies ExhaustiveEventNames<typeof AGENT_EVENT_NAMES>;

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
   * Create a child bus whose events automatically bubble to this
   * (parent) bus with `subagentId` injected into every payload.
   *
   * Usage:
   * ```ts
   * const childBus = parentBus.child("pentest-agent-0");
   * const agent = new TargetedPentestAgent({ ...input, eventBus: childBus });
   * await agent.consume();
   * // All events from the child arrive on the parent with subagentId set
   * ```
   */
  child(subagentId: string): AgentEventBus {
    const childBus = new AgentEventBus();

    for (const key of AGENT_EVENT_NAMES) {
      childBus.on(key, (payload: Record<string, unknown>) => {
        const tagged = { ...payload };
        // Preserve innermost subagentId for nested child-of-child buses
        if (!("subagentId" in tagged) || tagged.subagentId == null) {
          tagged.subagentId = subagentId;
        }
        this.emit(key, tagged as AgentEventMap[typeof key]);
      });
    }

    return childBus;
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
