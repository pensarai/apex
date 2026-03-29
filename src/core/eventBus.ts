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
  "command-output": { data: string; subagentId?: string };
  error: { error: unknown; subagentId?: string };
};

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
  emitStreamPart(
    chunk: TextStreamPart<ToolSet>,
    subagentId?: string,
  ): void {
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
      case "tool-call":
        this.emit("tool-call-complete", {
          toolCallId: chunk.toolCallId,
          toolName: chunk.toolName,
          args: chunk.args,
          subagentId,
        });
        break;
      case "tool-result":
        this.emit("tool-result", {
          toolCallId: chunk.toolCallId,
          toolName: chunk.toolName,
          result: chunk.result,
          subagentId,
        });
        break;
      case "error":
        this.emit("error", {
          error: (chunk as { type: "error"; error: unknown }).error,
          subagentId,
        });
        break;
    }
  }
}
