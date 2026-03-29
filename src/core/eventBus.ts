import { EventEmitter } from "events";

/**
 * Typed event map for the agent event bus.
 *
 * All streaming events carry an optional `subagentId` so consumers can
 * distinguish which agent produced a given event when multiple agents
 * share a single bus.
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
 * pattern with a publish-subscribe model that supports fan-out to multiple
 * consumers (TUI rendering, DB persistence, metrics, logging).
 *
 * Usage:
 * ```ts
 * const bus = new AgentEventBus();
 * bus.on("text-delta", (e) => process.stdout.write(e.text));
 * bus.on("tool-call-complete", (e) => console.log(`→ ${e.toolName}`));
 * const result = await agent.consume();
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
}
