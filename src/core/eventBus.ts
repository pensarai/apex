import { EventEmitter } from "node:events";
import type { TextStreamPart, ToolSet } from "ai";

/**
 * Typed event map for the agent event bus.
 *
 * Events mirror the AI SDK's `TextStreamPart` types, plus native identity
 * (`sessionId`/`messageId`/`partId`) for routing without inference.
 * `subagentId` is kept as a backward-compatible alias of `sessionId`.
 * Lifecycle events (`subagent-spawn`, `subagent-complete`) and side-channel
 * events (`command-output`, `error`) round out the map.
 */
export type AgentEventMap = {
  "text-delta": {
    text: string;
    subagentId?: string;
    sessionId?: string;
    messageId?: string;
    partId?: string;
  };
  /**
   * Extended-thinking / reasoning output streamed incrementally. Mirrors
   * `text-delta` but carries the model's reasoning tokens (Anthropic
   * extended thinking, OpenAI reasoning) so consumers can surface a
   * "thinking" indicator instead of appearing to hang between tool calls.
   */
  "reasoning-delta": { text: string; subagentId?: string };
  /** A reasoning block opened. Lets consumers time the thinking window. */
  "reasoning-start": { subagentId?: string };
  /** A reasoning block closed. Paired with `reasoning-start` to derive duration. */
  "reasoning-end": { subagentId?: string };
  "tool-call-start": {
    toolCallId: string;
    toolName: string;
    subagentId?: string;
    sessionId?: string;
    messageId?: string;
    partId?: string;
  };
  "tool-call-delta": {
    toolCallId: string;
    argsTextDelta: string;
    subagentId?: string;
    sessionId?: string;
    messageId?: string;
    partId?: string;
  };
  "tool-call-complete": {
    toolCallId: string;
    toolName: string;
    args: unknown;
    subagentId?: string;
    sessionId?: string;
    messageId?: string;
    partId?: string;
  };
  "tool-result": {
    toolCallId: string;
    toolName: string;
    result: unknown;
    subagentId?: string;
    sessionId?: string;
    messageId?: string;
    partId?: string;
  };
  "subagent-spawn": {
    subagentId: string;
    /** The spawned child's own session id (`ses_…`). */
    sessionId?: string;
    name?: string;
    input: unknown;
    /** Omitted means top-level. Auto-populated by {@link AgentEventBus.attachChild}. */
    parentSubagentId?: string;
    /** Parent agent's session id (`ses_…`). Auto-populated by {@link AgentEventBus.attachChild}. */
    parentSessionId?: string;
  };
  "subagent-complete": {
    subagentId: string;
    /** The completed child's own session id (`ses_…`). */
    sessionId?: string;
    status: "completed" | "failed";
    /** Omitted means top-level. Auto-populated by {@link AgentEventBus.attachChild}. */
    parentSubagentId?: string;
    /** Parent agent's session id (`ses_…`). Auto-populated by {@link AgentEventBus.attachChild}. */
    parentSessionId?: string;
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
    sessionId?: string;
    /** The assistant message (`msg_…`) that just closed this step. */
    messageId?: string;
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
  "reasoning-delta": "forward",
  "reasoning-start": "forward",
  "reasoning-end": "forward",
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
   * Forward selected events from a child bus to a parent bus, stamping
   * `sessionId`/`subagentId` (and `parentSessionId`/`parentSubagentId`
   * for lifecycle events) so the parent's routing works without inference.
   */
  static attachChild(
    child: AgentEventBus,
    parent: AgentEventBus | undefined,
    childSessionId: string,
  ): void {
    if (!parent) return;
    for (const key of CHILD_BUS_FORWARDED_EVENTS) {
      // Re-bind so the handler's payload type tracks `key` as a single K —
      // without this, the union of payload shapes is too wide for `emit`.
      const forwardKey = key as keyof AgentEventMap;
      child.on(forwardKey, (payload: AgentEventMap[typeof forwardKey]) => {
        const p = payload as Record<string, unknown>;

        const isLifecycle =
          forwardKey === "subagent-spawn" || forwardKey === "subagent-complete";

        if (isLifecycle) {
          // Nested subagent case: childSessionId becomes the grandchild's parent id.
          const next: Record<string, unknown> = { ...p };
          if (!p.parentSubagentId) next.parentSubagentId = childSessionId;
          if (!p.parentSessionId) next.parentSessionId = childSessionId;
          parent.emit(forwardKey, next as never);
          return;
        }

        const next: Record<string, unknown> = { ...p };
        if (!p.subagentId) next.subagentId = childSessionId;
        if (!p.sessionId) next.sessionId = childSessionId;
        parent.emit(forwardKey, next as never);
      });
    }
  }

  /**
   * Emit the appropriate bus event for an AI SDK `fullStream` chunk.
   *
   * Maps Vercel AI SDK `TextStreamPart` types to `AgentEventMap` keys:
   *   text-delta        → text-delta
   *   reasoning-start   → reasoning-start
   *   reasoning-delta   → reasoning-delta
   *   reasoning-end     → reasoning-end
   *   tool-input-start  → tool-call-start
   *   tool-input-delta  → tool-call-delta
   *   tool-call         → tool-call-complete
   *   tool-result       → tool-result
   *   error             → error
   *
   * `ids` accepts a bare `subagentId` string for backward compatibility, or
   * a {@link StreamIdContext} to also stamp `sessionId`/`messageId`/`partId`.
   */
  emitStreamPart(
    chunk: TextStreamPart<ToolSet>,
    ids?: string | StreamIdContext,
  ): void {
    const ctx: StreamIdContext =
      typeof ids === "string" ? { subagentId: ids } : (ids ?? {});
    // No sessionId fallback: subagentId stays undefined for the orchestrator.
    const subagentId = ctx.subagentId;
    const sessionId = ctx.sessionId;
    const messageId = ctx.messageId;

    switch (chunk.type) {
      case "text-delta":
        this.emit("text-delta", {
          text: chunk.text,
          subagentId,
          sessionId,
          messageId,
          partId: ctx.textPartId,
        });
        break;
      case "reasoning-start":
        this.emit("reasoning-start", { subagentId });
        break;
      case "reasoning-delta":
        this.emit("reasoning-delta", { text: chunk.text, subagentId });
        break;
      case "reasoning-end":
        this.emit("reasoning-end", { subagentId });
        break;
      case "tool-input-start":
        this.emit("tool-call-start", {
          toolCallId: chunk.id,
          toolName: chunk.toolName,
          subagentId,
          sessionId,
          messageId,
          partId: ctx.toolPartId?.(chunk.id),
        });
        break;
      case "tool-input-delta":
        this.emit("tool-call-delta", {
          toolCallId: chunk.id,
          argsTextDelta: chunk.delta,
          subagentId,
          sessionId,
          messageId,
          partId: ctx.toolPartId?.(chunk.id),
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
          sessionId,
          messageId,
          partId: ctx.toolPartId?.(tc.toolCallId),
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
          sessionId,
          messageId,
          partId: ctx.toolPartId?.(tr.toolCallId),
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

/**
 * Identity context the emitting agent threads through
 * {@link AgentEventBus.emitStreamPart}.
 */
export interface StreamIdContext {
  /** Legacy multi-agent delineator; equals {@link sessionId} when set. */
  subagentId?: string;
  /** Emitting agent's session id (`ses_…`). */
  sessionId?: string;
  /** Current open assistant message id (`msg_…`) for this step. */
  messageId?: string;
  /** Current text part id (`prt_…`); minted per text run by the agent. */
  textPartId?: string;
  /** Resolves a stable part id (`prt_…`) for a `toolCallId`, minting on first use. */
  toolPartId?: (toolCallId: string) => string;
}
