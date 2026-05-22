import type { TextStreamPart, ToolSet } from "ai";
import { EventEmitter } from "events";
import type { MessageId, PartId, SessionId } from "./id/id";

type IdFields = {
  sessionId?: SessionId;
  subagentSessionId?: SessionId;
  messageId?: MessageId;
  partId?: PartId;
};

/** Typed event map for the agent event bus. */
export type AgentEventMap = {
  "text-delta": IdFields & { text: string; subagentId?: string };
  "tool-call-start": IdFields & {
    toolCallId: string;
    toolName: string;
    subagentId?: string;
  };
  "tool-call-delta": IdFields & {
    toolCallId: string;
    argsTextDelta: string;
    subagentId?: string;
  };
  "tool-call-complete": IdFields & {
    toolCallId: string;
    toolName: string;
    args: unknown;
    subagentId?: string;
  };
  "tool-result": IdFields & {
    toolCallId: string;
    toolName: string;
    result: unknown;
    subagentId?: string;
  };
  "subagent-spawn": {
    subagentId: string;
    subagentSessionId?: SessionId;
    name?: string;
    input: unknown;
    /** Omitted means top-level. Auto-populated by attachChild. */
    parentSubagentId?: string;
    parentSubagentSessionId?: SessionId;
    sessionId?: SessionId;
  };
  "subagent-complete": {
    subagentId: string;
    subagentSessionId?: SessionId;
    status: "completed" | "failed";
    parentSubagentId?: string;
    parentSubagentSessionId?: SessionId;
    sessionId?: SessionId;
  };
  "workflow-phase-start": IdFields & {
    phase: "discovery" | "pentesting" | "reporting";
    label: string;
    metadata?: Record<string, unknown>;
  };
  "workflow-phase-complete": IdFields & {
    phase: "discovery" | "pentesting" | "reporting";
    summary: Record<string, unknown>;
  };
  "app-analysis-progress": IdFields & {
    totalApps: number;
    completedApps: number;
    appName?: string;
  };
  "step-finish": IdFields & {
    messages: unknown[];
    subagentId?: string;
    /** Monotonic per agent run. */
    stepSeq?: number;
  };
  "command-output": IdFields & { data: string; subagentId?: string };
  error: IdFields & { error: unknown; subagentId?: string };
  "trace-record": IdFields & {
    record: import("./agents/offSecAgent/trace").TraceRecord;
    subagentId?: string;
  };
};

/** Whether a child bus event bubbles to the parent or is dropped. */
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
  "workflow-phase-start": "parent-only",
  "workflow-phase-complete": "parent-only",
  "app-analysis-progress": "parent-only",
};

const CHILD_BUS_FORWARDED_EVENTS = (
  Object.keys(CHILD_BUS_FORWARD_POLICY) as (keyof AgentEventMap)[]
).filter((key) => CHILD_BUS_FORWARD_POLICY[key] === "forward");

/** Typed pub/sub bus for agent streaming output. */
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

  /** Forward child events to the parent bus, injecting subagent identity. */
  static attachChild(
    child: AgentEventBus,
    parent: AgentEventBus | undefined,
    subagentId: string,
    subagentSessionId?: SessionId,
  ): void {
    if (!parent) return;
    for (const key of CHILD_BUS_FORWARDED_EVENTS) {
      const forwardKey = key as keyof AgentEventMap;
      child.on(forwardKey, (payload: AgentEventMap[typeof forwardKey]) => {
        const p = payload as Record<string, unknown>;

        const isLifecycle =
          forwardKey === "subagent-spawn" || forwardKey === "subagent-complete";

        if (isLifecycle) {
          const inject: Record<string, unknown> = {};
          if (!p.parentSubagentId) inject.parentSubagentId = subagentId;
          if (!p.parentSubagentSessionId && subagentSessionId) {
            inject.parentSubagentSessionId = subagentSessionId;
          }
          if (Object.keys(inject).length === 0) {
            parent.emit(forwardKey, payload as never);
          } else {
            parent.emit(forwardKey, { ...p, ...inject } as never);
          }
          return;
        }

        const inject: Record<string, unknown> = {};
        if (!p.subagentId) inject.subagentId = subagentId;
        if (!p.subagentSessionId && subagentSessionId) {
          inject.subagentSessionId = subagentSessionId;
        }
        if (Object.keys(inject).length === 0) {
          parent.emit(forwardKey, payload as never);
        } else {
          parent.emit(forwardKey, { ...p, ...inject } as never);
        }
      });
    }
  }

  /** Emit a bus event for an AI SDK `fullStream` chunk. */
  emitStreamPart(
    chunk: TextStreamPart<ToolSet>,
    subagentId?: string,
    ids?: {
      sessionId?: SessionId;
      subagentSessionId?: SessionId;
      messageId?: MessageId;
      partId?: PartId;
    },
  ): void {
    const sessionId = ids?.sessionId;
    const subagentSessionId = ids?.subagentSessionId;
    const messageId = ids?.messageId;
    const partId = ids?.partId;
    switch (chunk.type) {
      case "text-delta":
        this.emit("text-delta", {
          text: chunk.text,
          subagentId,
          sessionId,
          subagentSessionId,
          messageId,
          partId,
        });
        break;
      case "tool-input-start":
        this.emit("tool-call-start", {
          toolCallId: chunk.id,
          toolName: chunk.toolName,
          subagentId,
          sessionId,
          subagentSessionId,
          messageId,
          partId,
        });
        break;
      case "tool-input-delta":
        this.emit("tool-call-delta", {
          toolCallId: chunk.id,
          argsTextDelta: chunk.delta,
          subagentId,
          sessionId,
          subagentSessionId,
          messageId,
          partId,
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
          subagentSessionId,
          messageId,
          partId,
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
          subagentSessionId,
          messageId,
          partId,
        });
        break;
      }
      case "error":
        this.emit("error", {
          error: (chunk as { type: "error"; error: unknown }).error,
          subagentId,
          sessionId,
          subagentSessionId,
        });
        break;
    }
  }
}
