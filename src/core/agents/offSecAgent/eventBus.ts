import type { TextStreamPart, ToolSet } from "ai";

export type TextDeltaData = Extract<
  TextStreamPart<ToolSet>,
  { type: "text-delta" }
>;
export type ToolCallData = Extract<
  TextStreamPart<ToolSet>,
  { type: "tool-call" }
>;
export type ToolResultData = Extract<
  TextStreamPart<ToolSet>,
  { type: "tool-result" }
>;

export type AgentEvent =
  | { type: "text-delta"; subagentId?: string; data: TextDeltaData }
  | { type: "tool-call"; subagentId?: string; data: ToolCallData }
  | { type: "tool-result"; subagentId?: string; data: ToolResultData }
  | { type: "error"; subagentId?: string; error: unknown }
  | {
      type: "subagent-spawn";
      subagentId: string;
      input: unknown;
      status: "pending";
    }
  | {
      type: "subagent-complete";
      subagentId: string;
      input: unknown;
      status: "completed" | "failed";
    };

export type AgentEventOfType<T extends AgentEvent["type"]> = Extract<
  AgentEvent,
  { type: T }
>;

export class AgentEventBus {
  private handlers: Array<(event: AgentEvent) => void> = [];
  private typedHandlers: Map<string, Array<(event: AgentEvent) => void>> =
    new Map();
  private parent: AgentEventBus | null;
  private subagentId: string | null;

  constructor(
    parent: AgentEventBus | null = null,
    subagentId: string | null = null,
  ) {
    this.parent = parent;
    this.subagentId = subagentId;
  }

  emit(event: AgentEvent): void {
    const tagged =
      this.subagentId && !event.subagentId
        ? { ...event, subagentId: this.subagentId }
        : event;

    for (const handler of this.handlers) {
      handler(tagged);
    }

    const typed = this.typedHandlers.get(tagged.type);
    if (typed) {
      for (const handler of typed) {
        handler(tagged);
      }
    }

    if (this.parent) {
      this.parent.emit(tagged);
    }
  }

  on(handler: (event: AgentEvent) => void): () => void;
  on<T extends AgentEvent["type"]>(
    type: T,
    handler: (event: AgentEventOfType<T>) => void,
  ): () => void;
  on(
    typeOrHandler: AgentEvent["type"] | ((event: AgentEvent) => void),
    handler?: (event: AgentEvent) => void,
  ): () => void {
    if (typeof typeOrHandler === "function") {
      this.handlers.push(typeOrHandler);
      return () => {
        const idx = this.handlers.indexOf(typeOrHandler);
        if (idx !== -1) this.handlers.splice(idx, 1);
      };
    }

    const list = this.typedHandlers.get(typeOrHandler) ?? [];
    list.push(handler!);
    this.typedHandlers.set(typeOrHandler, list);
    return () => {
      const idx = list.indexOf(handler!);
      if (idx !== -1) list.splice(idx, 1);
    };
  }

  child(subagentId: string): AgentEventBus {
    return new AgentEventBus(this, subagentId);
  }
}
