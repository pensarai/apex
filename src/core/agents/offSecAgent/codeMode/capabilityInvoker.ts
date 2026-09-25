import { asSchema, type ModelMessage, type Tool, type ToolSet } from "ai";
import type { AgentEventBus } from "../../../eventBus";
import { newPartId } from "../../../id/id";

type InvokeOptions = {
  parentToolCallId: string;
  messages: ModelMessage[];
  abortSignal?: AbortSignal;
};

type CapabilityInvokerOptions = {
  tools: ToolSet;
  allowedTools: Iterable<string>;
  eventBus: AgentEventBus;
  sessionId: string;
  subagentId?: string;
  getMessageId: () => string | undefined;
};

function isAsyncIterable(value: unknown): value is AsyncIterable<unknown> {
  return (
    typeof value === "object" && value !== null && Symbol.asyncIterator in value
  );
}

export class CanonicalCapabilityInvoker {
  private readonly allowedTools: Set<string>;
  private nextCallIndex = 0;
  private terminal = false;

  constructor(private readonly options: CapabilityInvokerOptions) {
    this.allowedTools = new Set(options.allowedTools);
  }

  async invoke(
    toolName: string,
    input: unknown,
    options: InvokeOptions,
  ): Promise<unknown> {
    if (this.terminal) {
      throw new Error(
        "The response has already been submitted; no more tools may run",
      );
    }
    if (!this.allowedTools.has(toolName)) {
      throw new Error(`Capability is not available in code mode: ${toolName}`);
    }

    const tool = this.options.tools[toolName] as Tool | undefined;
    if (!tool?.execute) {
      throw new Error(`Capability is not executable: ${toolName}`);
    }

    const schema = asSchema(tool.inputSchema);
    const validation = schema.validate
      ? await schema.validate(input)
      : { success: true as const, value: input };
    if (!validation.success) {
      throw new Error(
        `Invalid input for ${toolName}: ${validation.error.message}`,
      );
    }

    this.nextCallIndex += 1;
    const toolCallId = `${options.parentToolCallId}:nested:${this.nextCallIndex}`;
    const partId = newPartId();
    const eventIdentity = {
      toolCallId,
      toolName,
      sessionId: this.options.sessionId,
      subagentId: this.options.subagentId,
      messageId: this.options.getMessageId(),
      partId,
    };

    this.options.eventBus.emit("tool-call-start", eventIdentity);
    this.options.eventBus.emit("tool-call-complete", {
      ...eventIdentity,
      args: validation.value,
    });

    try {
      const execution = tool.execute(validation.value, {
        toolCallId,
        messages: options.messages,
        abortSignal: options.abortSignal,
      });

      let output: unknown;
      if (isAsyncIterable(execution)) {
        for await (const item of execution) output = item;
      } else {
        output = await execution;
      }

      this.options.eventBus.emit("tool-result", {
        ...eventIdentity,
        result: output,
      });
      if (toolName === "response") this.terminal = true;
      return output;
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      this.options.eventBus.emit("tool-result", {
        ...eventIdentity,
        result: { type: "error-text", value: message },
      });
      throw error;
    }
  }
}
