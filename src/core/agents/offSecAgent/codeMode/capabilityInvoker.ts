import { createHash } from "node:crypto";
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

export type CodeModeCellMetrics = {
  nestedCalls: number;
  uniqueCalls: number;
  repeatedCalls: number;
  maxConcurrency: number;
};

export type CodeModeCellObservation = {
  metrics: CodeModeCellMetrics;
  guidance: string[];
};

type CellStats = {
  activeCalls: number;
  maxConcurrency: number;
  fingerprints: string[];
  repeatedCalls: number;
  maxIdenticalResultRepeats: number;
};

type Repetition = {
  resultFingerprint: string;
  count: number;
};

function stableSerialize(value: unknown): string {
  if (value === null || typeof value !== "object") {
    return JSON.stringify(value) ?? String(value);
  }
  if (Array.isArray(value)) {
    return `[${value.map(stableSerialize).join(",")}]`;
  }
  const object = value as Record<string, unknown>;
  return `{${Object.keys(object)
    .sort()
    .map((key) => `${JSON.stringify(key)}:${stableSerialize(object[key])}`)
    .join(",")}}`;
}

function fingerprint(value: unknown): string {
  return createHash("sha256").update(stableSerialize(value)).digest("hex");
}

function invocationInput(value: unknown): unknown {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    return value;
  }
  const { toolCallDescription: _description, ...input } = value as Record<
    string,
    unknown
  >;
  return input;
}

function isAsyncIterable(value: unknown): value is AsyncIterable<unknown> {
  return (
    typeof value === "object" && value !== null && Symbol.asyncIterator in value
  );
}

export class CanonicalCapabilityInvoker {
  private readonly allowedTools: Set<string>;
  private readonly cells = new Map<string, CellStats>();
  private readonly invocationCounts = new Map<string, number>();
  private readonly repetitions = new Map<string, Repetition>();
  private nextCallIndex = 0;
  private consecutiveSingleCallCells = 0;
  private terminal = false;

  constructor(private readonly options: CapabilityInvokerOptions) {
    this.allowedTools = new Set(options.allowedTools);
  }

  private recordResult(
    stats: CellStats,
    callFingerprint: string,
    output: unknown,
  ): void {
    const resultFingerprint = fingerprint(output);
    const previous = this.repetitions.get(callFingerprint);
    const repetitionCount =
      previous?.resultFingerprint === resultFingerprint
        ? previous.count + 1
        : 1;
    this.repetitions.set(callFingerprint, {
      resultFingerprint,
      count: repetitionCount,
    });
    stats.maxIdenticalResultRepeats = Math.max(
      stats.maxIdenticalResultRepeats,
      repetitionCount,
    );
  }

  completeCell(parentToolCallId: string): CodeModeCellObservation {
    const stats = this.cells.get(parentToolCallId) ?? {
      activeCalls: 0,
      maxConcurrency: 0,
      fingerprints: [],
      repeatedCalls: 0,
      maxIdenticalResultRepeats: 0,
    };
    this.cells.delete(parentToolCallId);

    const uniqueCalls = new Set(stats.fingerprints).size;
    const metrics = {
      nestedCalls: stats.fingerprints.length,
      uniqueCalls,
      repeatedCalls: stats.repeatedCalls,
      maxConcurrency: stats.maxConcurrency,
    };

    this.consecutiveSingleCallCells =
      metrics.nestedCalls === 1 ? this.consecutiveSingleCallCells + 1 : 0;

    const guidance: string[] = [];
    if (
      metrics.nestedCalls >= 4 &&
      metrics.maxConcurrency === 1 &&
      metrics.uniqueCalls > 1
    ) {
      guidance.push(
        "This cell ran several calls sequentially. If their inputs were already known and independent, combine them with mapLimit or Promise.allSettled; keep only adaptive dependencies sequential.",
      );
    }
    if (this.consecutiveSingleCallCells >= 4) {
      guidance.push(
        "Repeated one-call exec cells are adding model round trips. Consolidate known independent work into one bounded stage, or write and reuse a script in the session workspace.",
      );
    }
    if (stats.maxIdenticalResultRepeats >= 3 && metrics.maxConcurrency <= 1) {
      guidance.push(
        "The same capability call has returned the same result at least three times. Treat it as a dead end unless new evidence changes the hypothesis.",
      );
    }

    return { metrics, guidance };
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

    const cell = this.cells.get(options.parentToolCallId) ?? {
      activeCalls: 0,
      maxConcurrency: 0,
      fingerprints: [],
      repeatedCalls: 0,
      maxIdenticalResultRepeats: 0,
    };
    this.cells.set(options.parentToolCallId, cell);
    const callFingerprint = fingerprint({
      toolName,
      input: invocationInput(validation.value),
    });
    cell.fingerprints.push(callFingerprint);
    if ((this.invocationCounts.get(callFingerprint) ?? 0) > 0) {
      cell.repeatedCalls += 1;
    }
    cell.activeCalls += 1;
    cell.maxConcurrency = Math.max(cell.maxConcurrency, cell.activeCalls);
    this.invocationCounts.set(
      callFingerprint,
      (this.invocationCounts.get(callFingerprint) ?? 0) + 1,
    );

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
      this.recordResult(cell, callFingerprint, output);
      if (toolName === "response") this.terminal = true;
      return output;
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      this.options.eventBus.emit("tool-result", {
        ...eventIdentity,
        result: { type: "error-text", value: message },
      });
      this.recordResult(cell, callFingerprint, {
        type: "error-text",
        value: message,
      });
      throw error;
    } finally {
      cell.activeCalls = Math.max(0, cell.activeCalls - 1);
    }
  }
}
