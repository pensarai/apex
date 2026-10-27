import { createHash } from "node:crypto";
import { asSchema, type ModelMessage, type Tool, type ToolSet } from "ai";
import type { AgentEventBus } from "../eventBus";
import { newPartId } from "../id/id";

type InvokeOptions = {
  parentToolCallId: string;
  messages: ModelMessage[];
  abortSignal?: AbortSignal;
  experimental_context?: unknown;
};

type CapabilityInvokerOptions = {
  tools: ToolSet;
  allowedTools: Iterable<string>;
  eventBus: AgentEventBus;
  sessionId: string;
  subagentId?: string;
  getMessageId: () => string | undefined;
  getToolPartId?: (toolCallId: string) => string;
};

export type CodeModeCellMetrics = {
  nestedCalls: number;
  uniqueCalls: number;
  repeatedCalls: number;
  maxConcurrency: number;
};

export type CodeModeEvidenceReference = {
  toolCallId: string;
  toolName: string;
  status: "succeeded" | "failed";
};

export type CodeModeCellObservation = {
  metrics: CodeModeCellMetrics;
  guidance: string[];
  evidence: CodeModeEvidenceReference[];
};

type CellStats = {
  activeCalls: number;
  maxConcurrency: number;
  fingerprints: string[];
  toolNames: string[];
  repeatedCalls: number;
  maxIdenticalResultRepeats: number;
  evidence: CodeModeEvidenceReference[];
};

type Repetition = {
  resultFingerprint: string;
  count: number;
};

type StatefulLane = "shell" | "browser" | "workspace";

function statefulLaneFor(toolName: string): StatefulLane | undefined {
  if (toolName === "execute_command") return "shell";
  if (["create_file", "update_file", "apply_patch"].includes(toolName)) {
    return "workspace";
  }
  if (toolName.startsWith("browser_")) return "browser";
  return undefined;
}

function laneConflictMessage(lane: StatefulLane): string {
  if (lane === "shell") {
    return "execute_command is single-lane across exec cells and direct calls. Await the active command before starting another.";
  }
  if (lane === "browser") {
    return "Browser operations are single-lane across exec cells and direct calls; await the active browser operation.";
  }
  return "Workspace writes are single-lane across exec cells and direct calls; await the active write.";
}

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

function normalizeCodeModeInput(toolName: string, value: unknown): unknown {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    return value;
  }
  const input = value as Record<string, unknown>;
  if (input.toolCallDescription !== undefined) return value;
  return {
    ...input,
    toolCallDescription: `Invoke ${toolName} from code mode`,
  };
}

function isAsyncIterable(value: unknown): value is AsyncIterable<unknown> {
  return (
    typeof value === "object" && value !== null && Symbol.asyncIterator in value
  );
}

export class CanonicalCapabilityInvoker {
  readonly tools: ToolSet;
  private readonly allowedTools: Set<string>;
  private readonly cells = new Map<string, CellStats>();
  private readonly invocationCounts = new Map<string, number>();
  private readonly repetitions = new Map<string, Repetition>();
  private consecutiveSingleCallCells = 0;
  private terminal = false;

  constructor(private readonly options: CapabilityInvokerOptions) {
    this.allowedTools = new Set(options.allowedTools);
    const activeLanes = new Set<StatefulLane>();
    this.tools = Object.fromEntries(
      Object.entries(options.tools).map(([name, definition]) => {
        const lane = statefulLaneFor(name);
        const execute = definition.execute;
        if (!lane || !execute) return [name, definition];
        return [
          name,
          {
            ...definition,
            // Keep streams visible to the SDK and hold the lane until iteration ends.
            execute: async function* (input, options) {
              options.abortSignal?.throwIfAborted();
              if (activeLanes.has(lane))
                throw new Error(laneConflictMessage(lane));
              activeLanes.add(lane);
              try {
                const result = await execute(input, options);
                if (isAsyncIterable(result)) yield* result;
                else yield result;
              } finally {
                activeLanes.delete(lane);
              }
            },
          } satisfies ToolSet[string],
        ];
      }),
    );
  }

  async describe(toolName: string): Promise<{
    name: string;
    description?: string;
    inputSchema: unknown;
  }> {
    if (!this.allowedTools.has(toolName)) {
      throw new Error(`Capability is not available in code mode: ${toolName}`);
    }
    const tool = Object.hasOwn(this.tools, toolName)
      ? (this.tools[toolName] as Tool)
      : undefined;
    if (!tool) throw new Error(`Unknown capability: ${toolName}`);
    return {
      name: toolName,
      description: tool.description,
      inputSchema: await asSchema(tool.inputSchema).jsonSchema,
    };
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
      toolNames: [],
      repeatedCalls: 0,
      maxIdenticalResultRepeats: 0,
      evidence: [],
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
      const hasShellCalls = stats.toolNames.includes("execute_command");
      const hasStatefulCalls = stats.toolNames.some(
        (name) => statefulLaneFor(name) !== undefined,
      );
      if (hasShellCalls) {
        guidance.push(
          "This cell ran several shell calls sequentially. Keep payload generation, loops, and result processing in JavaScript inside exec, and use available capabilities directly. Reserve execute_command for OS tools or dependencies unavailable in the cell; await each command sequentially.",
        );
      } else if (!hasStatefulCalls) {
        guidance.push(
          "This cell ran several calls sequentially. If their inputs were already known and independent, combine concurrency-safe capabilities with mapLimit or Promise.allSettled; keep only adaptive dependencies sequential.",
        );
      }
    }
    if (this.consecutiveSingleCallCells >= 4) {
      guidance.push(
        "Repeated one-call exec cells are adding wrappers without useful composition. Use direct tool calls for simple operations, or consolidate related work into one bounded JavaScript cell using tools.call and local result processing.",
      );
    }
    if (stats.maxIdenticalResultRepeats >= 3 && metrics.maxConcurrency <= 1) {
      guidance.push(
        "The same capability call has returned the same result at least three times. Treat it as a dead end unless new evidence changes the hypothesis.",
      );
    }

    return { metrics, guidance, evidence: structuredClone(stats.evidence) };
  }

  async invoke(
    toolName: string,
    input: unknown,
    options: InvokeOptions,
  ): Promise<unknown> {
    options.abortSignal?.throwIfAborted();
    if (this.terminal) {
      throw new Error(
        "The response has already been submitted; no more tools may run",
      );
    }
    if (!this.allowedTools.has(toolName)) {
      throw new Error(`Capability is not available in code mode: ${toolName}`);
    }

    const tool = Object.hasOwn(this.tools, toolName)
      ? (this.tools[toolName] as Tool)
      : undefined;
    if (!tool?.execute) {
      throw new Error(`Capability is not executable: ${toolName}`);
    }

    const schema = asSchema(tool.inputSchema);
    const jsonSchema = await schema.jsonSchema;
    const normalizedInput = jsonSchema.properties?.toolCallDescription
      ? normalizeCodeModeInput(toolName, input)
      : input;
    const validation = schema.validate
      ? await schema.validate(normalizedInput)
      : { success: true as const, value: normalizedInput };
    if (!validation.success) {
      throw new Error(
        `Invalid input for ${toolName}: ${validation.error.message}`,
      );
    }

    options.abortSignal?.throwIfAborted();

    const cell = this.cells.get(options.parentToolCallId) ?? {
      activeCalls: 0,
      maxConcurrency: 0,
      fingerprints: [],
      toolNames: [],
      repeatedCalls: 0,
      maxIdenticalResultRepeats: 0,
      evidence: [],
    };
    this.cells.set(options.parentToolCallId, cell);
    const callFingerprint = fingerprint({
      toolName,
      input: invocationInput(validation.value),
    });
    cell.fingerprints.push(callFingerprint);
    cell.toolNames.push(toolName);
    if ((this.invocationCounts.get(callFingerprint) ?? 0) > 0) {
      cell.repeatedCalls += 1;
    }
    cell.activeCalls += 1;
    cell.maxConcurrency = Math.max(cell.maxConcurrency, cell.activeCalls);
    this.invocationCounts.set(
      callFingerprint,
      (this.invocationCounts.get(callFingerprint) ?? 0) + 1,
    );

    const toolCallId = `${options.parentToolCallId}:nested:${cell.fingerprints.length}`;
    const partId = this.options.getToolPartId?.(toolCallId) ?? newPartId();
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
        experimental_context: options.experimental_context,
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
      cell.evidence.push({ toolCallId, toolName, status: "succeeded" });
      this.recordResult(cell, callFingerprint, output);
      if (toolName === "response") this.terminal = true;
      return output;
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      this.options.eventBus.emit("tool-result", {
        ...eventIdentity,
        result: { type: "error-text", value: message },
      });
      cell.evidence.push({ toolCallId, toolName, status: "failed" });
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
