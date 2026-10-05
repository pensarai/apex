import {
  type ToolExecutionOptions,
  type ToolResultPart,
  type ToolSet,
  toolModelMessageSchema,
} from "ai";
import type { ToolExecutionRecorder } from "../../runtime/runToolStore";

/** The model-visible settled shape the journal stores (runToolStore contract). */
type SettledOutput = ToolResultPart["output"];
type JsonValue = Extract<ToolResultPart["output"], { type: "json" }>["value"];

type ExecutableTool = {
  readonly [key: string]: unknown;
  execute?: (input: never, options: ToolExecutionOptions) => unknown;
  toModelOutput?: (options: {
    toolCallId: string;
    input: unknown;
    output: unknown;
  }) => SettledOutput | PromiseLike<SettledOutput>;
};

const STREAMING_OUTPUT_REJECTED =
  "Streaming tool output is not supported in recorded runs; the journal settles one final result per call";

/** Mirrors the SDK's default conversion exactly (createToolModelOutput). */
function defaultModelOutput(output: unknown): SettledOutput {
  if (typeof output === "string") return { type: "text", value: output };
  // toJSONValue(undefined) === null; anything else passes through as JSON.
  const value = (output === undefined ? null : output) as JsonValue;
  return { type: "json", value };
}

function isAsyncIterable(value: unknown): value is AsyncIterable<unknown> {
  return (
    typeof value === "object" &&
    value !== null &&
    Symbol.asyncIterator in (value as Record<symbol, unknown>)
  );
}

/**
 * Validate first so non-JSON values (NaN, Infinity, invalid shapes) fail
 * before settlement instead of being silently coerced by the stringify
 * round-trip, which strips legal undefined members the JSON transport
 * cannot carry (SQLite would otherwise drop them lossily).
 */
function transportShape(
  toolCallId: string,
  toolName: string,
  output: SettledOutput,
): SettledOutput {
  const validated = toolModelMessageSchema.safeParse({
    role: "tool",
    content: [{ type: "tool-result", toolCallId, toolName, output }],
  });
  if (!validated.success) {
    throw new Error(
      `Tool result for ${toolCallId} is not a valid model-visible output`,
    );
  }
  return JSON.parse(JSON.stringify(output)) as SettledOutput;
}

function reuseRaw(output: SettledOutput): unknown {
  return output.type === "text" || output.type === "json"
    ? output.value
    : output;
}

/**
 * Journal recorded-run tool calls. Intent is committed before any effect,
 * the exact model-visible conversion is normalized once to the JSON
 * transport shape and settled before the SDK can expose the result, and
 * that settled shape is cached by toolCallId so repeated SDK conversions
 * never re-run a spill-writing converter. Callers that pass no recorder
 * are never wrapped.
 */
export function wrapRecordedTools(
  tools: ToolSet,
  recorder: ToolExecutionRecorder,
): ToolSet {
  // Conflicting ids are rejected by the recorder's name/input/policy
  // comparison, so a cache hit is always this run's own settled outcome.
  const conversions = new Map<string, SettledOutput>();

  const wrapped: Record<string, unknown> = {};
  for (const [name, entry] of Object.entries(tools)) {
    const tool = entry as ExecutableTool;
    if (typeof tool?.execute !== "function") {
      wrapped[name] = entry;
      continue;
    }
    const originalExecute = tool.execute.bind(tool) as unknown as (
      input: unknown,
      options: ToolExecutionOptions,
    ) => Promise<unknown>;
    const originalToModelOutput = tool.toModelOutput?.bind(tool);

    wrapped[name] = {
      ...tool,
      execute: async (input: unknown, options: ToolExecutionOptions) => {
        // Snapshot synchronously before the gate: caller mutation during
        // the intent wait cannot change what executes versus what commits.
        const committedInput = structuredClone(input);
        const gate = await recorder.beforeExecute({
          toolCallId: options.toolCallId,
          toolName: name,
          input: committedInput,
        });
        if (gate.kind === "reuse") {
          const settled = structuredClone(gate.output);
          conversions.set(options.toolCallId, settled);
          return reuseRaw(settled);
        }
        try {
          // The intent row is committed; an abort from here on leaves an
          // unsettled operation rather than a silent skip.
          options.abortSignal?.throwIfAborted();
          const raw = await originalExecute(committedInput, options);
          if (isAsyncIterable(raw)) {
            throw new Error(STREAMING_OUTPUT_REJECTED);
          }
          const modelOutput = originalToModelOutput
            ? await originalToModelOutput({
                toolCallId: options.toolCallId,
                input: committedInput,
                output: raw,
              })
            : defaultModelOutput(raw);
          // The round-trip detaches and normalizes to the JSON transport
          // shape, so the journal receipt and the cached conversion are
          // exactly equal.
          const settled = transportShape(options.toolCallId, name, modelOutput);
          await recorder.settle(options.toolCallId, settled);
          conversions.set(options.toolCallId, settled);
          return raw;
        } catch (error) {
          // Anything thrown past the intent gate is an unsettled operation —
          // never a safe "failed". A latched recorder is already terminal,
          // so its rejection must not mask the original error.
          await recorder.unknown(options.toolCallId).catch(() => {});
          throw error;
        }
      },
      toModelOutput: async (call: {
        toolCallId: string;
        input: unknown;
        output: unknown;
      }) => {
        const cached = conversions.get(call.toolCallId);
        // Detached per read: mutating a served value cannot poison the cache.
        if (cached) return structuredClone(cached);
        if (originalToModelOutput) return await originalToModelOutput(call);
        return defaultModelOutput(call.output);
      },
    };
  }
  return wrapped as ToolSet;
}
