import type { ModelMessage, ToolResultPart } from "ai";

// ---------------------------------------------------------------------------
// Interrupted-step messages — pure construction of the transcript messages
// that make an interrupted step resumable: synthetic tool-results for open
// calls, plus (when the persisted base doesn't already carry them) an
// assistant tool-call turn reconstructed from streamed arguments.
// ---------------------------------------------------------------------------

export interface SyntheticToolResultsInput {
  inFlightTools: ReadonlyMap<string, string>;
  reason: string;
  /** Tool name treated as the structured-response tool. */
  responseToolName: string;
  /** Whether the response tool fired successfully before the interruption. */
  responseSubmitted: boolean;
}

/**
 * Synthetic tool-results for every open call. A `response` tool that already
 * fired before the interruption didn't fail — it reads "Response submitted."
 * instead of the aborted error.
 */
export function buildSyntheticToolResults(
  input: SyntheticToolResultsInput,
): ToolResultPart[] {
  const output = {
    type: "error-text" as const,
    value: `Tool execution aborted: ${input.reason}`,
  };
  const parts: ToolResultPart[] = [];
  for (const [toolCallId, toolName] of input.inFlightTools) {
    const result =
      toolName === input.responseToolName && input.responseSubmitted
        ? { type: "text" as const, value: "Response submitted." }
        : output;
    parts.push({
      type: "tool-result",
      toolCallId,
      toolName,
      output: result,
    });
  }
  return parts;
}

/** Whether an assistant message's content already carries every tool-call id. */
export function baseContainsToolCalls(
  msg: ModelMessage,
  toolCallIds: Set<string>,
): boolean {
  if (!Array.isArray(msg.content)) return false;
  const contentToolIds = new Set(
    (msg.content as Array<{ type: string; toolCallId?: string }>)
      .filter((p) => p.type === "tool-call" && p.toolCallId)
      .map((p) => p.toolCallId),
  );
  return [...toolCallIds].every((id) => contentToolIds.has(id));
}

export interface InterruptedStepMessagesInput {
  /** Persisted conversation base the appended messages extend. */
  base: readonly ModelMessage[];
  inFlightTools: ReadonlyMap<string, string>;
  completedResults: readonly ToolResultPart[];
  /** Pre-built synthetic results for the open calls. */
  syntheticParts: readonly ToolResultPart[];
  /** Raw streamed arg text per tool-call id, for argument preservation. */
  streamedArgText?: ReadonlyMap<string, string>;
}

export interface InterruptedStepMessages {
  /** Messages to append to the base: optional assistant tool-calls, then the tool results. */
  appended: ModelMessage[];
  /** Whether an assistant tool-call turn was reconstructed. */
  needsStepReconstruction: boolean;
}

/**
 * Build the messages that close an interrupted step. When the base's last
 * message doesn't already contain this step's tool-calls (onStepFinish never
 * fired), an assistant turn is reconstructed from the streamed argument
 * text — parsing it when possible, preserving it as `{ _partial }` when the
 * JSON is malformed, `{}` when nothing streamed. The tool message pairs every
 * call with a result: completed results first, then the synthetic closes.
 */
export function buildInterruptedStepMessages(
  input: InterruptedStepMessagesInput,
): InterruptedStepMessages {
  const { base, inFlightTools, completedResults, syntheticParts } = input;

  const allToolCallIds = new Set([
    ...inFlightTools.keys(),
    ...completedResults.map((r) => r.toolCallId),
  ]);
  const lastMsg = base[base.length - 1];
  const needsStepReconstruction =
    !lastMsg ||
    lastMsg.role !== "assistant" ||
    !baseContainsToolCalls(lastMsg, allToolCallIds);

  const appended: ModelMessage[] = [];
  if (needsStepReconstruction) {
    const stepTools: Array<[string, string]> = [
      ...inFlightTools,
      ...completedResults.map((r): [string, string] => [
        r.toolCallId,
        r.toolName,
      ]),
    ];
    // Preserve whatever args the model actually streamed instead of writing an empty `{}`.
    const reconstructInput = (toolCallId: string): unknown => {
      const raw = input.streamedArgText?.get(toolCallId);
      if (!raw) return {};
      try {
        return JSON.parse(raw);
      } catch {
        return { _partial: raw };
      }
    };
    appended.push({
      role: "assistant",
      content: stepTools.map(([toolCallId, toolName]) => ({
        type: "tool-call" as const,
        toolCallId,
        toolName,
        input: reconstructInput(toolCallId),
      })),
    });
  }
  appended.push({
    role: "tool",
    content: [...completedResults, ...syntheticParts],
  });

  return { appended, needsStepReconstruction };
}
