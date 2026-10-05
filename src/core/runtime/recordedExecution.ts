import type { InferenceRecorder } from "../ai";
import type { ToolExecutionRecorder } from "./runToolStore";

// Tool journal failures must cross SDK callbacks that discard execute errors.
export function composeRecordedExecution(
  inference: InferenceRecorder,
  tools: () => ToolExecutionRecorder | undefined,
): InferenceRecorder {
  const flush = async (): Promise<void> => {
    const results = await Promise.allSettled([
      inference.flush(),
      tools()?.flush(),
    ]);
    const errors = results.flatMap((result) =>
      result.status === "rejected" ? [result.reason] : [],
    );
    if (errors.length === 1) throw errors[0];
    if (errors.length > 1) {
      throw new AggregateError(errors, "Recorded execution persistence failed");
    }
  };
  return {
    ...inference,
    beforeDispatch: async (
      ...args: Parameters<typeof inference.beforeDispatch>
    ) => {
      await tools()?.flush();
      await inference.beforeDispatch(...args);
    },
    beforeToolCall: async (
      ...args: Parameters<typeof inference.beforeToolCall>
    ) => {
      await tools()?.flush();
      await inference.beforeToolCall(...args);
    },
    flush,
  };
}
