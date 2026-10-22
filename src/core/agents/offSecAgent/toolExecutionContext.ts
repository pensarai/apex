import type { ToolSet } from "ai";
import type { ToolExecutionContext } from "./types";

export function wrapToolExecutionContext(
  tools: ToolSet,
  context: ToolExecutionContext,
): ToolSet {
  return Object.fromEntries(
    Object.entries(tools).map(([toolName, entry]) => {
      const execute = entry.execute;
      if (!execute) return [toolName, entry];
      return [
        toolName,
        {
          ...entry,
          // The SDK detects AsyncIterable before awaiting execute's return value.
          execute: async function* (input, options) {
            const call = { toolName, toolCallId: options.toolCallId };
            const output = await context.run(call, async () =>
              execute(input, options),
            );
            if (
              output != null &&
              typeof output === "object" &&
              Symbol.asyncIterator in output
            ) {
              const iterator = await context.run(call, async () =>
                output[Symbol.asyncIterator](),
              );
              let completed = false;
              try {
                while (true) {
                  const step = await context.run(call, async () =>
                    iterator.next(),
                  );
                  if (step.done) {
                    completed = true;
                    return;
                  }
                  yield step.value;
                }
              } finally {
                const close = iterator.return;
                if (!completed && close) {
                  await context.run(call, async () => close.call(iterator));
                }
              }
            } else {
              yield output;
            }
          },
        } satisfies ToolSet[string],
      ];
    }),
  );
}
