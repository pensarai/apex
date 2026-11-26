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
            let iterator: AsyncIterator<unknown> | undefined;
            let completed = false;
            const errors: unknown[] = [];
            try {
              const output = await context.run(call, async () => {
                options.abortSignal?.throwIfAborted();
                return execute(input, options);
              });
              if (
                output != null &&
                typeof output === "object" &&
                Symbol.asyncIterator in output
              ) {
                const active = await context.run(call, async () =>
                  output[Symbol.asyncIterator](),
                );
                iterator = active;
                while (true) {
                  const step = await context.run(call, async () => {
                    options.abortSignal?.throwIfAborted();
                    return active.next();
                  });
                  if (step.done) {
                    completed = true;
                    return;
                  }
                  yield step.value;
                }
              } else {
                yield output;
              }
            } catch (error) {
              errors.push(error);
            } finally {
              try {
                const active = iterator;
                const close = active?.return;
                if (!completed && active && close) {
                  let step = await context.run(call, async () =>
                    close.call(active),
                  );
                  while (!step.done) {
                    step = await context.run(call, async () => active.next());
                  }
                }
              } catch (error) {
                if (!errors.includes(error)) errors.push(error);
              }
              try {
                await context.finish?.(call);
              } catch (error) {
                if (!errors.includes(error)) errors.push(error);
              }
              // biome-ignore lint/correctness/noUnsafeFinally: preserve cleanup failure even on an early generator return.
              if (errors.length === 1) throw errors[0];
              if (errors.length > 1)
                // biome-ignore lint/correctness/noUnsafeFinally: preserve every cause when return cleanup also fails.
                throw new AggregateError(
                  errors,
                  `Tool ${toolName} execution and cleanup failed`,
                );
            }
          },
        } satisfies ToolSet[string],
      ];
    }),
  );
}
