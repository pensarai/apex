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
          execute: (input, options) =>
            context.run(
              { toolName, toolCallId: options.toolCallId },
              async () => execute(input, options),
            ),
        } satisfies ToolSet[string],
      ];
    }),
  );
}
