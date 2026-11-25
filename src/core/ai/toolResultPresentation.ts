import { join } from "node:path";
import type { ModelMessage } from "ai";
import {
  boundedOutputPreview,
  persistToolOutput,
} from "../agents/offSecAgent/tools/toolOutput";

const PRESENTATION_TOOLS = new Set([
  "read_file",
  "grep",
  "list_files",
  "execute_command",
]);
type Result = Extract<ModelMessage, { role: "tool" }>["content"][number];
type ToolResult = Extract<Result, { type: "tool-result" }>;

export function createToolResultPresenter(
  initial: ModelMessage[],
  sessionPath: string,
) {
  const outputs = new Map<string, ToolResult["output"]>();
  const results = (messages: ModelMessage[]) =>
    messages.flatMap((message) =>
      message.role === "tool"
        ? message.content.filter(
            (part): part is ToolResult => part.type === "tool-result",
          )
        : [],
    );
  for (const part of results(initial))
    outputs.set(part.toolCallId, part.output);

  return (messages: ModelMessage[]): ModelMessage[] => {
    const fresh = results(messages).filter(
      (part) =>
        PRESENTATION_TOOLS.has(part.toolName) && !outputs.has(part.toolCallId),
    );
    // Preserve usable status and retrieval references even in unusually wide batches.
    const maxBytes = Math.max(
      512,
      Math.min(8 * 1024, Math.floor((32 * 1024) / Math.max(1, fresh.length))),
    );
    for (const part of fresh) {
      const output = part.output;
      if (output.type !== "text" && output.type !== "json") {
        outputs.set(part.toolCallId, output);
        continue;
      }
      const serialized =
        output.type === "text" ? output.value : JSON.stringify(output.value);
      if (Buffer.byteLength(serialized) <= maxBytes) {
        outputs.set(part.toolCallId, output);
        continue;
      }
      const text =
        typeof output.value === "string"
          ? output.value
          : output.value !== null && typeof output.value === "object"
            ? Object.entries(output.value)
                .map(
                  ([key, value]) =>
                    `${key}:\n${typeof value === "string" ? value : JSON.stringify(value)}`,
                )
                .join("\n\n")
            : serialized;
      const reference =
        /^tool-output:[0-9a-f-]{36}\b/.exec(text)?.[0] ??
        persistToolOutput(join(sessionPath, "logs"), part.toolCallId, text);
      const status =
        output.type === "json" &&
        typeof output.value === "object" &&
        output.value !== null
          ? JSON.stringify(
              Object.fromEntries(
                Object.entries(output.value).filter(([key]) =>
                  [
                    "success",
                    "exitCode",
                    "truncated",
                    "stdoutTruncated",
                    "stderrTruncated",
                  ].includes(key),
                ),
              ),
            )
          : "Inspect the captured result for execution status.";
      const header = `${reference}\n${status}\nCaptured result available via read_file or grep.\n`;
      outputs.set(part.toolCallId, {
        type: "text",
        value:
          header +
          boundedOutputPreview(
            text,
            "... output omitted ...",
            maxBytes - Buffer.byteLength(header),
          ),
      });
    }
    // SDK retries rebuild raw results; reuse the exact presentation already consumed.
    return messages.map((message) =>
      message.role === "tool"
        ? {
            ...message,
            content: message.content.map((part) =>
              part.type === "tool-result" && outputs.has(part.toolCallId)
                ? {
                    ...part,
                    output: outputs.get(part.toolCallId) ?? part.output,
                  }
                : part,
            ),
          }
        : message,
    );
  };
}
