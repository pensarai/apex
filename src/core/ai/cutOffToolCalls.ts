import type {
  LanguageModelV3,
  LanguageModelV3FinishReason,
  LanguageModelV3StreamPart,
} from "@ai-sdk/provider";
import { createLogger } from "../logger/structured";
import { scopedLogger } from "../util/lazyLogger";

const log = scopedLogger(() => createLogger("ai"));

/** Finish reasons under which the provider stopped the model mid-response. */
const CUT_OFF: ReadonlySet<LanguageModelV3FinishReason["unified"]> = new Set([
  "content-filter",
  "length",
]);

function warnDropped(toolNames: string[], reason: string): void {
  if (toolNames.length === 0) return;
  log.warn(
    `Dropped ${toolNames.length} tool call(s) from a response cut off by the provider (finishReason=${reason}); their input may be incomplete.`,
    { toolNames, finishReason: reason },
  );
}

/**
 * Holds tool calls until the response's finish reason is known and drops them
 * when the provider cut the response off. A cut-off call's input can still be
 * valid JSON — `rm -rf /tmp/work` arriving closed as `rm -rf /tmp` — and would
 * otherwise execute. A stream that ends without a finish part drops them too.
 */
export function withCutOffToolCallGuard(
  model: LanguageModelV3,
): LanguageModelV3 {
  return {
    specificationVersion: model.specificationVersion,
    provider: model.provider,
    modelId: model.modelId,
    supportedUrls: model.supportedUrls,
    doGenerate: async (options) => {
      const result = await model.doGenerate(options);
      if (!CUT_OFF.has(result.finishReason.unified)) return result;
      warnDropped(
        result.content.flatMap((part) =>
          part.type === "tool-call" ? [part.toolName] : [],
        ),
        result.finishReason.unified,
      );
      return {
        ...result,
        content: result.content.filter((part) => part.type !== "tool-call"),
      };
    },
    doStream: async (options) => {
      const result = await model.doStream(options);
      const held: Extract<LanguageModelV3StreamPart, { type: "tool-call" }>[] =
        [];
      return {
        ...result,
        stream: result.stream.pipeThrough(
          new TransformStream<
            LanguageModelV3StreamPart,
            LanguageModelV3StreamPart
          >({
            transform(part, controller) {
              if (part.type === "tool-call") {
                held.push(part);
                return;
              }
              if (part.type === "finish") {
                if (CUT_OFF.has(part.finishReason.unified))
                  warnDropped(
                    held.map((call) => call.toolName),
                    part.finishReason.unified,
                  );
                else for (const call of held) controller.enqueue(call);
                held.length = 0;
              }
              controller.enqueue(part);
            },
            flush() {
              warnDropped(
                held.map((call) => call.toolName),
                "missing",
              );
            },
          }),
        ),
      };
    },
  };
}
