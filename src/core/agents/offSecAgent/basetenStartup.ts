import type { LanguageModelV3StreamPart } from "@ai-sdk/provider";
import type { LanguageModelMiddleware } from "ai";
import type { AgentEventMap } from "../../eventBus";

export function basetenStartup(
  model: string,
  report: (event: AgentEventMap["model-loading"]) => void,
): LanguageModelMiddleware {
  let receivedOutput = false;
  return {
    specificationVersion: "v3",
    async wrapStream({ doStream, params }) {
      const signal = params.abortSignal;
      if (receivedOutput || signal?.aborted) return doStream();
      const firstTokenStartedAt = Date.now();
      let waiting = true;
      const emit = (status: AgentEventMap["model-loading"]["status"]) =>
        report({
          model,
          firstTokenStartedAt,
          elapsedMs: Date.now() - firstTokenStartedAt,
          status,
        });
      const done = (status: AgentEventMap["model-loading"]["status"]) => {
        if (!waiting) return;
        waiting = false;
        signal?.removeEventListener("abort", abort);
        if (status === "ready") receivedOutput = true;
        emit(status);
      };
      const abort = () => done("cancelled");
      signal?.addEventListener("abort", abort, { once: true });
      emit("loading");
      try {
        const result = await doStream();
        const relay = new TransformStream<
          LanguageModelV3StreamPart,
          LanguageModelV3StreamPart
        >({
          transform(part, controller) {
            if (waiting) {
              if (part.type === "error") done("failed");
              else if (
                part.type === "tool-call" ||
                part.type === "tool-input-start" ||
                ((part.type === "text-delta" ||
                  part.type === "reasoning-delta" ||
                  part.type === "tool-input-delta") &&
                  part.delta.length > 0)
              )
                done("ready");
            }
            controller.enqueue(part);
          },
        });
        void result.stream.pipeTo(relay.writable).then(
          () => done("finished"),
          () => done("failed"),
        );
        return { ...result, stream: relay.readable };
      } catch (error) {
        done("failed");
        throw error;
      }
    },
  };
}
