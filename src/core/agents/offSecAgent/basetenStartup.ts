import type { LanguageModelMiddleware } from "ai";
import type { AgentEventMap } from "../../eventBus";

export function basetenStartup(
  model: string,
  report: (event: AgentEventMap["model-loading"]) => void,
): LanguageModelMiddleware {
  return {
    specificationVersion: "v4",
    async wrapStream({ doStream, params }) {
      const signal = params.abortSignal;
      if (signal?.aborted) return doStream();
      const firstTokenStartedAt = Date.now();
      let waiting = true;
      let visible = false;
      const emit = (status: AgentEventMap["model-loading"]["status"]) =>
        report({
          model,
          firstTokenStartedAt,
          elapsedMs: Date.now() - firstTokenStartedAt,
          status,
        });
      const timer = setTimeout(() => {
        visible = true;
        emit("loading");
      }, 1000);
      const done = (status: AgentEventMap["model-loading"]["status"]) => {
        if (!waiting) return;
        waiting = false;
        signal?.removeEventListener("abort", abort);
        clearTimeout(timer);
        if (visible) emit(status);
      };
      const abort = () => done("cancelled");
      signal?.addEventListener("abort", abort, { once: true });
      try {
        const result = await doStream();
        const reader = result.stream.getReader();
        return {
          ...result,
          stream: new ReadableStream(
            {
              async pull(controller) {
                try {
                  const next = await reader.read();
                  if (next.done) {
                    reader.releaseLock();
                    done("finished");
                    controller.close();
                    return;
                  }
                  const part = next.value;
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
                } catch (error) {
                  reader.releaseLock();
                  done("failed");
                  controller.error(error);
                }
              },
              cancel(reason) {
                done("cancelled");
                return reader
                  .cancel(reason)
                  .finally(() => reader.releaseLock());
              },
            },
            { highWaterMark: 0 },
          ),
        };
      } catch (error) {
        done("failed");
        throw error;
      }
    },
  };
}
