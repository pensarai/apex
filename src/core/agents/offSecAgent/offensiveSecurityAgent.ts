import { streamResponse } from "../../ai";
import type {
  StreamTextResult,
  StopCondition,
  TextStreamPart,
  ToolSet,
} from "ai";
import { hasToolCall } from "ai";
import type { OffensiveSecurityAgentInput } from "./types";
import type { AgentEventBus } from "./eventBus";
import { createAllTools } from "./tools";
import { createResponseTool, RESPONSE_TOOL_NAME } from "./tools/response";
import { DEFAULT_SYSTEM_PROMPT } from "./prompt";

/**
 * General-purpose offensive security agent harness.
 *
 * The agent **owns tool creation** — all available tools are built from
 * the session context, and specific agents select which ones to activate
 * via the `activeTools` array (passed through to the AI SDK).
 *
 * The stream starts **immediately on construction** — no need to call a
 * separate `.run()` method.
 *
 * @typeParam TResult - The type returned by {@link consume}. When the input
 *   includes a `resolveResult` function, `consume()` awaits it after the
 *   stream finishes and returns the value. Defaults to `void`.
 *
 * ## Consumption (pick one — stream is single-read)
 *
 * **1. Event bus via `.consume()` → `TResult`**
 * ```ts
 * const bus = new AgentEventBus();
 * bus.on("text-delta", (e) => process.stdout.write(e.data.text));
 * const agent = new OffensiveSecurityAgent({ ..., eventBus: bus });
 * const result = await agent.consume();
 * ```
 *
 * **2. `for await` directly on the agent**
 * ```ts
 * for await (const chunk of agent) { ... }
 * ```
 *
 * **3. Raw stream access**
 * ```ts
 * for await (const chunk of agent.fullStream) { ... }
 * ```
 */
export class OffensiveSecurityAgent<TResult = void> {
  /** The underlying Vercel AI SDK stream result — escape hatch for advanced use. */
  public readonly streamResult: StreamTextResult<ToolSet, never>;

  private readonly resolveResult?: (
    streamResult: StreamTextResult<ToolSet, never>,
  ) => TResult | Promise<TResult>;

  private readonly eventBus?: AgentEventBus;

  constructor(input: OffensiveSecurityAgentInput<TResult>) {
    this.eventBus = input.eventBus;

    // -- Tools ----------------------------------------------------------------
    const builtinTools = createAllTools({
      session: input.session,
      target: input.target,
      abortSignal: input.abortSignal,
      model: input.model,
      authConfig: input.authConfig,
      eventBus: input.eventBus,
      sandbox: input.sandbox,
    });

    let tools: ToolSet = input.extraTools
      ? { ...builtinTools, ...input.extraTools }
      : { ...builtinTools };

    // -- Response schema → auto capture / stop / resolve ----------------------
    let capturedResponse: TResult | null = null;

    if (input.responseSchema) {
      tools = {
        ...tools,
        [RESPONSE_TOOL_NAME]: createResponseTool(
          input.responseSchema,
          (result) => {
            capturedResponse = result as TResult;
          },
        ),
      };
    }

    if (input.resolveResult) {
      this.resolveResult = input.resolveResult;
    } else if (input.responseSchema) {
      this.resolveResult = () => {
        if (capturedResponse !== null) return capturedResponse;
        return undefined as TResult;
      };
    }

    let stopWhen = input.stopWhen;
    if (input.responseSchema) {
      const responseStop = hasToolCall(
        RESPONSE_TOOL_NAME,
      ) as StopCondition<ToolSet>;
      if (!stopWhen) {
        stopWhen = responseStop;
      } else if (Array.isArray(stopWhen)) {
        stopWhen = [...stopWhen, responseStop];
      } else {
        stopWhen = [stopWhen, responseStop];
      }
    }

    // -- Stream ---------------------------------------------------------------
    this.streamResult = streamResponse({
      prompt: input.prompt,
      system: input.system ?? DEFAULT_SYSTEM_PROMPT,
      model: input.model,
      messages: input.messages,
      tools,
      activeTools: input.activeTools as string[],
      stopWhen,
      toolChoice: "auto",
      onStepFinish: input.onStepFinish,
      onFinish: input.onFinish,
      abortSignal: input.abortSignal,
      authConfig: input.authConfig,
      silent: true,
    });
  }

  // ---------------------------------------------------------------------------
  // Stream access
  // ---------------------------------------------------------------------------

  /**
   * The raw async-iterable stream of chunks.
   * Equivalent to `streamResult.fullStream`.
   */
  get fullStream(): AsyncIterable<TextStreamPart<ToolSet>> {
    return this.streamResult.fullStream;
  }

  /**
   * Makes the agent instance itself async-iterable so callers can write:
   * ```ts
   * for await (const chunk of agent) { ... }
   * ```
   *
   * **Note:** The underlying stream can only be consumed once.
   */
  async *[Symbol.asyncIterator](): AsyncIterator<TextStreamPart<ToolSet>> {
    for await (const chunk of this.streamResult.fullStream) {
      yield chunk;
    }
  }

  // ---------------------------------------------------------------------------
  // Convenience helpers
  // ---------------------------------------------------------------------------

  async consume(): Promise<TResult> {
    try {
      for await (const chunk of this.streamResult.fullStream) {
        switch (chunk.type) {
          case "text-delta":
            this.eventBus?.emit({ type: "text-delta", data: chunk });
            break;
          case "tool-call":
            this.eventBus?.emit({ type: "tool-call", data: chunk });
            break;
          case "tool-result":
            this.eventBus?.emit({ type: "tool-result", data: chunk });
            break;
          case "error":
            this.eventBus?.emit({ type: "error", error: chunk.error });
            break;
        }
      }
    } catch (error) {
      this.eventBus?.emit({ type: "error", error });
      throw error;
    }

    if (this.resolveResult) {
      return this.resolveResult(this.streamResult);
    }
    return undefined as TResult; // TResult is void when resolveResult is absent
  }

  /**
   * Promise that resolves to the final response metadata once the stream
   * has been fully consumed. Await this *after* iterating the stream.
   */
  get response() {
    return this.streamResult.response;
  }
}
