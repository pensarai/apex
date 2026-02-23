import { streamResponse } from "../../ai";
import type { StreamTextResult, TextStreamPart, ToolSet } from "ai";
import type { OffensiveSecurityAgentInput, ConsumeCallbacks } from "./types";
import { createAllTools } from "./tools";
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
 * **1. Typed callbacks via `.consume()` → `TResult`**
 * ```ts
 * const result = await agent.consume({
 *   onTextDelta: (d) => process.stdout.write(d.text),
 *   onToolCall:  (d) => console.log(`→ ${d.toolName}`),
 * });
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

  /** Identifier for this agent when it is running as a subagent. */
  private readonly subagentId?: string;

  constructor(input: OffensiveSecurityAgentInput<TResult>) {
    this.resolveResult = input.resolveResult;
    this.subagentId = input.subagentId;

    // -- Tools ----------------------------------------------------------------
    const builtinTools = createAllTools({
      session: input.session,
      target: input.target,
      abortSignal: input.abortSignal,
      model: input.model,
      authConfig: input.authConfig,
      callbacks: input.callbacks,
      subagentCallbacks: input.subagentCallbacks,
      sandbox: input.sandbox,
    });
    const tools = input.extraTools
      ? { ...builtinTools, ...input.extraTools }
      : builtinTools;

    // -- Stream ---------------------------------------------------------------
    // streamResponse returns synchronously; the actual LLM I/O is lazy.
    this.streamResult = streamResponse({
      prompt: input.prompt,
      system: input.system ?? DEFAULT_SYSTEM_PROMPT,
      model: input.model,
      messages: input.messages,
      tools,
      activeTools: input.activeTools as string[],
      stopWhen: input.stopWhen,
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

  /**
   * Consume the stream with typed callbacks, then resolve the final result.
   *
   * Dispatches each chunk to the appropriate callback, and after the stream
   * is fully consumed, calls `resolveResult` (if provided at construction)
   * to produce a typed return value.
   *
   * @returns The value produced by `resolveResult`, or `void` if none was provided.
   */
  async consume(callbacks: ConsumeCallbacks = {}): Promise<TResult> {
    const {
      onTextDelta,
      onToolCall,
      onToolResult,
      onError,
      subagentCallbacks,
    } = callbacks;

    const sid = this.subagentId;

    for await (const chunk of this.streamResult.fullStream) {
      switch (chunk.type) {
        case "text-delta":
          onTextDelta?.(chunk);
          subagentCallbacks?.onTextDelta?.({ ...chunk, subagentId: sid });
          break;
        case "tool-call":
          onToolCall?.(chunk);
          subagentCallbacks?.onToolCall?.({ ...chunk, subagentId: sid });
          break;
        case "tool-result":
          onToolResult?.(chunk);
          subagentCallbacks?.onToolResult?.({ ...chunk, subagentId: sid });
          break;
        case "error":
          if (onError) {
            onError((chunk as { type: "error"; error: unknown }).error);
          }
          subagentCallbacks?.onError?.(chunk.error);
          break;
      }
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
