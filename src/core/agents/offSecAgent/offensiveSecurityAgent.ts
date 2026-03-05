import { streamResponse } from "../../ai";
import type {
  ModelMessage,
  StreamTextResult,
  StopCondition,
  TextStreamPart,
  ToolSet,
} from "ai";
import { hasToolCall } from "ai";
import type { OffensiveSecurityAgentInput, ConsumeCallbacks } from "./types";
import { createAllTools, EMAIL_TOOL_NAMES_ACTIVE } from "./tools";
import { createResponseTool, RESPONSE_TOOL_NAME } from "./tools/response";
import { PersistentShell } from "./tools/persistentShell";
import { DEFAULT_SYSTEM_PROMPT } from "./prompt";
import type { ApprovalGate } from "../../operator";
import { ApprovalDeniedError } from "../../operator";
import { join } from "path";
import { writeFileSync, mkdirSync, existsSync } from "fs";

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

  /** Persistent shell for local-mode command execution; disposed on consume() completion. */
  private readonly persistentShell?: PersistentShell;

  constructor(input: OffensiveSecurityAgentInput<TResult>) {
    this.subagentId = input.subagentId;

    // -- Persistent shell (local mode only) -----------------------------------
    // Shell survives command cancellation; only disposed in consume() after the
    // stream ends, or when the agent is fully killed.
    if (!input.sandbox) {
      this.persistentShell = new PersistentShell();
      input.callbacks?.onCancelCommandAvailable?.(() =>
        this.persistentShell!.cancelCurrentCommand(),
      );
    }

    // -- Tools ----------------------------------------------------------------
    const credentialManager =
      input.credentialManager ?? input.session.credentialManager;

    const builtinTools = createAllTools({
      session: input.session,
      target: input.target,
      abortSignal: input.abortSignal,
      model: input.model,
      authConfig: input.authConfig,
      callbacks: input.callbacks,
      subagentCallbacks: input.subagentCallbacks,
      sandbox: input.sandbox,
      findingsRegistry: input.findingsRegistry,
      credentialManager,
      persistentShell: this.persistentShell,
      onCommandOutput: input.callbacks?.onCommandOutput,
    });

    let tools: ToolSet = input.extraTools
      ? { ...builtinTools, ...input.extraTools }
      : { ...builtinTools };

    // -- Approval gate wrapping -----------------------------------------------
    if (input.approvalGate) {
      tools = wrapToolsWithApprovalGate(tools, input.approvalGate);
    }

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

    // -- Filter email tools when no inboxes are configured -------------------
    const hasEmail =
      (input.session.config?.emailIntegration?.inboxes?.length ?? 0) > 0;

    const emailToolSet = new Set<string>(EMAIL_TOOL_NAMES_ACTIVE);
    const activeTools = hasEmail
      ? (input.activeTools as string[])
      : (input.activeTools as string[]).filter((t) => !emailToolSet.has(t));

    // -- Messages persistence -------------------------------------------------
    const messagesDir = input.messagesDir ?? input.session.rootPath;
    if (!existsSync(messagesDir)) {
      mkdirSync(messagesDir, { recursive: true });
    }
    const messagesPath = join(messagesDir, "messages.json");

    const initialMessages: ModelMessage[] = input.messages
      ? [...input.messages]
      : [
          {
            role: "user" as const,
            content: [{ type: "text", text: input.prompt }],
          },
        ];

    // -- Stream ---------------------------------------------------------------
    this.streamResult = streamResponse({
      prompt: input.prompt,
      system: input.system ?? DEFAULT_SYSTEM_PROMPT,
      model: input.model,
      messages: input.messages,
      tools,
      activeTools,
      stopWhen,
      toolChoice: "auto",
      onStepFinish: (event) => {
        try {
          const allMessages = [...initialMessages, ...event.response.messages];
          writeFileSync(messagesPath, JSON.stringify(allMessages, null, 2));
        } catch {
          // Best-effort persistence — don't break the agent loop
        }
        input.onStepFinish?.(event);
      },
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

    this.persistentShell?.dispose();

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

/**
 * Wrap every tool's execute function with the approval gate so that
 * tool calls are held until the operator approves them.
 */
function wrapToolsWithApprovalGate(
  tools: ToolSet,
  gate: ApprovalGate,
): ToolSet {
  const wrapped: ToolSet = {};

  for (const [name, coreTool] of Object.entries(tools)) {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const t = coreTool as any;

    if (!t.execute) {
      wrapped[name] = coreTool;
      continue;
    }

    const originalExecute = t.execute;

    wrapped[name] = {
      ...t,
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      execute: async (args: Record<string, unknown>, options: any) => {
        const toolCallId =
          args.toolCallId ??
          `tc_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`;

        try {
          await gate.check(name, String(toolCallId), args);
        } catch (err) {
          if (err instanceof ApprovalDeniedError) {
            return { blocked: true, reason: "Denied by operator" };
          }
          throw err;
        }

        return originalExecute(args, options);
      },
    };
  }

  return wrapped;
}
