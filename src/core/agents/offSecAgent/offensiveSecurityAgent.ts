import { streamResponse } from "../../ai";
import type {
  ModelMessage,
  StreamTextResult,
  StopCondition,
  TextStreamPart,
  ToolSet,
} from "ai";
import { hasToolCall } from "ai";
import type {
  OffensiveSecurityAgentInput,
  CreateAgentInput,
  ConsumeCallbacks,
} from "./types";
import {
  createAllTools,
  EMAIL_TOOL_NAMES_ACTIVE,
  PLAN_MODE_TOOL_NAMES,
} from "./tools";
import { createResponseTool, RESPONSE_TOOL_NAME } from "./tools/response";
import { PersistentShell } from "./tools/persistentShell";
import { buildBaseSystemPrompt, buildSessionWorkspaceSection } from "./prompt";
import type { ApprovalGate } from "../../operator";
import { ApprovalDeniedError } from "../../operator";
import { create as createSession, type SessionInfo } from "../../session";
import { AgentEventBus } from "../../eventBus";
import { join } from "path";
import { mkdirSync, existsSync } from "fs";
import { writeFile } from "fs/promises";

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

  /** The event bus for this agent's streaming output. */
  public readonly eventBus: AgentEventBus;

  private readonly resolveResult?: (
    streamResult: StreamTextResult<ToolSet, never>,
  ) => TResult | Promise<TResult>;

  /** Identifier for this agent when it is running as a subagent. */
  private readonly subagentId?: string;

  /** Persistent shell for local-mode command execution; disposed on consume() completion. */
  private readonly persistentShell?: PersistentShell;

  private readonly abortSignal?: AbortSignal;

  /** The session this agent is operating within. */
  private readonly _session: SessionInfo;

  /**
   * Async factory that creates a session when one is not provided,
   * then constructs the agent. Use this instead of `new` when you
   * want the agent to own session lifecycle.
   *
   * Pass an existing `session` to reuse one (console integration,
   * subagent spawning, etc.).
   */
  static async create<TResult = void>(
    input: CreateAgentInput<TResult>,
  ): Promise<OffensiveSecurityAgent<TResult>> {
    let session = input.session;
    if (!session) {
      session = await createSession({
        targets: input.target ? [input.target] : [],
        config: input.sessionConfig,
        model: input.model,
        authConfig: input.authConfig,
        userMessage: input.prompt,
        onNameGenerated: input.onNameGenerated,
      });
    }
    return new OffensiveSecurityAgent({ ...input, session });
  }

  /** The session this agent is operating within. */
  get session(): SessionInfo {
    return this._session;
  }

  constructor(input: OffensiveSecurityAgentInput<TResult>) {
    this._session = input.session;
    this.subagentId = input.subagentId;
    this.abortSignal = input.abortSignal;
    this.eventBus = input.eventBus ?? new AgentEventBus();

    // -- Resolve agent working directory ----------------------------------------
    const agentCwd = input.session.config?.agentCwd ?? input.session.rootPath;

    // -- Persistent shell (local mode only) -----------------------------------
    // Shell survives command cancellation; only disposed in consume() after the
    // stream ends, or when the agent is fully killed.
    if (!input.sandbox) {
      this.persistentShell = new PersistentShell({
        cwd: agentCwd,
        env: input.environmentVariables,
      });
      if (input.commandCancelHandle) {
        const shell = this.persistentShell;
        input.commandCancelHandle.cancel = () => shell.cancelCurrentCommand();
      }
    }

    // -- Tools ----------------------------------------------------------------
    const credentialManager =
      input.credentialManager ?? input.session.credentialManager;

    const subagentCallbacks =
      input.subagentCallbacks ?? input.callbacks?.subagentCallbacks;

    const builtinTools = createAllTools({
      session: input.session,
      agentCwd,
      target: input.target,
      abortSignal: input.abortSignal,
      model: input.model,
      authConfig: input.authConfig,
      callbacks: input.callbacks,
      subagentCallbacks,
      eventBus: this.eventBus,
      sandbox: input.sandbox,
      findingsRegistry: input.findingsRegistry,
      attackSurfaceRegistry: input.attackSurfaceRegistry,
      credentialManager,
      persistentShell: this.persistentShell,
      onCommandOutput: input.callbacks?.onCommandOutput,
      skillsRegistry: input.skillsRegistry,
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
    let activeTools = hasEmail
      ? (input.activeTools as string[])
      : (input.activeTools as string[]).filter((t) => !emailToolSet.has(t));

    // -- Plan mode: restrict to read-only tools -----------------------------
    if (input.mode === "plan") {
      const planSet = new Set<string>(PLAN_MODE_TOOL_NAMES);
      activeTools = activeTools.filter((t) => planSet.has(t));
    }

    // -- Messages persistence -------------------------------------------------
    const messagesDir = input.messagesDir ?? input.session.rootPath;
    if (!existsSync(messagesDir)) {
      mkdirSync(messagesDir, { recursive: true });
    }
    const messagesPath = join(messagesDir, "messages.json");

    // Mutable so that summarization can clear stale history.
    const initialMessagesRef: { current: ModelMessage[] } = {
      current: input.messages
        ? [...input.messages]
        : [
            {
              role: "user" as const,
              content: [{ type: "text", text: input.prompt }],
            },
          ],
    };

    // Debounced persistence: avoid blocking the event loop with
    // JSON.stringify on every step when many agents run concurrently.
    const PERSIST_INTERVAL_MS = 15_000;
    let persistTimer: ReturnType<typeof setTimeout> | null = null;
    let latestMessages: ModelMessage[] | null = null;

    const schedulePersist = () => {
      if (persistTimer) return;
      persistTimer = setTimeout(() => {
        persistTimer = null;
        if (latestMessages) {
          const toWrite = latestMessages;
          latestMessages = null;
          writeFile(messagesPath, JSON.stringify(toWrite)).catch(() => {});
        }
      }, PERSIST_INTERVAL_MS);
    };

    // -- Stream ---------------------------------------------------------------
    this.streamResult = streamResponse({
      prompt: input.prompt,
      system:
        (input.system ??
          buildBaseSystemPrompt({
            sandboxMode: agentCwd === input.session.rootPath,
          })) + buildSessionWorkspaceSection(input.session, agentCwd),
      model: input.model,
      messages: input.messages,
      tools,
      activeTools,
      stopWhen,
      toolChoice: "auto",
      onStepFinish: async (event) => {
        latestMessages = [
          ...initialMessagesRef.current,
          ...event.response.messages,
        ];
        schedulePersist();
        await input.onStepFinish?.(event);
      },
      onSummarized: () => {
        // Context was reset by summarization — discard the old history so
        // subsequent onStepFinish writes only persist post-summary messages.
        initialMessagesRef.current = [];
      },
      onFinish: async (event) => {
        // Flush any pending persistence before finishing
        if (persistTimer) {
          clearTimeout(persistTimer);
          persistTimer = null;
        }
        const finalMessages = latestMessages ?? [
          ...initialMessagesRef.current,
          ...event.response.messages,
        ];
        await writeFile(messagesPath, JSON.stringify(finalMessages)).catch(
          () => {},
        );
        await input.onFinish?.(event);
      },
      abortSignal: input.abortSignal,
      authConfig: input.authConfig,
      onCacheMetrics: input.onCacheMetrics,
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
      onToolCallStreaming,
      onToolCallDelta,
      onToolCall,
      onToolResult,
      onError,
      subagentCallbacks,
    } = callbacks;

    const sid = this.subagentId;
    const bus = this.eventBus;

    for await (const chunk of this.streamResult.fullStream) {
      switch (chunk.type) {
        case "text-delta":
          bus.emit("text-delta", { text: chunk.text, subagentId: sid });
          onTextDelta?.(chunk);
          subagentCallbacks?.onTextDelta?.({ ...chunk, subagentId: sid });
          break;
        case "tool-input-start": {
          const delta = { toolCallId: chunk.id, toolName: chunk.toolName };
          bus.emit("tool-call-start", { ...delta, subagentId: sid });
          onToolCallStreaming?.(delta);
          subagentCallbacks?.onToolCallStreaming?.({
            ...delta,
            subagentId: sid,
          });
          break;
        }
        case "tool-input-delta": {
          const delta = { toolCallId: chunk.id, argsTextDelta: chunk.delta };
          bus.emit("tool-call-delta", { ...delta, subagentId: sid });
          onToolCallDelta?.(delta);
          subagentCallbacks?.onToolCallDelta?.({
            ...delta,
            subagentId: sid,
          });
          break;
        }
        case "tool-call":
          bus.emit("tool-call-complete", {
            toolCallId: chunk.toolCallId,
            toolName: chunk.toolName,
            args: chunk.args,
            subagentId: sid,
          });
          onToolCall?.(chunk);
          subagentCallbacks?.onToolCall?.({ ...chunk, subagentId: sid });
          break;
        case "tool-result":
          bus.emit("tool-result", {
            toolCallId: chunk.toolCallId,
            toolName: chunk.toolName,
            result: chunk.result,
            subagentId: sid,
          });
          onToolResult?.(chunk);
          subagentCallbacks?.onToolResult?.({ ...chunk, subagentId: sid });
          break;
        case "error": {
          const error = (chunk as { type: "error"; error: unknown }).error;
          bus.emit("error", { error, subagentId: sid });
          if (onError) {
            onError(error);
          }
          subagentCallbacks?.onError?.(chunk.error);
          break;
        }
      }
    }

    this.persistentShell?.dispose();

    if (this.abortSignal?.aborted) {
      throw new DOMException("Agent aborted by user", "AbortError");
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

        console.error(`[approval-gate] ${name} (${toolCallId}): checking`);
        try {
          await gate.check(name, String(toolCallId), args);
        } catch (err) {
          if (err instanceof ApprovalDeniedError) {
            console.error(`[approval-gate] ${name} (${toolCallId}): denied`);
            return { blocked: true, reason: "Denied by operator" };
          }
          throw err;
        }
        console.error(
          `[approval-gate] ${name} (${toolCallId}): approved, executing`,
        );

        const result = await originalExecute(args, options);
        console.error(
          `[approval-gate] ${name} (${toolCallId}): execute finished`,
        );
        return result;
      },
    };
  }

  return wrapped;
}
