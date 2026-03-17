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
import { createAllTools, EMAIL_TOOL_NAMES_ACTIVE } from "./tools";
import { createResponseTool, RESPONSE_TOOL_NAME } from "./tools/response";
import { PersistentShell } from "./tools/persistentShell";
import { BASE_SYSTEM_PROMPT, buildSessionWorkspaceSection } from "./prompt";
import type { ApprovalGate } from "../../operator";
import { ApprovalDeniedError } from "../../operator";
import { create as createSession, type SessionInfo } from "../../session";
import { join } from "path";
import { writeFileSync, mkdirSync, existsSync } from "fs";

function cloneModelMessages(messages: ModelMessage[]): ModelMessage[] {
  return JSON.parse(JSON.stringify(messages)) as ModelMessage[];
}

function persistMessagesSnapshot(
  messagesPath: string,
  messages: ModelMessage[],
): void {
  writeFileSync(messagesPath, JSON.stringify(messages, null, 2));
}

type AssistantMessage = Extract<ModelMessage, { role: "assistant" }>;
type AssistantPart = Exclude<AssistantMessage["content"], string>[number];
type ToolMessage = Extract<ModelMessage, { role: "tool" }>;
type ToolPart = ToolMessage["content"][number];

function ensureAssistantParts(messages: ModelMessage[]): AssistantPart[] {
  const last = messages[messages.length - 1];

  if (!last || last.role !== "assistant") {
    const nextContent: AssistantPart[] = [];
    const next = {
      role: "assistant" as const,
      content: nextContent,
    } as AssistantMessage;
    messages.push(next);
    return nextContent;
  }

  if (typeof last.content === "string") {
    const content = last.content;
    const parts =
      content.length > 0
        ? ([{ type: "text", text: content }] as AssistantPart[])
        : [];
    (last as AssistantMessage as { content: AssistantPart[] }).content = parts;
    return parts;
  }

  if (Array.isArray(last.content)) {
    return (last as AssistantMessage).content as AssistantPart[];
  }

  (last as AssistantMessage).content = [];
  return (last as AssistantMessage).content as AssistantPart[];
}

function appendAssistantText(messages: ModelMessage[], text: string): void {
  const last = messages[messages.length - 1];
  if (last?.role === "assistant" && typeof last.content === "string") {
    last.content += text;
    return;
  }

  const parts = ensureAssistantParts(messages);
  const lastPart = parts[parts.length - 1];
  if (lastPart?.type === "text" && typeof lastPart.text === "string") {
    lastPart.text += text;
    return;
  }

  parts.push({ type: "text", text } as AssistantPart);
}

function upsertAssistantToolCall(
  messages: ModelMessage[],
  toolCallId: string,
  toolName: string,
  input?: unknown,
): void {
  const parts = ensureAssistantParts(messages);
  const existing = parts.find(
    (
      part,
    ): part is Extract<
      AssistantPart,
      { type: "tool-call"; toolCallId: string }
    > => part.type === "tool-call" && part.toolCallId === toolCallId,
  );

  if (existing) {
    existing.toolName = toolName;
    if (input !== undefined) {
      existing.input = input;
    }
    return;
  }

  parts.push({
    type: "tool-call",
    toolCallId,
    toolName,
    input: input ?? {},
  } as AssistantPart);
}

function appendToolResult(
  messages: ModelMessage[],
  toolCallId: string,
  toolName: string,
  output: unknown,
): void {
  const part = {
    type: "tool-result",
    toolCallId,
    toolName,
    output,
  } as ToolPart;
  messages.push({
    role: "tool",
    content: [part],
  } as ToolMessage);
}

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

  private readonly abortSignal?: AbortSignal;

  /** The session this agent is operating within. */
  private readonly _session: SessionInfo;

  /** Path to the persisted operator/session transcript. */
  private readonly messagesPath: string;

  /** Best-effort live snapshot used to persist canceled runs. */
  private readonly persistedMessagesRef: { current: ModelMessage[] };

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

    // -- Persistent shell (local mode only) -----------------------------------
    // Shell survives command cancellation; only disposed in consume() after the
    // stream ends, or when the agent is fully killed.
    if (!input.sandbox) {
      this.persistentShell = new PersistentShell({
        cwd: input.session.rootPath,
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
      target: input.target,
      abortSignal: input.abortSignal,
      model: input.model,
      authConfig: input.authConfig,
      callbacks: input.callbacks,
      subagentCallbacks,
      sandbox: input.sandbox,
      findingsRegistry: input.findingsRegistry,
      attackSurfaceRegistry: input.attackSurfaceRegistry,
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
    this.messagesPath = messagesPath;

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
    this.persistedMessagesRef = {
      current: cloneModelMessages(initialMessagesRef.current),
    };
    persistMessagesSnapshot(
      this.messagesPath,
      this.persistedMessagesRef.current,
    );

    // -- Stream ---------------------------------------------------------------
    this.streamResult = streamResponse({
      prompt: input.prompt,
      system:
        (input.system ?? BASE_SYSTEM_PROMPT) +
        buildSessionWorkspaceSection(input.session),
      model: input.model,
      messages: input.messages,
      tools,
      activeTools,
      stopWhen,
      toolChoice: "auto",
      onStepFinish: (event) => {
        try {
          const allMessages = [
            ...initialMessagesRef.current,
            ...event.response.messages,
          ];
          this.persistedMessagesRef.current = cloneModelMessages(allMessages);
          persistMessagesSnapshot(
            messagesPath,
            this.persistedMessagesRef.current,
          );
        } catch {
          // Best-effort persistence — don't break the agent loop
        }
        input.onStepFinish?.(event);
      },
      onSummarized: () => {
        // Context was reset by summarization — discard the old history so
        // subsequent onStepFinish writes only persist post-summary messages.
        initialMessagesRef.current = [];
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
      onToolCallStreaming,
      onToolCallDelta,
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
          appendAssistantText(this.persistedMessagesRef.current, chunk.text);
          persistMessagesSnapshot(
            this.messagesPath,
            this.persistedMessagesRef.current,
          );
          break;
        case "tool-input-start": {
          const delta = { toolCallId: chunk.id, toolName: chunk.toolName };
          onToolCallStreaming?.(delta);
          subagentCallbacks?.onToolCallStreaming?.({
            ...delta,
            subagentId: sid,
          });
          upsertAssistantToolCall(
            this.persistedMessagesRef.current,
            chunk.id,
            chunk.toolName,
          );
          persistMessagesSnapshot(
            this.messagesPath,
            this.persistedMessagesRef.current,
          );
          break;
        }
        case "tool-input-delta": {
          const delta = { toolCallId: chunk.id, argsTextDelta: chunk.delta };
          onToolCallDelta?.(delta);
          subagentCallbacks?.onToolCallDelta?.({
            ...delta,
            subagentId: sid,
          });
          break;
        }
        case "tool-call":
          onToolCall?.(chunk);
          subagentCallbacks?.onToolCall?.({ ...chunk, subagentId: sid });
          upsertAssistantToolCall(
            this.persistedMessagesRef.current,
            chunk.toolCallId,
            chunk.toolName,
            chunk.input,
          );
          persistMessagesSnapshot(
            this.messagesPath,
            this.persistedMessagesRef.current,
          );
          break;
        case "tool-result":
          onToolResult?.(chunk);
          subagentCallbacks?.onToolResult?.({ ...chunk, subagentId: sid });
          appendToolResult(
            this.persistedMessagesRef.current,
            chunk.toolCallId,
            chunk.toolName,
            chunk.output,
          );
          persistMessagesSnapshot(
            this.messagesPath,
            this.persistedMessagesRef.current,
          );
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
