import { existsSync, mkdirSync, readFileSync } from "node:fs";
import { writeFile } from "node:fs/promises";
import { join } from "node:path";
import type {
  ModelMessage,
  StopCondition,
  StreamTextResult,
  TextStreamPart,
  ToolCallPart,
  ToolResultPart,
  ToolSet,
} from "ai";
import { hasToolCall } from "ai";
import { streamResponse } from "../../ai";
import { AgentEventBus, type StreamIdContext } from "../../eventBus";
import {
  resolveEffectiveHeaders,
  stripBrowserManagedHeaders,
} from "../../http/targetHeaders";
import { newMessageId, newPartId } from "../../id/id";
import { getApexTracer } from "../../observability";
import type { ApprovalGate } from "../../operator";
import { ApprovalDeniedError } from "../../operator";
import { create as createSession, type SessionInfo } from "../../session";
import { detectOSAndEnhancePrompt } from "../specialized/utils";
import { buildBaseSystemPrompt, buildSessionWorkspaceSection } from "./prompt";
import {
  ASK_USER_QUESTIONS_TOOL_NAME,
  createAllTools,
  createResponseTool,
  EMAIL_TOOL_NAMES_ACTIVE,
  PersistentShell,
  PLAN_MODE_TOOL_NAMES,
  PlaywrightMcpSession,
  RESPONSE_TOOL_NAME,
  SEND_EMAIL_TOOL_NAME,
} from "./tools";
import { StepTraceWriter } from "./trace";
import type { CreateAgentInput, OffensiveSecurityAgentInput } from "./types";

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
 * **1. Emit to EventBus via `.consume()` → `TResult`**
 * ```ts
 * const bus = new AgentEventBus();
 * bus.on("text-delta", (e) => process.stdout.write(e.text));
 * bus.on("tool-call-complete", (e) => console.log(`→ ${e.toolName}`));
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

  /** The event bus for this agent's streaming output. */
  public readonly eventBus: AgentEventBus;

  private readonly resolveResult?: (
    streamResult: StreamTextResult<ToolSet, never>,
  ) => TResult | Promise<TResult>;

  /**
   * The structured result captured by the `response` tool, or `null` if the
   * agent has not (yet) called `response`.
   */
  private _capturedResponse: TResult | null = null;

  /**
   * Resolves the instant the `response` tool captures the structured result —
   * the moment the agent is semantically done, independent of stream teardown
   * (which can wedge before the final `finish` chunk). {@link consume} races
   * this so it returns the result then and drains the rest in the background.
   * Never rejects; never resolves if `response` is never called — there the
   * idle-guard-bounded drain settles `consume` instead.
   */
  private _resolveResponseCaptured!: (result: TResult) => void;
  public readonly responseCaptured: Promise<TResult> = new Promise(
    (resolve) => {
      this._resolveResponseCaptured = resolve;
    },
  );

  /** Identifier for this agent when it is running as a subagent. */
  private readonly subagentId?: string;

  /**
   * The current open assistant message id (`msg_…`) for the in-flight step.
   * Minted on the `start-step` chunk in {@link consume} and read by
   * `onStepFinish` so the closing `step-finish` event carries the same id.
   * `null` between steps.
   */
  private currentMessageId: string | null = null;

  /** Persistent shell for local-mode command execution; disposed on consume() completion. */
  private readonly persistentShell?: PersistentShell;

  /**
   * This agent's Playwright MCP browser session. Either constructed fresh
   * by this agent (when no `browserSession` was passed in) or supplied by
   * the caller (e.g. `spawn_pentest_agent` constructs a fresh, isolated
   * session for each worker, seeds it with a snapshot of the orchestrator's
   * cookies + localStorage, and hands the seeded session in here so this
   * agent's browser tools operate against an authenticated-but-isolated
   * Chromium).
   *
   * Exposed publicly so spawn tools can read this agent's session (e.g.
   * the pentest orchestrator's `browserSession` is what `spawn_pentest_agent`
   * snapshots when it builds the worker's seeded clone). The session
   * object is NOT shared between agents at runtime — each agent gets its
   * own isolated Chromium so a sub-agent can't clobber its parent's DOM,
   * cookies, or navigation state.
   *
   * Only populated for non-sandbox (local MCP) mode. In sandbox mode,
   * browser state is already shared via the sandbox's per-sandbox
   * Playwright user-data directory, so no host-side session object is
   * needed.
   */
  public readonly browserSession?: PlaywrightMcpSession;

  private readonly abortSignal?: AbortSignal;

  /** The user-facing prompt passed to the model. */
  public readonly userPrompt: string;

  /** The session this agent is operating within. */
  private readonly _session: SessionInfo;

  /** Latest accumulated messages, shared with `consume()` for abort persistence. */
  private latestMessages: ModelMessage[] | null = null;

  private messagesPath: string | null = null;

  /** Cancels the debounced persist timer so abort writes don't race it. */
  private cancelPersistTimer: (() => void) | null = null;

  private syntheticsPersisted = false;

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

  /**
   * This agent's identity on the event bus, as a session id (`ses_…`).
   *
   * For a subagent, `subagentId` is the child's own session id (minted by
   * the spawning tool). For the root agent, it is the root session's id.
   * Used to stamp `sessionId` (and the legacy `subagentId` alias) onto
   * every event this agent emits.
   */
  private get busSessionId(): string {
    return this.subagentId ?? this._session.id;
  }

  constructor(input: OffensiveSecurityAgentInput<TResult>) {
    this._session = input.session;
    this.subagentId = input.subagentId;
    this.abortSignal = input.abortSignal;
    this.userPrompt = input.prompt;
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

    // -- Browser session (local MCP mode only) -------------------------------
    // Either inherit from the parent agent (e.g. pentest orchestrator handing
    // its authenticated context down via spawn_pentest_agent) or construct a
    // fresh one. The session itself does not spawn the MCP child / Chromium
    // until the first browser tool call, so eager construction is cheap even
    // for agents that never use browser tools. Sandbox-mode agents already
    // share browser state via the sandbox's per-sandbox Playwright user-data
    // dir, so they don't need a session object on the host.
    if (!input.sandbox) {
      // Snapshot resolved headers into the browser session. Later mutations
      // require a browser restart to take effect.
      const sessionHeaders = input.target
        ? resolveEffectiveHeaders(input.session, input.target)
        : input.session.config?.headers;
      this.browserSession =
        input.browserSession ??
        new PlaywrightMcpSession({
          extraHttpHeaders: stripBrowserManagedHeaders(sessionHeaders),
        });
    }

    // -- Step trace (trace.jsonl) ---------------------------------------------
    // Created before tools so the checkpoint_state tool can reference it.
    const messagesDir =
      input.messagesDir ??
      (input.subagentId
        ? join(input.session.rootPath, "subagents", input.subagentId)
        : input.session.rootPath);
    const tracePath = input.subagentId
      ? join(
          input.session.rootPath,
          "subagents",
          `${input.subagentId}.trace.jsonl`,
        )
      : join(messagesDir, "trace.jsonl");
    const traceWriter = new StepTraceWriter({
      tracePath,
      agentId: input.subagentId ?? null,
      eventBus: this.eventBus,
    });

    // -- Task directory (per-agent tasks, opt-in via taskDriven config) -------
    const taskDriven = input.session.config?.taskDriven ?? false;
    const tasksDir =
      input.tasksDir ??
      (taskDriven
        ? input.subagentId
          ? join(
              input.session.rootPath,
              "subagents",
              `${input.subagentId}-tasks`,
            )
          : join(input.session.rootPath, "tasks")
        : undefined);

    // -- Tools ----------------------------------------------------------------
    const credentialManager =
      input.credentialManager ?? input.session.credentialManager;

    const builtinTools = createAllTools({
      session: input.session,
      agentCwd,
      target: input.target,
      abortSignal: input.abortSignal,
      model: input.model,
      authConfig: input.authConfig,
      eventBus: this.eventBus,
      sandbox: input.sandbox,
      findingsRegistry: input.findingsRegistry,
      attackSurfaceRegistry: input.attackSurfaceRegistry,
      credentialManager,
      persistentShell: this.persistentShell,
      skillsRegistry: input.skillsRegistry,
      traceWriter,
      tasksDir,
      enableThinking: input.enableThinking,
      openAIReasoningEffort: input.openAIReasoningEffort,
      surfaceIntegrationEnabled: input.surfaceIntegrationEnabled,
      projectThreatModel: input.projectThreatModel,
      planSubagentId: input.planSubagentId,
      subagentId: input.subagentId,
      browserSession: this.browserSession,
    });

    let tools: ToolSet = input.extraTools
      ? { ...builtinTools, ...input.extraTools }
      : { ...builtinTools };

    // -- Approval gate wrapping -----------------------------------------------
    if (input.approvalGate) {
      tools = wrapToolsWithApprovalGate(
        tools,
        input.approvalGate,
        AGENT_PAUSE_TOOLS,
      );
    }

    // -- Response schema → auto capture / stop / resolve ----------------------
    if (input.responseSchema) {
      tools = {
        ...tools,
        [RESPONSE_TOOL_NAME]: createResponseTool(
          input.responseSchema,
          (result) => {
            this._capturedResponse = result as TResult;
            this._resolveResponseCaptured(result as TResult);
          },
        ),
      };
    }

    if (input.resolveResult) {
      this.resolveResult = input.resolveResult;
    } else if (input.responseSchema) {
      this.resolveResult = () => {
        if (this._capturedResponse !== null) return this._capturedResponse;
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

    // -- Filter email tools when no inboxes / SMTP are configured -----------
    const hasEmail =
      (input.session.config?.emailIntegration?.inboxes?.length ?? 0) > 0;
    const hasSmtp = !!input.session.config?.smtpConfig;

    const emailToolSet = new Set<string>(EMAIL_TOOL_NAMES_ACTIVE);
    let activeTools = (input.activeTools as string[]).filter((t) => {
      if (!emailToolSet.has(t)) return true;
      if (t === SEND_EMAIL_TOOL_NAME) return hasSmtp;
      return hasEmail;
    });

    // -- Plan mode: restrict to read-only tools -----------------------------
    if (input.mode === "plan") {
      const planSet = new Set<string>(PLAN_MODE_TOOL_NAMES);
      activeTools = activeTools.filter((t) => planSet.has(t));
    }

    // -- Messages persistence -------------------------------------------------
    if (!existsSync(messagesDir)) {
      mkdirSync(messagesDir, { recursive: true });
    }
    this.messagesPath = join(messagesDir, "messages.json");
    const messagesPath = this.messagesPath;

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

    const schedulePersist = () => {
      if (persistTimer) return;
      persistTimer = setTimeout(() => {
        persistTimer = null;
        if (this.latestMessages) {
          const toWrite = this.latestMessages;
          this.latestMessages = null;
          writeFile(messagesPath, JSON.stringify(toWrite)).catch(() => {});
        }
      }, PERSIST_INTERVAL_MS);
    };

    this.cancelPersistTimer = () => {
      if (persistTimer) {
        clearTimeout(persistTimer);
        persistTimer = null;
      }
    };

    // -- Init record (trace.jsonl first line) ---------------------------------
    // Hash only the base system prompt (excluding session workspace paths)
    // so the hash is stable across runs with identical prompt versions.
    const baseSystemPrompt =
      input.system ??
      detectOSAndEnhancePrompt(
        buildBaseSystemPrompt({
          sandboxMode: agentCwd === input.session.rootPath,
        }),
      );
    const systemPrompt =
      baseSystemPrompt + buildSessionWorkspaceSection(input.session, agentCwd);

    traceWriter.writeInit({
      model: input.model,
      systemPrompt: baseSystemPrompt,
      activeTools,
      sessionId: input.session.id,
      target: input.target,
    });

    // -- Stream ---------------------------------------------------------------
    // Mutable ref for cache metrics — onCacheMetrics fires synchronously
    // before onStepFinish within the same step (see ai.ts:367-391).
    let lastCacheMetrics: {
      cacheReadTokens: number;
      cacheWriteTokens: number;
    } | null = null;

    this.streamResult = streamResponse({
      prompt: input.prompt,
      system: systemPrompt,
      model: input.model,
      messages: input.messages,
      tools,
      activeTools,
      stopWhen,
      toolChoice: "auto",
      sessionPath: input.session.rootPath,
      onStepFinish: async (event) => {
        this.latestMessages = [
          ...initialMessagesRef.current,
          ...event.response.messages,
        ];
        schedulePersist();
        traceWriter.recordStep(event.response.messages as ModelMessage[], {
          inputTokens: event.usage.inputTokens ?? 0,
          outputTokens: event.usage.outputTokens ?? 0,
          ...lastCacheMetrics,
        });
        lastCacheMetrics = null;
        this.eventBus.emit("step-finish", {
          messages: event.response.messages,
          subagentId: this.subagentId,
          sessionId: this.busSessionId,
          messageId: this.currentMessageId ?? undefined,
        });
        // The step's message is now closed; the next `start-step` chunk in
        // consume() mints a fresh one.
        this.currentMessageId = null;
        await input.onStepFinish?.(event);
      },
      onSummarized: () => {
        // Context was reset by summarization — discard the old history so
        // subsequent onStepFinish writes only persist post-summary messages.
        initialMessagesRef.current = [];
        traceWriter.markSummarized();
      },
      onFinish: async (event) => {
        // Flush any pending persistence before finishing
        if (persistTimer) {
          clearTimeout(persistTimer);
          persistTimer = null;
        }
        // Skip if emitSyntheticToolResults already wrote the abort snapshot.
        if (!this.syntheticsPersisted) {
          const finalMessages = this.latestMessages ?? [
            ...initialMessagesRef.current,
            ...event.response.messages,
          ];
          await writeFile(messagesPath, JSON.stringify(finalMessages)).catch(
            () => {},
          );
        }
        await input.onFinish?.(event);
      },
      abortSignal: input.abortSignal,
      authConfig: input.authConfig,
      onCacheMetrics: (metrics) => {
        lastCacheMetrics = {
          cacheReadTokens: metrics.cacheReadInputTokens,
          cacheWriteTokens: metrics.cacheCreationInputTokens,
        };
        input.onCacheMetrics?.(metrics);
      },
      enableThinking: input.enableThinking,
      openAIReasoningEffort: input.openAIReasoningEffort,
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
   * Consume the stream, emitting each chunk on the {@link eventBus}, then
   * resolve the final result.
   *
   * Each AI SDK stream part is forwarded to the bus via
   * {@link AgentEventBus.emitStreamPart}, tagged with this agent's
   * `subagentId` when present.
   *
   * @returns The value produced by `resolveResult`, or `void` if none was provided.
   */
  async consume(): Promise<TResult> {
    const sid = this.subagentId;
    const bus = this.eventBus;

    const runConsume = async (): Promise<TResult> => {
      // Per-tool-call part ids: minted on first reference and reused for that
      // call's complete / result. Cleared each step.
      let toolParts = new Map<string, string>();
      const ids: StreamIdContext = {
        subagentId: this.busSessionId,
        sessionId: this.busSessionId,
        messageId: undefined,
        textPartId: undefined,
        toolPartId: (toolCallId: string) => {
          let p = toolParts.get(toolCallId);
          if (!p) {
            p = newPartId();
            toolParts.set(toolCallId, p);
          }
          return p;
        },
      };

      // Track the current step so it can be reconstructed on abort (PR #779):
      // inFlightTools = calls still awaiting a result, completedResults =
      // results already streamed but not yet persisted by onStepFinish. On
      // stream end with calls still in flight, `emitSyntheticToolResults`
      // closes them so no tool-call is ever left without a matching result.
      const inFlightTools = new Map<string, string>();
      const completedResults: ToolResultPart[] = [];
      let streamError: unknown = null;

      try {
        for await (const chunk of this.streamResult.fullStream) {
          switch (chunk.type) {
            case "start-step":
              // New step → new assistant message; reset part tracking. Mirror
              // the id onto the instance so onStepFinish can close it.
              ids.messageId = newMessageId();
              this.currentMessageId = ids.messageId;
              ids.textPartId = undefined;
              toolParts = new Map();
              ids.toolPartId = (toolCallId: string) => {
                let p = toolParts.get(toolCallId);
                if (!p) {
                  p = newPartId();
                  toolParts.set(toolCallId, p);
                }
                return p;
              };
              break;
            case "text-start":
              // Each text run within a step gets its own part id.
              ids.textPartId = newPartId();
              break;
            case "text-end":
              ids.textPartId = undefined;
              break;
            case "tool-call":
              inFlightTools.set(chunk.toolCallId, chunk.toolName);
              break;
            case "tool-result": {
              const tc = chunk as {
                toolCallId: string;
                toolName: string;
                result?: unknown;
                output?: unknown;
              };
              inFlightTools.delete(tc.toolCallId);
              completedResults.push({
                type: "tool-result",
                toolCallId: tc.toolCallId,
                toolName: tc.toolName,
                output: (tc.result ?? tc.output) as ToolResultPart["output"],
              });
              break;
            }
            case "finish-step":
              // onStepFinish has persisted this step; drop its results so a
              // later abort doesn't re-append already-saved tool calls/results.
              completedResults.length = 0;
              break;
          }
          bus.emitStreamPart(chunk, ids);
        }
        // Completed normally — onStepFinish persists everything.
        completedResults.length = 0;
      } catch (err) {
        streamError = err;
      } finally {
        // Dispose first — don't block on persistence I/O.
        this.persistentShell?.dispose();

        if (inFlightTools.size > 0) {
          const reason = this.abortSignal?.aborted
            ? "Agent aborted by user"
            : streamError instanceof Error && streamError.message
              ? streamError.message
              : "Stream terminated unexpectedly";
          try {
            await this.emitSyntheticToolResults(
              inFlightTools,
              completedResults,
              reason,
            );
          } catch {
            // Never mask the original streamError with a listener error.
          }
        }
      }

      if (streamError) {
        throw streamError;
      }

      if (this.abortSignal?.aborted) {
        throw new DOMException("Agent aborted by user", "AbortError");
      }

      if (this.resolveResult) {
        return this.resolveResult(this.streamResult);
      }
      return undefined as TResult;
    };

    // Only subagents get a span here; top-level runs are wrapped by the host.
    const drain = !sid
      ? runConsume()
      : getApexTracer().startActiveSpan(
          `invoke_agent ${sid}`,
          {
            attributes: {
              "gen_ai.operation.name": "invoke_agent",
              "gen_ai.agent.name": sid,
            },
          },
          async (span) => {
            try {
              return await runConsume();
            } catch (err) {
              span.recordException(err as Error);
              throw err;
            } finally {
              span.end();
            }
          },
        );

    // Decouple the result from stream teardown. With a `response` schema the
    // structured result is captured mid-stream (in the response tool), so return
    // it the instant it's available rather than waiting for the stream to close
    // — teardown can wedge (Bedrock goes byte-silent before the final chunk).
    // The drain keeps running in the background for persistence/cleanup, bounded
    // by the transport idle guard so it can't block the caller or leak. Without
    // a response schema `responseCaptured` never fires and this is the same
    // full-drain await as before.
    const result = await Promise.race([drain, this.responseCaptured]);
    drain.catch(() => {});
    return result;
  }

  /**
   * Promise that resolves to the final response metadata once the stream
   * has been fully consumed. Await this *after* iterating the stream.
   */
  get response() {
    return this.streamResult.response;
  }

  private async emitSyntheticToolResults(
    inFlightTools: Map<string, string>,
    completedResults: ToolResultPart[],
    reason: string,
  ): Promise<void> {
    const sid = this.subagentId;
    const output = {
      type: "error-text" as const,
      value: `Tool execution aborted: ${reason}`,
    };
    const syntheticParts: ToolResultPart[] = [];

    for (const [toolCallId, toolName] of inFlightTools) {
      this.eventBus.emit("tool-result", {
        toolCallId,
        toolName,
        result: output,
        // Carry this agent's canonical session id (not just the legacy
        // subagentId alias) so the execution translator routes the synthetic
        // result to THIS subagent's session rather than falling back to root.
        sessionId: this.busSessionId,
        subagentId: sid,
      });
      syntheticParts.push({
        type: "tool-result",
        toolCallId,
        toolName,
        output,
      });
    }

    if (!this.messagesPath) return;

    // Cancel the debounced timer so its writeFile can't race the write below.
    this.cancelPersistTimer?.();

    // latestMessages is null once the debounced timer has flushed; fall back
    // to the on-disk snapshot so we don't overwrite history with synthetics.
    let base: ModelMessage[] = this.latestMessages ?? [];
    if (base.length === 0 && existsSync(this.messagesPath)) {
      try {
        base = JSON.parse(readFileSync(this.messagesPath, "utf-8"));
      } catch {
        // Corrupt file → proceed with empty base.
      }
    }

    // When onStepFinish hasn't fired, this step's assistant + tool messages
    // aren't in base yet; reconstruct it so resumed sessions see valid pairs.
    const allToolCallIds = new Set([
      ...inFlightTools.keys(),
      ...completedResults.map((r) => r.toolCallId),
    ]);
    const lastMsg = base[base.length - 1];
    const needsStepReconstruction =
      !lastMsg ||
      lastMsg.role !== "assistant" ||
      !this.baseContainsToolCalls(lastMsg, allToolCallIds);

    const appended: ModelMessage[] = [];
    if (needsStepReconstruction) {
      const stepTools: Array<[string, string]> = [
        ...inFlightTools,
        ...completedResults.map((r): [string, string] => [
          r.toolCallId,
          r.toolName,
        ]),
      ];
      const toolCalls: ToolCallPart[] = stepTools.map(
        ([toolCallId, toolName]) => ({
          type: "tool-call" as const,
          toolCallId,
          toolName,
          input: {},
        }),
      );
      appended.push({ role: "assistant", content: toolCalls });
    }
    appended.push({
      role: "tool",
      content: [...completedResults, ...syntheticParts],
    });

    const next: ModelMessage[] = [...base, ...appended];
    this.latestMessages = next;
    try {
      await writeFile(this.messagesPath, JSON.stringify(next));
      // Only suppress onFinish's write once the snapshot is safely on disk.
      this.syntheticsPersisted = true;
    } catch {
      // Write failed — leave the flag false so onFinish still attempts a write.
    }
  }

  private baseContainsToolCalls(
    msg: ModelMessage,
    toolCallIds: Set<string>,
  ): boolean {
    if (!Array.isArray(msg.content)) return false;
    const contentToolIds = new Set(
      (msg.content as Array<{ type: string; toolCallId?: string }>)
        .filter((p) => p.type === "tool-call" && p.toolCallId)
        .map((p) => p.toolCallId),
    );
    return [...toolCallIds].every((id) => contentToolIds.has(id));
  }
}

// These tools pause the agent and surface their own UI to the operator.
// Gating them through the approval gate would double-prompt.
const AGENT_PAUSE_TOOLS = new Set<string>([ASK_USER_QUESTIONS_TOOL_NAME]);

function wrapToolsWithApprovalGate(
  tools: ToolSet,
  gate: ApprovalGate,
  exemptToolNames?: Set<string>,
): ToolSet {
  const wrapped: ToolSet = {};

  for (const [name, coreTool] of Object.entries(tools)) {
    if (exemptToolNames?.has(name)) {
      wrapped[name] = coreTool;
      continue;
    }

    // biome-ignore lint/suspicious/noExplicitAny: ai-sdk CoreTool is a discriminated union that requires runtime narrowing for the approval gate wrapper.
    const t = coreTool as any;

    if (!t.execute) {
      wrapped[name] = coreTool;
      continue;
    }

    const originalExecute = t.execute;

    wrapped[name] = {
      ...t,
      // biome-ignore lint/suspicious/noExplicitAny: ai-sdk tool execute receives an opaque ExecuteContext we don't need to narrow.
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
