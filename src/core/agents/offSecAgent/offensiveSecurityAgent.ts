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
import { createLogger } from "../../logger/structured";
import { getApexTracer, withSubagentSessionBaggage } from "../../observability";
import type { ApprovalGate } from "../../operator";
import { ApprovalDeniedError } from "../../operator";
import { create as createSession, type SessionInfo } from "../../session";
import { scopedLogger } from "../../util/lazyLogger";
import { detectOSAndEnhancePrompt } from "../specialized/utils";
import { buildBaseSystemPrompt, buildSessionWorkspaceSection } from "./prompt";
import {
  ASK_USER_QUESTIONS_TOOL_NAME,
  createAllTools,
  createResponseTool,
  EMAIL_TOOL_NAMES_ACTIVE,
  FAST_STRIKE_EXCLUDED_TOOL_NAMES,
  PersistentShell,
  PLAN_MODE_TOOL_NAMES,
  PlaywrightMcpSession,
  RESPONSE_TOOL_NAME,
  SEND_EMAIL_TOOL_NAME,
} from "./tools";
import { StepTraceWriter } from "./trace";
import type { CreateAgentInput, OffensiveSecurityAgentInput } from "./types";

const log = scopedLogger(() => createLogger("approval-gate"));

// Opt-in `response` tool lifecycle tracer (RESPONSE_DEBUG=1) for the empty-`{}` / "Tool call did not complete" loop on threat-model sub-agents.
const RESPONSE_DEBUG =
  process.env.RESPONSE_DEBUG === "1" || process.env.RESPONSE_DEBUG === "true";
const rlog = scopedLogger(() => createLogger("response-debug"));

// Opt-in stall watchdog (STREAM_STALL_DEBUG=1): warns when fullStream goes byte-silent, catching a Bedrock wedge.
const STREAM_STALL_DEBUG =
  process.env.STREAM_STALL_DEBUG === "1" ||
  process.env.STREAM_STALL_DEBUG === "true";
const STREAM_STALL_TICK_MS = 15_000;
const STREAM_STALL_WARN_MS = 20_000;
const STREAM_GAP_RECOVERED_MS = 10_000;

function responseArgBytes(input: unknown): number {
  if (input == null) return 0;
  if (typeof input === "string") return input.length;
  try {
    return JSON.stringify(input).length;
  } catch {
    return -1;
  }
}

/**
 * General-purpose offensive security agent harness.
 *
 * The agent **owns tool creation** — all available tools are built from
 * the session context, and specific agents select which ones to activate
 * via the `activeTools` array (passed through to the AI SDK).
 *
 * The stream is created lazily on first consumption (see {@link streamResult}),
 * so the AI SDK telemetry nests under this agent's span — no separate `.run()`.
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
  /** Cached stream result, populated on first {@link streamResult} access. */
  private _streamResult: StreamTextResult<ToolSet, never> | null = null;

  /** Builds the underlying stream; invoked lazily by {@link streamResult}. */
  private readonly createStream: () => StreamTextResult<ToolSet, never>;

  /** The event bus for this agent's streaming output. */
  public readonly eventBus: AgentEventBus;

  private readonly resolveResult?: (
    streamResult: StreamTextResult<ToolSet, never>,
  ) => TResult | Promise<TResult>;

  /** The structured result captured by the `response` tool, or `null` until it fires. */
  private _capturedResponse: TResult | null = null;

  /** Set synchronously when `response` fires, ahead of any async `resolveResult`, to distinguish a clean finish from an abort. */
  private _responseToolFired = false;

  /** Resolves the instant `response` captures the result, so {@link consume} can return early and drain in the background. */
  private _resolveResponseCaptured!: (result: TResult) => void;
  private _rejectResponseCaptured!: (err: unknown) => void;
  public readonly responseCaptured: Promise<TResult> = new Promise(
    (resolve, reject) => {
      this._resolveResponseCaptured = resolve;
      this._rejectResponseCaptured = reject;
    },
  );

  /** Rejects when the background drain errors, so a custom resolver racing `streamResult.response` isn't blocked by a wedged stream. */
  private _drainRejection: Promise<never> = new Promise<never>(() => {});

  /** Settles when the background drain (including its synthetic-close finally) has fully finished. */
  public drained: Promise<void> = Promise.resolve();

  /** Identifier for this agent when it is running as a subagent. */
  private readonly subagentId?: string;

  /**
   * Human-readable label for this subagent (e.g. "Attack Surface",
   * "Threat Model: /api/users"). Since {@link subagentId} is now an opaque
   * `ses_` execution-session id, this carries the display slug that was
   * previously the id. Used only for the OTel span name / `gen_ai.agent.name`
   * so Sentry traces stay readable; the id remains the join key.
   */
  private readonly subagentName?: string;

  /** The current open assistant message id (`msg_…`); minted on `start-step` in {@link consume}, `null` between steps. */
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

  /**
   * True when this agent constructed its own {@link browserSession} (no
   * `browserSession` was passed in). Only the owner disconnects it on
   * `consume()` completion — an inherited session is torn down by whoever
   * created it (e.g. `spawn_pentest_agent` for worker clones), so we must
   * never disconnect a session we don't own.
   */
  private readonly ownsBrowserSession: boolean;

  /** Guards against double force-kill across the drain-finally and result-capture paths. */
  private browserDisconnected = false;

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

  /** This agent's identity on the event bus (subagent's session id, or the root session's id). */
  private get busSessionId(): string {
    return this.subagentId ?? this._session.id;
  }

  constructor(input: OffensiveSecurityAgentInput<TResult>) {
    this._session = input.session;
    this.subagentId = input.subagentId;
    this.subagentName = input.subagentName;
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
      this.ownsBrowserSession = !input.browserSession;
      this.browserSession =
        input.browserSession ??
        new PlaywrightMcpSession({
          extraHttpHeaders: stripBrowserManagedHeaders(sessionHeaders),
          display: input.display,
        });
    } else {
      this.ownsBrowserSession = false;
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
      promptInjectionLibrary: input.promptInjectionLibrary,
      promptInjectionLibrarySource:
        input.promptInjectionLibrarySource ??
        input.session.config?.promptInjectionLibrarySource,
      traceWriter,
      tasksDir,
      enableThinking: input.enableThinking,
      thinkingEffort: input.thinkingEffort,
      openAIReasoningEffort: input.openAIReasoningEffort,
      surfaceIntegrationEnabled: input.surfaceIntegrationEnabled,
      projectThreatModel: input.projectThreatModel,
      planSubagentId: input.planSubagentId,
      subagentId: input.subagentId,
      browserSession: this.browserSession,
      // Propagate this agent's display so spawned workers run on the SAME
      // virtual desktop (their browsers belong to the same endpoint's stream),
      // rather than falling back to the process-wide DISPLAY (:0).
      display: input.display,
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
            this._responseToolFired = true;
            if (RESPONSE_DEBUG) {
              rlog.warn(
                `[response-debug] response tool EXECUTED (captured) session=${this.busSessionId} ` +
                  `resultBytes=${responseArgBytes(result)} — happy path`,
              );
            }
            // With a custom resolveResult (e.g. TargetedPentestAgent), the raw schema result must be funnelled through it before fulfilling consume()'s race.
            const customResolve = input.resolveResult;
            if (customResolve) {
              void Promise.resolve()
                .then(() => {
                  // Race .response against _drainRejection so a wedged stream can't hang a resolver awaiting it.
                  const sr = this.streamResult;
                  const guarded = Object.create(sr, {
                    response: {
                      get: () =>
                        Promise.race([sr.response, this._drainRejection]),
                    },
                  });
                  return customResolve(guarded);
                })
                .then((resolved) => {
                  this._capturedResponse = resolved;
                  this._resolveResponseCaptured(resolved);
                })
                .catch((err) => {
                  this._rejectResponseCaptured(err);
                });
              return;
            }
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
    } else if (input.mode === "fast-strike") {
      // Registry minus orchestration tools; email gating matches default mode.
      const excluded = new Set<string>(FAST_STRIKE_EXCLUDED_TOOL_NAMES);
      activeTools = Object.keys(tools).filter((t) => {
        if (excluded.has(t)) return false;
        if (!emailToolSet.has(t)) return true;
        if (t === SEND_EMAIL_TOOL_NAME) return hasSmtp;
        return hasEmail;
      });
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

    // Deferred so the AI SDK telemetry binds to this agent's span (entered in
    // consume()) rather than the construction-time context. See `streamResult`.
    this.createStream = () =>
      streamResponse({
        prompt: input.prompt,
        system: systemPrompt,
        model: input.model,
        messages: input.messages,
        tools,
        activeTools,
        stopWhen,
        toolChoice: "auto",
        // Per-subagent so the overflow tool-result dumps land next to this
        // agent's messages.json (`subagents/{id}/tool-results/`) and a host
        // can reclaim them when the subagent finishes, instead of piling up
        // at the shared session root for the whole scan (ENOSPC). Falls back
        // to the session root for the root/operator agent.
        sessionPath: messagesDir,
        sessionId: this.busSessionId,
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
        thinkingEffort: input.thinkingEffort,
        openAIReasoningEffort: input.openAIReasoningEffort,
        silent: true,
      });
  }

  // ---------------------------------------------------------------------------
  // Stream access
  // ---------------------------------------------------------------------------

  /**
   * The underlying Vercel AI SDK stream result — escape hatch for advanced use.
   * Created lazily so its telemetry binds to the span active at first
   * consumption (this agent's `invoke_agent` span), not the construction context.
   */
  get streamResult(): StreamTextResult<ToolSet, never> {
    if (this._streamResult === null) {
      this._streamResult = this.createStream();
    }
    return this._streamResult;
  }

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
      // Tool-call part ids are minted once and reused for the WHOLE session, never reset per step.
      const toolParts = new Map<string, string>();
      const ids: StreamIdContext = {
        // The TUI routes any event with a subagentId into a subagent panel, so
        // the orchestrator must leave it undefined; only real subagents set it.
        subagentId: this.subagentId,
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

      // inFlightTools = calls awaiting a result; completedResults = streamed but not yet persisted by onStepFinish (PR #779).
      const inFlightTools = new Map<string, string>();
      const completedResults: ToolResultPart[] = [];
      let streamError: unknown = null;

      const responseArgChars = new Map<string, number>();
      const responseSawTerminal = new Map<string, string>();

      // Raw streamed arg text per tool-call id, kept so a `tool-error` can persist the real (possibly truncated) payload instead of `{}`.
      const streamedArgText = new Map<string, string>();
      // Tool errors observed mid-stream, surfaced at finish-step (where finishReason is known) instead of a generic "did not complete".
      const toolErrors = new Map<
        string,
        { message: string; input: unknown; toolName: string }
      >();

      let lastChunkAt = Date.now();
      let lastChunkType = "none";
      let stallStepIndex = -1;
      let stallTimer: ReturnType<typeof setInterval> | undefined;
      if (STREAM_STALL_DEBUG) {
        const label = this._session.id;
        stallTimer = setInterval(() => {
          const gap = Date.now() - lastChunkAt;
          if (gap > STREAM_STALL_WARN_MS) {
            rlog.warn(
              `[stream-stall] no chunk for ${Math.round(gap / 1000)}s ` +
                `session=${label} subagent=${sid ?? "-"} step=${stallStepIndex} ` +
                `lastChunkType=${lastChunkType} ` +
                `inFlightTools=${[...inFlightTools.values()].join(",")} ` +
                `responseToolFired=${this._responseToolFired}`,
            );
          }
        }, STREAM_STALL_TICK_MS);
      }

      try {
        for await (const chunk of this.streamResult.fullStream) {
          if (STREAM_STALL_DEBUG) {
            const now = Date.now();
            const gap = now - lastChunkAt;
            lastChunkAt = now;
            lastChunkType = chunk.type;
            if (chunk.type === "start-step") stallStepIndex++;
            if (gap > STREAM_GAP_RECOVERED_MS) {
              rlog.warn(
                `[stream-gap] recovered after ${Math.round(gap / 1000)}s ` +
                  `session=${this._session.id} chunkType=${chunk.type}`,
              );
            }
          }
          if (RESPONSE_DEBUG) {
            const c = chunk as {
              type: string;
              id?: string;
              toolCallId?: string;
              toolName?: string;
              delta?: string;
              input?: unknown;
              args?: unknown;
              error?: unknown;
            };
            const idForChunk = c.toolCallId ?? c.id;
            const nameForChunk =
              c.toolName ??
              (idForChunk ? inFlightTools.get(idForChunk) : undefined);
            if (nameForChunk === RESPONSE_TOOL_NAME && idForChunk) {
              if (chunk.type === "tool-input-start") {
                responseArgChars.set(idForChunk, 0);
                rlog.warn(
                  `[response-debug] tool-input-start id=${idForChunk} session=${this.busSessionId}`,
                );
              } else if (chunk.type === "tool-input-delta") {
                responseArgChars.set(
                  idForChunk,
                  (responseArgChars.get(idForChunk) ?? 0) +
                    (c.delta?.length ?? 0),
                );
              } else if (chunk.type === "tool-input-end") {
                rlog.warn(
                  `[response-debug] tool-input-end id=${idForChunk} argChars=${responseArgChars.get(idForChunk) ?? 0}`,
                );
              } else if (chunk.type === "tool-call") {
                responseSawTerminal.set(idForChunk, "tool-call");
                const inputBytes = responseArgBytes(c.input ?? c.args);
                const invalid = (c as { invalid?: boolean }).invalid === true;
                rlog.warn(
                  `[response-debug] tool-call id=${idForChunk} streamedArgChars=${responseArgChars.get(idForChunk) ?? 0} parsedInputBytes=${inputBytes} invalid=${invalid}`,
                );
              } else if (chunk.type === "tool-error") {
                responseSawTerminal.set(idForChunk, "tool-error");
                const errMsg =
                  c.error instanceof Error
                    ? c.error.message
                    : typeof c.error === "string"
                      ? c.error
                      : JSON.stringify(c.error)?.slice(0, 300);
                rlog.warn(
                  `[response-debug] tool-error id=${idForChunk} streamedArgChars=${responseArgChars.get(idForChunk) ?? 0} stillInFlight=${inFlightTools.has(idForChunk)} error=${errMsg}`,
                );
              } else if (chunk.type === "tool-result") {
                responseSawTerminal.set(idForChunk, "tool-result");
                rlog.warn(
                  `[response-debug] tool-result id=${idForChunk} streamedArgChars=${responseArgChars.get(idForChunk) ?? 0}`,
                );
              } else if (chunk.type === "finish-step") {
                const fr = (c as { finishReason?: string }).finishReason;
                rlog.warn(
                  `[response-debug] finish-step finishReason=${fr} responseInFlight=${[
                    ...inFlightTools.entries(),
                  ]
                    .filter(([, n]) => n === RESPONSE_TOOL_NAME)
                    .map(([id]) => id)
                    .join(",")} responseToolFired=${this._responseToolFired}`,
                );
              }
            }
          }
          switch (chunk.type) {
            case "start-step":
              ids.messageId = newMessageId();
              this.currentMessageId = ids.messageId;
              ids.textPartId = undefined;
              break;
            case "text-start":
              ids.textPartId = newPartId();
              break;
            case "text-end":
              ids.textPartId = undefined;
              break;
            case "tool-input-start":
              // Track from the start so a truncated call still gets closed instead of left "running".
              inFlightTools.set(chunk.id, chunk.toolName);
              streamedArgText.set(chunk.id, "");
              break;
            case "tool-input-delta": {
              const d = chunk as { id: string; delta?: string };
              streamedArgText.set(
                d.id,
                (streamedArgText.get(d.id) ?? "") + (d.delta ?? ""),
              );
              break;
            }
            case "tool-call":
              inFlightTools.set(chunk.toolCallId, chunk.toolName);
              break;
            case "tool-error": {
              // `execute` never runs for an errored call, so it must be cleared here or finish-step would fabricate a bogus "did not complete".
              const te = chunk as {
                toolCallId: string;
                toolName: string;
                input?: unknown;
                error?: unknown;
              };
              inFlightTools.delete(te.toolCallId);
              const errMsg =
                te.error instanceof Error
                  ? te.error.message
                  : typeof te.error === "string"
                    ? te.error
                    : (() => {
                        try {
                          return JSON.stringify(te.error);
                        } catch {
                          return String(te.error);
                        }
                      })();
              const partialArgs =
                te.input !== undefined &&
                te.input !== null &&
                responseArgBytes(te.input) > 2
                  ? te.input
                  : (streamedArgText.get(te.toolCallId) ?? "");
              toolErrors.set(te.toolCallId, {
                message: errMsg,
                input: partialArgs,
                toolName: te.toolName,
              });
              break;
            }
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
            case "finish-step": {
              // onStepFinish has persisted this step; drop its results so a later abort doesn't re-append them.
              completedResults.length = 0;
              const finishReason = (chunk as { finishReason?: string })
                .finishReason;
              const truncated = finishReason === "length";

              for (const [toolCallId, info] of toolErrors) {
                if (RESPONSE_DEBUG && info.toolName === RESPONSE_TOOL_NAME) {
                  rlog.warn(
                    `[response-debug] tool-error SURFACED id=${toolCallId} ` +
                      `streamedArgChars=${(streamedArgText.get(toolCallId) ?? "").length} ` +
                      `finishReason=${finishReason ?? "unknown"} ` +
                      `outputTokenTruncated=${truncated} error=${info.message.slice(0, 300)}`,
                  );
                }
                bus.emit("tool-result", {
                  toolCallId,
                  toolName: info.toolName,
                  result: {
                    type: "error-text",
                    value: truncated
                      ? `Tool call failed: the model's output was truncated at its max output tokens before the "${info.toolName}" arguments were complete. ${info.message}`
                      : `Tool call failed: ${info.message}`,
                  },
                  sessionId: this.busSessionId,
                  subagentId: sid,
                  partId: ids.toolPartId?.(toolCallId),
                  messageId: ids.messageId,
                });
              }
              toolErrors.clear();

              // Close any call still in flight (args never finalized) so it doesn't render stuck "running".
              for (const [toolCallId, toolName] of inFlightTools) {
                if (RESPONSE_DEBUG && toolName === RESPONSE_TOOL_NAME) {
                  rlog.warn(
                    `[response-debug] CLOSING response as "did not complete" id=${toolCallId} ` +
                      `streamedArgChars=${responseArgChars.get(toolCallId) ?? 0} ` +
                      `sawTerminalChunk=${responseSawTerminal.get(toolCallId) ?? "none"} ` +
                      `finishReason=${finishReason ?? "unknown"} outputTokenTruncated=${truncated} ` +
                      `responseToolFired=${this._responseToolFired}`,
                  );
                }
                // Already-fired response: mark submitted, not "did not complete".
                const result =
                  toolName === RESPONSE_TOOL_NAME && this._responseToolFired
                    ? { type: "text" as const, value: "Response submitted." }
                    : {
                        type: "error-text" as const,
                        value: truncated
                          ? "Tool call did not complete: the model's output was truncated at its max output tokens before the arguments were finalized."
                          : "Tool call did not complete",
                      };
                bus.emit("tool-result", {
                  toolCallId,
                  toolName,
                  result,
                  sessionId: this.busSessionId,
                  subagentId: sid,
                  partId: ids.toolPartId?.(toolCallId),
                  messageId: ids.messageId,
                });
              }
              inFlightTools.clear();
              break;
            }
          }
          bus.emitStreamPart(chunk, ids);
        }
        // Keep completedResults: an abort with no trailing finish-step needs them for the finally snapshot.
      } catch (err) {
        streamError = err;
      } finally {
        // Stop the stall watchdog so it never leaks past stream end / throw.
        if (stallTimer) clearInterval(stallTimer);
        // Dispose first — don't block on persistence I/O.
        this.persistentShell?.dispose();
        // Flush tool-errors that never reached a finish-step into the snapshot.
        for (const [toolCallId, info] of toolErrors) {
          const result = {
            type: "error-text" as const,
            value: `Tool call failed: ${info.message}`,
          };
          bus.emit("tool-result", {
            toolCallId,
            toolName: info.toolName,
            result,
            sessionId: this.busSessionId,
            subagentId: sid,
            partId: ids.toolPartId?.(toolCallId),
            messageId: ids.messageId,
          });
          completedResults.push({
            type: "tool-result",
            toolCallId,
            toolName: info.toolName,
            output: result,
          });
        }
        toolErrors.clear();
        // Snapshot unpersisted step state: open tools get synthetic closes, completed/errored results get written.
        if (inFlightTools.size > 0 || completedResults.length > 0) {
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
              ids.toolPartId,
              ids.messageId,
              streamedArgText,
            );
          } catch {
            // Never mask the original streamError with a listener error.
          }
        }
        // Tear down the Chromium child process we own. Without this, a
        // naturally-finishing agent leaks its Playwright MCP browser — over a
        // long single-process scan (many endpoints) the leaked Chromium
        // processes exhaust memory and OOM the run. disconnect() force-kills
        // and never hangs, so awaiting here is safe.
        await this.disconnectOwnedBrowser();
      }

      if (streamError) {
        throw streamError;
      }

      if (this.abortSignal?.aborted) {
        throw new DOMException("Agent aborted by user", "AbortError");
      }

      if (this.resolveResult) {
        if (this._responseToolFired) {
          return undefined as TResult;
        }
        return this.resolveResult(this.streamResult);
      }
      return undefined as TResult;
    };

    // Only subagents get a span here; top-level runs are wrapped by the host.
    // Span display uses the human label (subagentName) so Sentry traces stay
    // readable now that `subagentId` is an opaque `ses_` id; the id remains the
    // baggage join key.
    const spanLabel = this.subagentName ?? sid;
    const drain = !sid
      ? runConsume()
      : withSubagentSessionBaggage(sid, () =>
          getApexTracer().startActiveSpan(
            `invoke_agent ${spanLabel}`,
            {
              attributes: {
                "gen_ai.operation.name": "invoke_agent",
                "gen_ai.agent.name": spanLabel,
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
          ),
        );

    // Decouple the result from stream teardown: with a `response` schema, return as soon as it's captured rather than waiting for the stream to close (which can wedge).
    let rejectDrain: ((err: unknown) => void) | undefined;
    this._drainRejection = new Promise<never>((_, reject) => {
      rejectDrain = reject;
    });
    this._drainRejection.catch(() => {});

    // Lets a caller that aborts after capturing the result await the drain's finally (in-flight tool closes) before completing.
    this.drained = drain.then(
      () => {},
      () => {},
    );

    // Don't let drain's settle (reject OR resolve) mask an already-captured
    // response; unblock the resolver's streamResult.response wait either way.
    const guardedDrain = drain
      .then((result) => {
        if (this._responseToolFired) {
          rejectDrain?.(new Error("drain resolved"));
          return this.responseCaptured;
        }
        return result;
      })
      .catch((err) => {
        rejectDrain?.(err);
        if (!this._responseToolFired) throw err;
        return this.responseCaptured;
      });
    guardedDrain.catch(() => {});

    const result = await Promise.race([guardedDrain, this.responseCaptured]);
    // Free the browser on result capture; the drain can wedge and leak camoufox.
    await this.disconnectOwnedBrowser();
    return result;
  }

  /** Force-kills the owned Chromium child process exactly once; safe to call from multiple teardown paths. */
  private async disconnectOwnedBrowser(): Promise<void> {
    if (this.browserDisconnected) return;
    if (!this.ownsBrowserSession || !this.browserSession) return;
    this.browserDisconnected = true;
    await this.browserSession.disconnect().catch(() => {});
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
    partIdFor?: (toolCallId: string) => string,
    messageId?: string,
    streamedArgText?: Map<string, string>,
  ): Promise<void> {
    const sid = this.subagentId;
    const output = {
      type: "error-text" as const,
      value: `Tool execution aborted: ${reason}`,
    };
    const syntheticParts: ToolResultPart[] = [];

    if (RESPONSE_DEBUG) {
      const responseInFlight = [...inFlightTools.entries()].filter(
        ([, n]) => n === RESPONSE_TOOL_NAME,
      );
      if (responseInFlight.length > 0) {
        rlog.warn(
          `[response-debug] emitSyntheticToolResults closing ${responseInFlight.length} response call(s) ` +
            `ids=${responseInFlight.map(([id]) => id).join(",")} reason="${reason}" ` +
            `aborted=${this.abortSignal?.aborted === true} responseToolFired=${this._responseToolFired}`,
        );
      }
    }

    for (const [toolCallId, toolName] of inFlightTools) {
      // The `response` tool reaching here after a successful capture didn't fail — mark it completed, not aborted.
      const result =
        toolName === RESPONSE_TOOL_NAME && this._responseToolFired
          ? { type: "text" as const, value: "Response submitted." }
          : output;
      this.eventBus.emit("tool-result", {
        toolCallId,
        toolName,
        result,
        // Canonical session id, not just the legacy subagentId alias, so the translator routes to THIS subagent's session.
        sessionId: this.busSessionId,
        subagentId: sid,
        partId: partIdFor?.(toolCallId),
        messageId,
      });
      syntheticParts.push({
        type: "tool-result",
        toolCallId,
        toolName,
        output: result,
      });
    }

    if (!this.messagesPath) return;

    // Cancel the debounced timer so its writeFile can't race the write below.
    this.cancelPersistTimer?.();

    // Fall back to the on-disk snapshot once the debounced timer has flushed latestMessages, so we don't overwrite history.
    let base: ModelMessage[] = this.latestMessages ?? [];
    if (base.length === 0 && existsSync(this.messagesPath)) {
      try {
        base = JSON.parse(readFileSync(this.messagesPath, "utf-8"));
      } catch {
        // Corrupt file → proceed with empty base.
      }
    }

    // When onStepFinish hasn't fired, this step's messages aren't in base yet; reconstruct so resumed sessions see valid pairs.
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
      // Preserve whatever args the model actually streamed instead of writing an empty `{}`.
      const reconstructInput = (toolCallId: string): unknown => {
        const raw = streamedArgText?.get(toolCallId);
        if (!raw) return {};
        try {
          return JSON.parse(raw);
        } catch {
          return { _partial: raw };
        }
      };
      if (RESPONSE_DEBUG) {
        const responseReconstructed = stepTools
          .filter(([, n]) => n === RESPONSE_TOOL_NAME)
          .map(([id]) => id);
        if (responseReconstructed.length > 0) {
          rlog.warn(
            `[response-debug] step-reconstruction for response call(s) ` +
              `ids=${responseReconstructed.join(",")} ` +
              `preservedArgChars=${responseReconstructed
                .map((id) => streamedArgText?.get(id)?.length ?? 0)
                .join(",")}`,
          );
        }
      }
      const toolCalls: ToolCallPart[] = stepTools.map(
        ([toolCallId, toolName]) => ({
          type: "tool-call" as const,
          toolCallId,
          toolName,
          input: reconstructInput(toolCallId),
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

        log.debug(`${name} (${toolCallId}): checking`);
        try {
          await gate.check(name, String(toolCallId), args);
        } catch (err) {
          if (err instanceof ApprovalDeniedError) {
            log.debug(`${name} (${toolCallId}): denied`);
            return { blocked: true, reason: "Denied by operator" };
          }
          throw err;
        }
        log.debug(`${name} (${toolCallId}): approved, executing`);

        const result = await originalExecute(args, options);
        log.debug(`${name} (${toolCallId}): execute finished`);
        return result;
      },
    };
  }

  return wrapped;
}
