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
import { AgentEventBus } from "../../eventBus";
import {
  resolveEffectiveHeaders,
  stripBrowserManagedHeaders,
} from "../../http/targetHeaders";
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

  /** Identifier for this agent when it is running as a subagent. */
  private readonly subagentId?: string;

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

  /** Shared with stream callbacks so consume() can read messages on abort. */
  private latestMessages: ModelMessage[] | null = null;

  private messagesPath: string | null = null;

  private cancelPersistTimer: (() => void) | null = null;

  /** Set after emitSyntheticToolResults writes successfully; gates onFinish write. */
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
          });
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
      const inFlightTools = new Map<string, string>();
      const completedResults: ToolResultPart[] = [];
      let streamError: unknown = null;

      try {
        for await (const chunk of this.streamResult.fullStream) {
          if (chunk.type === "tool-input-start") {
            // Track from the start so a truncated call (started, args never
            // completed) still gets closed and isn't left "running".
            inFlightTools.set(chunk.id, chunk.toolName);
          } else if (chunk.type === "tool-call") {
            inFlightTools.set(chunk.toolCallId, chunk.toolName);
          } else if (chunk.type === "tool-result") {
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
          } else if (chunk.type === "finish-step") {
            // Close any call that started this step but produced no result
            // (truncated args) so it doesn't render stuck "running".
            for (const [toolCallId, toolName] of inFlightTools) {
              bus.emit("tool-result", {
                toolCallId,
                toolName,
                result: {
                  type: "error-text",
                  value: "Tool call did not complete",
                },
                subagentId: sid,
              });
            }
            inFlightTools.clear();
          }
          bus.emitStreamPart(chunk, sid);
        }
        // Stream completed normally — onStepFinish persists everything.
        completedResults.length = 0;
      } catch (err) {
        streamError = err;
      } finally {
        this.persistentShell?.dispose();

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
            );
          } catch {
            // Swallow — never mask the original streamError with a listener error.
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
    if (!sid) return runConsume();

    const tracer = getApexTracer();
    return tracer.startActiveSpan(
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

    this.cancelPersistTimer?.();

    let base: ModelMessage[] = this.latestMessages ?? [];
    if (base.length === 0 && existsSync(this.messagesPath)) {
      try {
        base = JSON.parse(readFileSync(this.messagesPath, "utf-8"));
      } catch {
        // Best-effort: corrupt file → proceed with empty base.
      }
    }

    // If onStepFinish never fired for the current step, reconstruct the
    // assistant tool-call message so resumed sessions have valid pairs.
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
      const toolCalls: ToolCallPart[] = [
        ...[...inFlightTools.entries()].map(([toolCallId, toolName]) => ({
          type: "tool-call" as const,
          toolCallId,
          toolName,
          input: {},
        })),
        ...completedResults.map((r) => ({
          type: "tool-call" as const,
          toolCallId: r.toolCallId,
          toolName: r.toolName,
          input: {},
        })),
      ];
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
      this.syntheticsPersisted = true;
    } catch {
      // Write failed — leave syntheticsPersisted false so onFinish can retry.
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
    for (const toolCallId of toolCallIds) {
      if (!contentToolIds.has(toolCallId)) return false;
    }
    return true;
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
