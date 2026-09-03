import { existsSync, mkdirSync } from "node:fs";
import { join } from "node:path";
import { SpanStatusCode } from "@opentelemetry/api";
import type {
  ModelMessage,
  StopCondition,
  StreamTextResult,
  TextStreamPart,
  ToolSet,
} from "ai";
import { hasToolCall } from "ai";
import { streamResponse } from "../../ai";
import { AgentEventBus, type StreamIdContext } from "../../eventBus";
import {
  resolveEffectiveHeaders,
  stripBrowserManagedHeaders,
} from "../../http/targetHeaders";
import { newMessageId, newPartId, newRunId } from "../../id/id";
import { createLogger } from "../../logger/structured";
import {
  getApexTracer,
  registerActiveRootSpan,
  unregisterActiveRootSpan,
  withSubagentSessionBaggage,
} from "../../observability";
import type { ApprovalGate } from "../../operator";
import { ApprovalDeniedError } from "../../operator";
import { create as createSession, type SessionInfo } from "../../session";
import { scopedLogger } from "../../util/lazyLogger";
import { detectOSAndEnhancePrompt } from "../specialized/utils";
import {
  createInterruptedStepFinalizer,
  type FinalizeInterruptedStepInput,
} from "./interruptedStepFinalization";
import { AgentMessageWriter } from "./messagePersistence";
import { buildBaseSystemPrompt, buildSessionWorkspaceSection } from "./prompt";
import { responseArgBytes, StreamDiagnostics } from "./streamDiagnostics";
import { inProcessSubagentSpawner } from "./subagentSpawner";
import { ToolLifecycleTracker } from "./toolLifecycle";
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
  SMS_TOOL_NAMES_ACTIVE,
  sessionHasSmsPasswordless,
  WORKSPACE_TOOL_NAMES,
  WORKSPACE_WRITE_TOOL_NAMES,
} from "./tools";
import { StepTraceWriter } from "./trace";
import type {
  AgentMode,
  CreateAgentInput,
  OffensiveSecurityAgentInput,
  StreamIdFactory,
} from "./types";

const log = scopedLogger(() => createLogger("approval-gate"));

// Opt-in `response` tool lifecycle tracer (RESPONSE_DEBUG=1) for the empty-`{}` / "Tool call did not complete" loop on threat-model sub-agents.
const RESPONSE_DEBUG =
  process.env.RESPONSE_DEBUG === "1" || process.env.RESPONSE_DEBUG === "true";
const rlog = scopedLogger(() => createLogger("response-debug"));

const WORKSPACE_TOOL_NAME_SET = new Set<string>(WORKSPACE_TOOL_NAMES);
const WORKSPACE_WRITE_TOOL_NAME_SET = new Set<string>(
  WORKSPACE_WRITE_TOOL_NAMES,
);

const WORKSPACE_TARGET_RE = /\b(?:console|workspace)\b/i;
const WORKSPACE_NOUN_RE =
  /\b(?:domains?|apps?|applications?|endpoints?|threat\s+models?|attack\s+surfaces?)\b/i;
const WORKSPACE_READ_REQUEST_RE =
  /(?:\b(?:list|show|find|search|get)\s+(?:(?:me|a|an|the|my|our|all|any|list|of|for|in|within|registered|existing|available|console|workspace|which)\s+){0,8}(?:domains?|apps?|applications?|endpoints?)\b|\b(?:what|which)\s+(?:(?:of|a|an|the|my|our|all|any|are|is|do|does|we|i|have|has|there|registered|existing|available|console|workspace)\s+){0,8}(?:domains?|apps?|applications?|endpoints?)\b)/i;
const WORKSPACE_WRITE_ACTION = String.raw`(?:add|create|register|import|update|edit|change|set|correct|repair|link|unlink|rename|break\s+down)`;
const WORKSPACE_EXPLICIT_WRITE_REQUEST_RE = new RegExp(
  String.raw`(?:^\s*|[.?!;\n]\s*|\b(?:please|kindly)\s+|\b(?:can|could|would|will)\s+you\s+|\b(?:i|we)\s+(?:want|need)\s+(?:you\s+)?to\s+|\bi(?:['’]d| would)\s+like\s+(?:you\s+)?to\s+|\blet['’]s\s+|\bgo\s+ahead\s+and\s+)${WORKSPACE_WRITE_ACTION}\b`,
  "i",
);
const WORKSPACE_NEGATED_WRITE_REQUEST_RE = new RegExp(
  String.raw`\b(?:do\s+not|don't|never|avoid)\b[^.?!;\n]{0,40}\b${WORKSPACE_WRITE_ACTION}\b`,
  "i",
);
const WORKSPACE_CLAUSE_BOUNDARY_RE = new RegExp(
  String.raw`(?:[.!?;]+(?=\s|$)\s*|\n+|\s+(?:but|however)\s+|\s+and\s+(?=(?:(?:do\s+not|don't|never|avoid)\s+)?${WORKSPACE_WRITE_ACTION}\b))`,
  "i",
);
// Sentence delimiters only (never splits `example.com`), so a leading
// capability question can be scoped to the whole sentence before the
// clause-level `and`/`but` split runs.
const WORKSPACE_SENTENCE_BOUNDARY_RE = /(?:[.!?;]+(?=\s|$)\s*|\n+)/;
// Capability/permission questions ("Can I … and create …", "How do I …")
// stay read-only: the interrogative governs every coordinated clause, so the
// clause split must not let a trailing bare write verb pass as an imperative.
// Requests aimed at the agent ("Can you …", "Please …", "I'd like to …") are
// not questions and are handled by WORKSPACE_EXPLICIT_WRITE_REQUEST_RE.
const WORKSPACE_CAPABILITY_QUESTION_RE =
  /^\s*(?:(?:so|and|also|then|ok|okay|well|hey|hi|actually|but)[,\s]+)*(?:is\s+it\s+possible\b|what\s+if\b|how\s+(?:do|can|could|should|would|shall|might)\s+(?:i|we)\b|(?:can|could|should|would|may|will|do|does|did|am|are|is|shall|have|has)\s+(?:i|we)\b)/i;
const WORKSPACE_CREATE_REQUEST_RE =
  /\b(?:add|create|register|import)\s+(?:(?:the|this|that|a|an|my|our|existing|new|current|connected|authenticated|console|workspace|attached|provided)\s+){0,4}(?:domains?|apps?|applications?|endpoints?|threat\s+models?|attack\s+surfaces?)\b/i;
const WORKSPACE_DOMAIN_HOST_WRITE_RE =
  /\b(?:add|create|register|import|link)\s+(?:https?:\/\/)?(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}(?::\d+)?(?:\/\S*)?\s+(?:to|in|under)\s+(?:(?:the|my|our|connected|authenticated)\s+)?(?:console|workspace)\b/i;
const WORKSPACE_APP_FIELD_UPDATE_RE =
  /\b(?:update|edit|change|set|correct|repair)\s+(?:(?:the|this|that|my|our|existing|current|connected|authenticated|console|workspace)\s+){0,4}(?:apps?|applications?)(?:['’]s)?\s+(?:name|description|type|framework|domain|disallowed\s+actions?)\s+(?:(?:to|as|with|from)\b|[:=])/i;
const WORKSPACE_ENDPOINT_FIELD_UPDATE_RE =
  /\b(?:update|edit|change|set|correct|repair)\s+(?:(?:the|this|that|my|our|existing|current|connected|authenticated|console|workspace)\s+){0,4}endpoints?(?:['’]s)?\s+(?:path|route|url|description|type|transport|location|source(?:\s+location)?|start\s+line|end\s+line|line\s+numbers?|objectives?|authentication(?:\s+requirements?)?|business\s+logic|threat\s+model|parent\s+application)\s+(?:(?:to|as|with|from)\b|[:=])/i;
const WORKSPACE_LINK_CLAUSE_GAP = String.raw`[^.?!;\n]{0,80}`;
const WORKSPACE_APP_RESOURCE = String.raw`\b(?:apps?|applications?)\b`;
const WORKSPACE_DOMAIN_RESOURCE = String.raw`\b(?:domains?|(?:https?:\/\/)?(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,})\b`;
const WORKSPACE_APP_DOMAIN_LINK_RE = new RegExp(
  String.raw`(?:\blink\b${WORKSPACE_LINK_CLAUSE_GAP}${WORKSPACE_APP_RESOURCE}${WORKSPACE_LINK_CLAUSE_GAP}\bto\b${WORKSPACE_LINK_CLAUSE_GAP}${WORKSPACE_DOMAIN_RESOURCE}|\blink\b${WORKSPACE_LINK_CLAUSE_GAP}${WORKSPACE_DOMAIN_RESOURCE}${WORKSPACE_LINK_CLAUSE_GAP}\bto\b${WORKSPACE_LINK_CLAUSE_GAP}${WORKSPACE_APP_RESOURCE}|\bunlink\b${WORKSPACE_LINK_CLAUSE_GAP}${WORKSPACE_APP_RESOURCE}${WORKSPACE_LINK_CLAUSE_GAP}\bfrom\b${WORKSPACE_LINK_CLAUSE_GAP}${WORKSPACE_DOMAIN_RESOURCE}|\bunlink\b${WORKSPACE_LINK_CLAUSE_GAP}${WORKSPACE_DOMAIN_RESOURCE}${WORKSPACE_LINK_CLAUSE_GAP}\bfrom\b${WORKSPACE_LINK_CLAUSE_GAP}${WORKSPACE_APP_RESOURCE})`,
  "i",
);
const WORKSPACE_APP_RENAME_RE =
  /\brename\s+(?:(?:the|this|that|my|our|existing|current|connected|authenticated|console|workspace)\s+){0,4}(?:apps?|applications?)\b[^.?!;\n]{0,60}\b(?:to|as)\b/i;
const WORKSPACE_BREAK_DOWN_IMPORT_RE =
  /\bbreak\s+down\b[^.?!;\n]{0,100}\b(?:threat\s+models?|attack\s+surfaces?)\b[^.?!;\n]{0,100}\b(?:into|as)\b[^.?!;\n]{0,40}\b(?:apps?|applications?|endpoints?)\b/i;

function hasExplicitWorkspaceWriteRequest(
  prompt: string,
  targetsWorkspace: boolean,
): boolean {
  return prompt.split(WORKSPACE_SENTENCE_BOUNDARY_RE).some((sentence) => {
    // A capability question governs its whole sentence, so its clauses stay
    // read-only even when `and`/`but` splits a bare write verb off the front.
    if (WORKSPACE_CAPABILITY_QUESTION_RE.test(sentence)) return false;

    return sentence.split(WORKSPACE_CLAUSE_BOUNDARY_RE).some((clause) => {
      if (
        !WORKSPACE_EXPLICIT_WRITE_REQUEST_RE.test(clause) ||
        WORKSPACE_NEGATED_WRITE_REQUEST_RE.test(clause)
      ) {
        return false;
      }

      return (
        WORKSPACE_DOMAIN_HOST_WRITE_RE.test(clause) ||
        (targetsWorkspace &&
          (WORKSPACE_CREATE_REQUEST_RE.test(clause) ||
            WORKSPACE_APP_FIELD_UPDATE_RE.test(clause) ||
            WORKSPACE_ENDPOINT_FIELD_UPDATE_RE.test(clause) ||
            WORKSPACE_APP_DOMAIN_LINK_RE.test(clause) ||
            WORKSPACE_APP_RENAME_RE.test(clause) ||
            WORKSPACE_BREAK_DOWN_IMPORT_RE.test(clause)))
      );
    });
  });
}

// ponytail: current-message opt-in avoids persistent workspace capability state.
//
// Read (`list_*`) and write (`create_*` / `update_*`) tools are gated
// separately: recon phrasing (find/search/show/list a domain, app, or endpoint on the "console"/
// "workspace") is common in ordinary Operator pentests, so it must never
// expose mutation tools. Write tools require an explicit mutation request —
// a write verb, a "break down …" import, or a direct tool-name mention.
export function filterWorkspaceToolsForRun(
  activeTools: string[],
  prompt: string,
  hasInteractiveApprovalGate: boolean,
): string[] {
  const gated =
    hasInteractiveApprovalGate && !prompt.trimStart().startsWith("<skill ");

  if (!gated) {
    return activeTools.filter((name) => !WORKSPACE_TOOL_NAME_SET.has(name));
  }

  const targetsWorkspace =
    WORKSPACE_TARGET_RE.test(prompt) && WORKSPACE_NOUN_RE.test(prompt);

  const writeRequested =
    WORKSPACE_WRITE_TOOL_NAMES.some((name) => prompt.includes(name)) ||
    hasExplicitWorkspaceWriteRequest(prompt, targetsWorkspace);

  const readRequested =
    writeRequested ||
    WORKSPACE_TOOL_NAMES.some((name) => prompt.includes(name)) ||
    (targetsWorkspace && WORKSPACE_READ_REQUEST_RE.test(prompt));

  return activeTools.filter((name) => {
    if (WORKSPACE_WRITE_TOOL_NAME_SET.has(name)) return writeRequested;
    if (WORKSPACE_TOOL_NAME_SET.has(name)) return readRequested;
    return true;
  });
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

  /** Display label for span name / `gen_ai.agent.name`; the id stays the join key. */
  private readonly subagentName?: string;
  /** Operating mode (tools surface); used for run-span attribution. */
  private readonly agentMode: AgentMode;

  /** The current open assistant message id (`msg_…`); minted on `start-step` in {@link consume}, `null` between steps. */
  private currentMessageId: string | null = null;

  /** Per-run stream counters for deterministic id derivation via {@link streamIdFactory}. */
  private streamStepIndex = -1;

  private streamTextPartIndex = 0;

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
  private shellDisposed = false;

  private readonly abortSignal?: AbortSignal;

  private readonly streamIdFactory?: StreamIdFactory;

  /** The user-facing prompt passed to the model. */
  public readonly userPrompt: string;

  /** The session this agent is operating within. */
  private readonly _session: SessionInfo;

  /** Agent-local message persistence (debounce + serialized writes). */
  private readonly writer!: AgentMessageWriter;

  /** Closes an interrupted step: synthetic results, reconstruction, write. */
  private readonly finalizeInterruptedStep!: (
    input: FinalizeInterruptedStepInput,
  ) => Promise<void>;

  private messagesPath: string | null = null;

  /** Serializes agent-owned messages.json writes in enqueue order. */
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
    this.agentMode = input.mode ?? "default";
    this.abortSignal = input.abortSignal;
    this.streamIdFactory = input.streamIdFactory;
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
      // Owned sessions aren't wired through createBrowserTools' abort path
      // (existingSession skips that listener). Disconnect on abort so timeout/
      // pause reaps Camoufox even when consume()'s drain is still unwinding.
      if (this.ownsBrowserSession && this.abortSignal) {
        const onAbort = () => {
          void this.disconnectOwnedBrowser();
        };
        if (this.abortSignal.aborted) onAbort();
        else
          this.abortSignal.addEventListener("abort", onAbort, { once: true });
      }
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
      grpc: input.grpc,
      systemScope: input.systemScope,
      abortSignal: input.abortSignal,
      model: input.model,
      authConfig: input.authConfig,
      eventBus: this.eventBus,
      onStepFinish: input.forwardUsageCallbacksToSpawnedAgents
        ? input.onStepFinish
        : undefined,
      onCacheMetrics: input.forwardUsageCallbacksToSpawnedAgents
        ? input.onCacheMetrics
        : undefined,
      sandbox: input.sandbox,
      findingsRegistry: input.findingsRegistry,
      attackSurfaceRegistry: input.attackSurfaceRegistry,
      credentialManager,
      secretValues: input.secretValues,
      environmentVariables: input.environmentVariables,
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
      // Spawn seam + durable hooks inherited by any sub-agent this agent spawns.
      // Resolve the default once here so every tool sees a guaranteed spawner.
      subagentSpawner: input.subagentSpawner ?? inProcessSubagentSpawner,
      languageModelMiddleware: input.languageModelMiddleware,
      usageRecorder: input.usageRecorder,
      streamIdFactory: input.streamIdFactory,
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
    const smsToolSet = new Set<string>(SMS_TOOL_NAMES_ACTIVE);
    const hasSms = sessionHasSmsPasswordless(input.session);
    let activeTools = (input.activeTools as string[]).filter((t) => {
      if (smsToolSet.has(t)) return hasSms;
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
        if (smsToolSet.has(t)) return hasSms;
        if (!emailToolSet.has(t)) return true;
        if (t === SEND_EMAIL_TOOL_NAME) return hasSmtp;
        return hasEmail;
      });
    }

    activeTools = filterWorkspaceToolsForRun(
      activeTools,
      input.prompt,
      input.approvalGate !== undefined,
    );

    // -- Messages persistence -------------------------------------------------
    if (!existsSync(messagesDir)) {
      mkdirSync(messagesDir, { recursive: true });
    }
    this.messagesPath = join(messagesDir, "messages.json");

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

    // Agent-local persistence: debounce, latest snapshot, and the
    // serialized write queue live in the writer (see ./messagePersistence).
    this.writer = new AgentMessageWriter({ messagesPath: this.messagesPath });
    this.finalizeInterruptedStep = createInterruptedStepFinalizer({
      eventBus: this.eventBus,
      sessionId: this.busSessionId,
      subagentId: this.subagentId,
      writer: this.writer,
      responseToolName: RESPONSE_TOOL_NAME,
      responseToolFired: () => this._responseToolFired,
      ...(RESPONSE_DEBUG
        ? { debugLog: (message: string) => rlog.warn(message) }
        : {}),
    });
    const schedulePersist = () => this.writer.schedulePersist();

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
      baseSystemPrompt +
      buildSessionWorkspaceSection(input.session, agentCwd, activeTools);

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
        languageModelMiddleware: input.languageModelMiddleware,
        usageRecorder: input.usageRecorder,
        // Per-subagent so the overflow tool-result dumps land next to this
        // agent's messages.json (`subagents/{id}/tool-results/`) and a host
        // can reclaim them when the subagent finishes, instead of piling up
        // at the shared session root for the whole scan (ENOSPC). Falls back
        // to the session root for the root/operator agent.
        sessionPath: messagesDir,
        sessionId: this.busSessionId,
        onStepFinish: async (event) => {
          this.writer.setLatest([
            ...initialMessagesRef.current,
            ...event.response.messages,
          ]);
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
          this.writer.cancelTimer();
          // Skip if the interrupted-step finalizer already wrote the abort snapshot.
          if (!this.writer.syntheticsPersisted) {
            const finalMessages = this.writer.latest ?? [
              ...initialMessagesRef.current,
              ...event.response.messages,
            ];
            this.writer.setLatest(finalMessages);
            await this.writer.enqueueWrite(finalMessages).catch(() => {});
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
      // Reset per-run stream counters so a replayed run derives the same ids.
      this.streamStepIndex = -1;
      this.streamTextPartIndex = 0;
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
            p =
              this.streamIdFactory?.({ kind: "tool-part", toolCallId }) ??
              newPartId();
            toolParts.set(toolCallId, p);
          }
          return p;
        },
      };

      // Tool lifecycle state: in-flight calls awaiting a result, completed but
      // unpersisted results (PR #779), streamed arg text, and deferred tool
      // errors — all owned by the tracker (see ./toolLifecycle).
      const tracker = new ToolLifecycleTracker();
      let streamError: unknown = null;

      // Opt-in stall watchdog + response-tool tracer (see ./streamDiagnostics).
      const diagnostics = new StreamDiagnostics({
        sessionId: this._session.id,
        subagentId: sid,
        inFlightTools: () => tracker.inFlightTools,
        responseToolFired: () => this._responseToolFired,
        responseToolName: RESPONSE_TOOL_NAME,
      });
      diagnostics.start();

      try {
        // 1–3. Iterate the stream: observe diagnostics, apply the part (id
        // bookkeeping, tracker updates, step-close emissions), forward it.
        for await (const chunk of this.streamResult.fullStream) {
          diagnostics.observeChunk(chunk);
          this.applyStreamPart(chunk, { ids, tracker, diagnostics });
          bus.emitStreamPart(chunk, ids);
        }
        // The tracker keeps completed results: an abort with no trailing
        // finish-step needs them for the finalization snapshot.
      } catch (err) {
        // 4. Capture the error; finalization below still runs.
        streamError = err;
      } finally {
        // 5–7. Close the interrupted step, dispose owned resources, settle.
        const finalizeError = await this.finalizeRun({
          tracker,
          diagnostics,
          ids,
          streamError,
        });
        // Teardown failures must not replace the provider/stream failure.
        if (streamError === null && finalizeError !== null) {
          streamError = finalizeError;
        }
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

    // One invoke_agent span per execution: root runs get the full run
    // attribution (stable run id, mode); subagent runs nest beneath the root
    // span via the async context and carry their own execution-session id.
    const isSubagent = Boolean(sid);
    const spanLabel = isSubagent
      ? (this.subagentName ?? sid ?? "subagent")
      : this.agentMode;
    const runId = isSubagent ? undefined : newRunId();
    const runSpanAttributes: Record<string, string> = {
      "gen_ai.operation.name": "invoke_agent",
      "gen_ai.agent.name": spanLabel,
      "gen_ai.conversation.id": this.busSessionId,
      "pensar.session.id": this.busSessionId,
      ...(isSubagent
        ? {}
        : {
            "pensar.run.id": runId,
            "pensar.agent.mode": this.agentMode,
          }),
    };

    const runInSpan = () =>
      getApexTracer().startActiveSpan(
        `invoke_agent ${spanLabel}`,
        { attributes: runSpanAttributes },
        async (span) => {
          // Root runs register so process-exit shutdown can end an
          // in-flight run's span before the final flush.
          if (!isSubagent) registerActiveRootSpan(span);
          try {
            return await runConsume();
          } catch (err) {
            // Record once, keep the cardinality low, preserve the original.
            span.recordException(err as Error);
            span.setStatus({ code: SpanStatusCode.ERROR });
            span.setAttribute(
              "error.type",
              err instanceof Error ? err.name : "Error",
            );
            throw err;
          } finally {
            unregisterActiveRootSpan(span);
            // Ends only after runConsume's finalization (persistence +
            // owned-resource disposal) has settled.
            span.end();
          }
        },
      );

    const drain = !isSubagent
      ? runInSpan()
      : withSubagentSessionBaggage(sid, runInSpan);

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

  /**
   * Apply one stream part: part-id bookkeeping, lifecycle-tracker updates,
   * and the finish-step close-out emissions. Pure projection of the part
   * onto run state; forwarding to the bus is the caller's job.
   */
  private applyStreamPart(
    chunk: TextStreamPart<ToolSet>,
    ctx: {
      ids: StreamIdContext;
      tracker: ToolLifecycleTracker;
      diagnostics: StreamDiagnostics;
    },
  ): void {
    const { ids, tracker, diagnostics } = ctx;
    const sid = this.subagentId;
    const bus = this.eventBus;
    switch (chunk.type) {
      case "start-step":
        this.streamStepIndex++;
        this.streamTextPartIndex = 0;
        ids.messageId =
          this.streamIdFactory?.({
            kind: "message",
            stepIndex: this.streamStepIndex,
          }) ?? newMessageId();
        this.currentMessageId = ids.messageId;
        ids.textPartId = undefined;
        break;
      case "text-start":
        ids.textPartId =
          this.streamIdFactory?.({
            kind: "text-part",
            stepIndex: this.streamStepIndex,
            textPartIndex: this.streamTextPartIndex,
          }) ?? newPartId();
        this.streamTextPartIndex++;
        break;
      case "text-end":
        ids.textPartId = undefined;
        break;
      case "finish-step": {
        tracker.onStepPersisted();
        const finishReason = (chunk as { finishReason?: string }).finishReason;
        const truncated = finishReason === "length";

        for (const [toolCallId, info] of tracker.toolErrors) {
          diagnostics.logSurfacedToolError({
            toolCallId,
            toolName: info.toolName,
            message: info.message,
            streamedArgChars: (tracker.streamedArgText.get(toolCallId) ?? "")
              .length,
            finishReason,
            truncated,
          });
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
        tracker.clearToolErrors();

        // Close any call still in flight (args never finalized) so it doesn't render stuck "running".
        for (const [toolCallId, toolName] of tracker.inFlightTools) {
          diagnostics.logClosingInFlightTool({
            toolCallId,
            toolName,
            finishReason,
            truncated,
          });
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
        tracker.clearInFlight();
        break;
      }
      default:
        // Tool-input/delta, tool-call, tool-error, tool-result → tracker.
        tracker.observePart(chunk);
    }
  }

  /**
   * Finalize a finished (or failed) run: stop diagnostics, dispose the owned
   * shell, surface deferred tool errors, close the interrupted step, and
   * disconnect the owned browser on every path. Returns the first
   * finalization error (or null) — the caller keeps the stream error
   * primary.
   */
  private async finalizeRun(input: {
    tracker: ToolLifecycleTracker;
    diagnostics: StreamDiagnostics;
    ids: StreamIdContext;
    streamError: unknown;
  }): Promise<unknown> {
    const { tracker, diagnostics, ids, streamError } = input;
    const sid = this.subagentId;
    const bus = this.eventBus;

    // Stop the stall watchdog so it never leaks past stream end / throw.
    diagnostics.stop();
    let finalizationError: unknown;
    let hasFinalizationError = false;
    const recordFinalizationError = (error: unknown) => {
      if (hasFinalizationError) return;
      finalizationError = error;
      hasFinalizationError = true;
    };

    try {
      // Dispose first — don't block on persistence I/O.
      try {
        this.disposeOwnedShell();
      } catch (error) {
        recordFinalizationError(error);
      }
      // Flush tool-errors that never reached a finish-step into the snapshot.
      for (const [toolCallId, info] of tracker.flushToolErrorsToResults()) {
        const result = {
          type: "error-text" as const,
          value: `Tool call failed: ${info.message}`,
        };
        try {
          bus.emit("tool-result", {
            toolCallId,
            toolName: info.toolName,
            result,
            sessionId: this.busSessionId,
            subagentId: sid,
            partId: ids.toolPartId?.(toolCallId),
            messageId: ids.messageId,
          });
        } catch (error) {
          recordFinalizationError(error);
        }
      }
      // Snapshot unpersisted step state: open tools get synthetic closes,
      // completed/errored results get written.
      if (tracker.hasUnpersistedState()) {
        const reason = this.abortSignal?.aborted
          ? "Agent aborted by user"
          : streamError instanceof Error && streamError.message
            ? streamError.message
            : "Stream terminated unexpectedly";
        try {
          await this.finalizeInterruptedStep({
            snapshot: tracker.snapshot(),
            reason,
            partIdFor: ids.toolPartId,
            messageId: ids.messageId,
          });
        } catch (error) {
          recordFinalizationError(error);
        }
      }
    } catch (error) {
      recordFinalizationError(error);
    } finally {
      // Tear down the Chromium child process we own. Without this, a
      // naturally-finishing agent leaks its Playwright MCP browser — over a
      // long single-process scan (many endpoints) the leaked Chromium
      // processes exhaust memory and OOM the run. disconnect() force-kills
      // and never hangs, so awaiting here is safe.
      await this.disconnectOwnedBrowser();
    }
    return hasFinalizationError ? finalizationError : null;
  }

  // ---------------------------------------------------------------------------
  // Owned-resource disposal — explicit idempotent operations; the
  // finalization path and host teardown (abortAndDrain) coordinate them
  // without knowing the shell/browser implementations.
  // ---------------------------------------------------------------------------

  /** Disposes the owned persistent shell exactly once; safe to call from multiple teardown paths. */
  disposeOwnedShell(): void {
    if (this.shellDisposed) return;
    this.shellDisposed = true;
    this.persistentShell?.dispose();
  }

  /** Force-kills the owned Chromium child process exactly once; safe to call from multiple teardown paths. */
  private async disconnectOwnedBrowser(): Promise<void> {
    if (this.browserDisconnected) return;
    if (!this.ownsBrowserSession || !this.browserSession) return;
    this.browserDisconnected = true;
    await this.browserSession.disconnect().catch(() => {});
  }

  /**
   * Idempotent teardown for hosts that abort before `consume()` settles
   * (Console `settleOnAbort` on timeout/pause). Force-disconnects the owned
   * browser, then awaits the drain so Camoufox is reaped before the next
   * endpoint starts.
   */
  async abortAndDrain(): Promise<void> {
    await this.disconnectOwnedBrowser();
    await this.drained.catch(() => {});
  }

  /**
   * Promise that resolves to the final response metadata once the stream
   * has been fully consumed. Await this *after* iterating the stream.
   */
  get response() {
    return this.streamResult.response;
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
