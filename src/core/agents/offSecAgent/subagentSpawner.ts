import type {
  LanguageModelMiddleware,
  StopCondition,
  StreamTextOnStepFinishCallback,
  ToolSet,
} from "ai";
import type { z } from "zod";
import type {
  AIAuthConfig,
  AIModel,
  CacheMetrics,
  OpenAIReasoningEffort,
  ThinkingEffort,
  UsageRecorder,
} from "../../ai";
import type { CredentialManager } from "../../credentials";
import { AgentEventBus } from "../../eventBus";
import type { AttackSurfaceRegistry } from "../../findings/attackSurfaceRegistry";
import type { FindingsRegistry } from "../../findings/registry";
import type { SessionInfo } from "../../session";
import { runWithBoundedConcurrency } from "../../utils/concurrency";
import {
  type BrowserSessionProvider,
  inProcessSeams,
  randomSessionIdFactory,
  resolveItemHooks,
  type SessionIdFactory,
  type WorkflowSeams,
} from "../../workflows/seams";
import type { GrpcPentestContext } from "../specialized/attackSurface/grpcSchema";
import type { AuthenticationAgentInput } from "../specialized/authenticationAgent/agent";
import type { FindingJudgeInput } from "../specialized/findingJudge";
// Type-only (erased) — the value is constructed inside runSpawnedPentestWorker.
import type {
  PentestResult,
  TargetedPentestAgent,
} from "../specialized/pentest/agent";
import type { PlaywrightMcpSession, UnifiedSandbox } from "./tools";
import type { AgentHooks, StreamIdFactory, SystemPentestScope } from "./types";

/** Registry key selecting which child agent {@link SubagentSpawner.spawn} builds. */
export type SubagentType =
  | "pentest"
  | "code"
  | "whitebox-attack-surface"
  | "blackbox-attack-surface"
  | "authentication"
  | "finding-judge";

/** Type-specific construction fields; the `type` also selects the registry entry. */
export type SubagentSpec =
  | {
      type: "pentest";
      target: string;
      objectives: string[];
      context?: string;
      grpc?: GrpcPentestContext;
      systemScope?: SystemPentestScope;
      role?: "worker";
      findingsRegistry?: FindingsRegistry;
      browserSession?: PlaywrightMcpSession;
    }
  | {
      type: "code";
      codebasePath: string;
      objective: string;
      system?: string;
      responseSchema?: z.ZodSchema;
      stopWhen?: StopCondition<ToolSet>;
      excludeTools?: string[];
    }
  | {
      type: "whitebox-attack-surface";
      codebasePath: string;
      attackSurfaceRegistry?: AttackSurfaceRegistry;
    }
  | {
      type: "blackbox-attack-surface";
      target: string;
      attackSurfaceRegistry?: AttackSurfaceRegistry;
    }
  | {
      type: "authentication";
      target: string;
      authHints?: AuthenticationAgentInput["authHints"];
    }
  | {
      type: "finding-judge";
      judgeInput: FindingJudgeInput;
      target?: string;
    };

/**
 * Harness the parent runtime injects into every child. The durable hooks and
 * `sandbox` are inherited from the parent so a spawned child is subject to the
 * same middleware / usage recording / id minting / execution sandbox.
 * @public Consumed by Console's durable subagent runtime.
 */
export interface SpawnRuntime {
  session: SessionInfo;
  model: AIModel;
  authConfig?: AIAuthConfig;
  abortSignal?: AbortSignal;
  sandbox?: UnifiedSandbox;
  credentialManager?: CredentialManager;
  display?: string;
  enableThinking?: boolean;
  thinkingEffort?: ThinkingEffort | null;
  openAIReasoningEffort?: OpenAIReasoningEffort | null;
  environmentVariables?: Record<string, string>;
  secretValues?: string[];
  languageModelMiddleware?: LanguageModelMiddleware | LanguageModelMiddleware[];
  usageRecorder?: UsageRecorder;
  streamIdFactory?: StreamIdFactory;
  /**
   * Step-usage + cache-metric callbacks forwarded to spawned workers. The inline
   * spawner path uses these for usage accounting; the durable runtime attributes
   * usage via {@link usageRecorder} instead and leaves them unset.
   */
  onStepFinish?: StreamTextOnStepFinishCallback<ToolSet>;
  onCacheMetrics?: (metrics: CacheMetrics) => void;
}

/** @public Consumed by Console's durable subagent runtime. */
export interface SpawnOptions<TResult = unknown> {
  /** Type-specific construction fields + the registry discriminator. */
  spec: SubagentSpec;

  /** Harness inherited from the parent runtime. */
  runtime: SpawnRuntime;

  /** Parent bus the child's events bubble to via {@link AgentEventBus.attachChild}. */
  parentBus?: AgentEventBus;

  /** Explicit child id. When omitted, minted via the spawner's id factory. */
  subagentId?: string;

  /** UI label — `subagent-spawn.name` and the child's `subagentName`. */
  subagentName?: string;

  /** Payload for the `subagent-spawn` `input` field. */
  lifecycleInput?: unknown;

  /** Owning agent id → lifecycle `parentSubagentId`. */
  parentSubagentId?: string;

  /** Owning agent session id → lifecycle `parentSessionId`. */
  parentSessionId?: string;

  /** Stamp the child's own id as `sessionId` on lifecycle events. */
  stampChildSessionId?: boolean;

  /** When set, await the child's background drain (bounded) before `subagent-complete`. */
  drainGraceMs?: number;

  /** Derive the completion status from the result (default: resolve → completed). */
  resolveStatus?: (result: TResult) => "completed" | "failed";

  /** Called with the freshly minted (or overridden) child id. */
  onSpawned?: (childId: string) => void;

  /** Attach listeners to the child bus before consumption (e.g. text capture). */
  beforeConsume?: (childBus: AgentEventBus) => void;

  /** Runs after a successful consume, before the drain wait and completion emit. */
  onConsumed?: (result: TResult) => void | Promise<void>;

  /** Runs after a failed consume, before the drain wait and completion emit. */
  onError?: (error: unknown) => void | Promise<void>;
}

/**
 * The one seam through which every sub-agent is spawned. The in-process
 * default preserves today's behavior; a durable implementation can swap in
 * deterministic ids, a recording sandbox, and child-workflow scheduling
 * without touching any spawn call site.
 */
export interface SubagentSpawner {
  /**
   * Spawn one child: mint its id, wire a child bus onto the parent, emit the
   * `subagent-spawn` / `subagent-complete` lifecycle, construct the agent by
   * `spec.type`, and return its consumed result.
   */
  spawn<TResult = unknown>(opts: SpawnOptions<TResult>): Promise<TResult>;

  /**
   * Run a fan-out with bounded concurrency. Unifies the `pLimit` /
   * `runWithBoundedConcurrency` / sequential mechanisms behind one `concurrency`
   * arg. Failed workers yield `null`, matching the fan-out helpers it replaces.
   */
  spawnMany<TItem, TResult>(
    items: readonly TItem[],
    worker: (item: TItem, index: number) => Promise<TResult>,
    opts: { concurrency: number; abortSignal?: AbortSignal },
  ): Promise<(TResult | null)[]>;
}

// ---------------------------------------------------------------------------
// Spawned pentest worker (closure-free)
// ---------------------------------------------------------------------------

/**
 * The serializable subset of a pentest {@link SubagentSpec} — everything a
 * durable caller can carry across a child-workflow boundary. `findingsRegistry`
 * and `browserSession` are live objects, not serializable, so they live on
 * {@link SpawnedPentestWorkerInput} instead.
 */
export type SpawnedPentestWorkerSpec = Omit<
  Extract<SubagentSpec, { type: "pentest" }>,
  "type" | "findingsRegistry" | "browserSession"
>;

/**
 * Explicit, serializable-by-the-caller input for {@link runSpawnedPentestWorker}
 * — everything the `spawn_pentest_agent` worker path reads today, with no
 * reads of the spawner's own enclosing scope. A durable caller rebuilds
 * `hooks` and `seams` on its own side and runs the worker as a child workflow.
 */
export interface SpawnedPentestWorkerInput {
  model: AIModel;
  session: SessionInfo;
  authConfig?: AIAuthConfig;
  abortSignal?: AbortSignal;
  eventBus?: AgentEventBus;
  subagentId?: string;
  subagentName?: string;
  findingsRegistry?: FindingsRegistry;
  browserSession?: PlaywrightMcpSession;
  onStepFinish?: StreamTextOnStepFinishCallback<ToolSet>;
  onCacheMetrics?: (metrics: CacheMetrics) => void;
  environmentVariables?: Record<string, string>;
  secretValues?: string[];
  enableThinking?: boolean;
  thinkingEffort?: ThinkingEffort | null;
  openAIReasoningEffort?: OpenAIReasoningEffort | null;
  display?: string;
  /** The caller's own {@link AgentHooks} — `backends` is the caller's object. */
  hooks: AgentHooks;
  /** Fan-out / hook seams (`../../workflows/seams.ts`); only `hooksForItem` is consulted here. */
  seams: WorkflowSeams;
  /** Lets the in-process spawner observe its drain promise; unused by a standalone/durable caller. */
  onAgentConstructed?: (agent: TargetedPentestAgent) => void;
}

/**
 * Construct one {@link TargetedPentestAgent} from a spawn spec and consume it —
 * the exact mapping `spawn_pentest_agent`'s in-process worker path uses today,
 * pulled out so a durable caller can run a spawned pentest worker as its own
 * child workflow instead of hand-rolling the construction (design doc A13).
 */
export async function runSpawnedPentestWorker(
  spec: SpawnedPentestWorkerSpec,
  input: SpawnedPentestWorkerInput,
): Promise<PentestResult> {
  const { TargetedPentestAgent } = await import("../specialized/pentest/agent");
  const hooks = resolveItemHooks(input.hooks, input.seams, spec, 0);

  const agent = new TargetedPentestAgent({
    target: spec.target,
    grpc: spec.grpc,
    systemScope: spec.systemScope,
    objectives: spec.objectives,
    context: spec.context,
    role: spec.role,
    findingsRegistry: input.findingsRegistry,
    browserSession: input.browserSession,
    model: input.model,
    session: input.session,
    authConfig: input.authConfig,
    onStepFinish: input.onStepFinish,
    onCacheMetrics: input.onCacheMetrics,
    eventBus: input.eventBus,
    subagentId: input.subagentId,
    subagentName: input.subagentName,
    environmentVariables: input.environmentVariables,
    secretValues: input.secretValues,
    enableThinking: input.enableThinking,
    thinkingEffort: input.thinkingEffort,
    openAIReasoningEffort: input.openAIReasoningEffort,
    display: input.display,
    ...hooks,
    abortSignal: input.abortSignal,
  });

  input.onAgentConstructed?.(agent);
  return agent.consume();
}

// ---------------------------------------------------------------------------
// In-process implementation
// ---------------------------------------------------------------------------

type ChildRuntime = SpawnRuntime & {
  eventBus: AgentEventBus;
  subagentId: string;
  subagentName?: string;
};

interface AgentHandle<TResult> {
  run: () => Promise<TResult>;
  /** Background stream drain, when the child exposes one. */
  drained?: () => Promise<void>;
}

type SubagentRunner<T extends SubagentType> = (
  spec: Extract<SubagentSpec, { type: T }>,
  ctx: ChildRuntime,
) => Promise<AgentHandle<unknown>>;

type AnyRunner = (
  spec: SubagentSpec,
  ctx: ChildRuntime,
) => Promise<AgentHandle<unknown>>;

const runPentestChild: SubagentRunner<"pentest"> = async (spec, ctx) => {
  // Delegates construction+consume to runSpawnedPentestWorker (see above);
  // only stashes the constructed agent's `drained` for the drain-grace wait.
  let constructed: TargetedPentestAgent | undefined;
  const workerSpec: SpawnedPentestWorkerSpec = {
    target: spec.target,
    grpc: spec.grpc,
    systemScope: spec.systemScope,
    objectives: spec.objectives,
    context: spec.context,
    role: spec.role,
  };
  const workerInput: SpawnedPentestWorkerInput = {
    model: ctx.model,
    session: ctx.session,
    authConfig: ctx.authConfig,
    abortSignal: ctx.abortSignal,
    onStepFinish: ctx.onStepFinish,
    onCacheMetrics: ctx.onCacheMetrics,
    eventBus: ctx.eventBus,
    subagentId: ctx.subagentId,
    subagentName: ctx.subagentName,
    findingsRegistry: spec.findingsRegistry,
    browserSession: spec.browserSession,
    environmentVariables: ctx.environmentVariables,
    secretValues: ctx.secretValues,
    enableThinking: ctx.enableThinking,
    thinkingEffort: ctx.thinkingEffort,
    openAIReasoningEffort: ctx.openAIReasoningEffort,
    display: ctx.display,
    hooks: {
      sandbox: ctx.sandbox,
      languageModelMiddleware: ctx.languageModelMiddleware,
      usageRecorder: ctx.usageRecorder,
      streamIdFactory: ctx.streamIdFactory,
    },
    seams: inProcessSeams(),
    onAgentConstructed: (agent) => {
      constructed = agent;
    },
  };
  return {
    run: () => runSpawnedPentestWorker(workerSpec, workerInput),
    drained: () => constructed?.drained ?? Promise.resolve(),
  };
};

const runCodeChild: SubagentRunner<"code"> = async (spec, ctx) => {
  const { CodeAgent } = await import("../specialized/codeAgent/agent");
  const agent = new CodeAgent({
    codebasePath: spec.codebasePath,
    objective: spec.objective,
    system: spec.system,
    responseSchema: spec.responseSchema,
    stopWhen: spec.stopWhen,
    excludeTools: spec.excludeTools,
    model: ctx.model,
    session: ctx.session,
    authConfig: ctx.authConfig,
    abortSignal: ctx.abortSignal,
    eventBus: ctx.eventBus,
    subagentId: ctx.subagentId,
    subagentName: ctx.subagentName,
    sandbox: ctx.sandbox,
    enableThinking: ctx.enableThinking,
    thinkingEffort: ctx.thinkingEffort,
    openAIReasoningEffort: ctx.openAIReasoningEffort,
    display: ctx.display,
    languageModelMiddleware: ctx.languageModelMiddleware,
    usageRecorder: ctx.usageRecorder,
    streamIdFactory: ctx.streamIdFactory,
  });
  return { run: () => agent.consume(), drained: () => agent.drained };
};

const runWhiteboxChild: SubagentRunner<"whitebox-attack-surface"> = async (
  spec,
  ctx,
) => {
  const { WhiteboxAttackSurfaceAgent } = await import(
    "../specialized/whiteboxAttackSurface"
  );
  const agent = new WhiteboxAttackSurfaceAgent({
    codebasePath: spec.codebasePath,
    attackSurfaceRegistry: spec.attackSurfaceRegistry,
    model: ctx.model,
    session: ctx.session,
    authConfig: ctx.authConfig,
    abortSignal: ctx.abortSignal,
    eventBus: ctx.eventBus,
    subagentId: ctx.subagentId,
    subagentName: ctx.subagentName,
    sandbox: ctx.sandbox,
    languageModelMiddleware: ctx.languageModelMiddleware,
    usageRecorder: ctx.usageRecorder,
    streamIdFactory: ctx.streamIdFactory,
  });
  return { run: () => agent.consume(), drained: () => agent.drained };
};

const runBlackboxChild: SubagentRunner<"blackbox-attack-surface"> = async (
  spec,
  ctx,
) => {
  const { BlackboxAttackSurfaceAgent } = await import(
    "../specialized/attackSurface/blackboxAgent"
  );
  const agent = new BlackboxAttackSurfaceAgent({
    target: spec.target,
    attackSurfaceRegistry: spec.attackSurfaceRegistry,
    model: ctx.model,
    session: ctx.session,
    authConfig: ctx.authConfig,
    abortSignal: ctx.abortSignal,
    eventBus: ctx.eventBus,
    subagentId: ctx.subagentId,
    sandbox: ctx.sandbox,
    languageModelMiddleware: ctx.languageModelMiddleware,
    usageRecorder: ctx.usageRecorder,
    streamIdFactory: ctx.streamIdFactory,
  });
  return { run: () => agent.consume(), drained: () => agent.drained };
};

const runAuthChild: SubagentRunner<"authentication"> = async (spec, ctx) => {
  const { runAuthenticationAgent } = await import(
    "../specialized/authenticationAgent/agent"
  );
  return {
    run: () =>
      runAuthenticationAgent({
        target: spec.target,
        authHints: spec.authHints,
        session: ctx.session,
        model: ctx.model,
        authConfig: ctx.authConfig,
        abortSignal: ctx.abortSignal,
        eventBus: ctx.eventBus,
        subagentId: ctx.subagentId,
        subagentName: ctx.subagentName,
        environmentVariables: ctx.environmentVariables,
        secretValues: ctx.secretValues,
        languageModelMiddleware: ctx.languageModelMiddleware,
        usageRecorder: ctx.usageRecorder,
        streamIdFactory: ctx.streamIdFactory,
      }),
  };
};

const runJudgeChild: SubagentRunner<"finding-judge"> = async (spec, ctx) => {
  const { judgeFinding } = await import("../specialized/findingJudge");
  return {
    run: () =>
      judgeFinding(spec.judgeInput, {
        model: ctx.model,
        session: ctx.session,
        authConfig: ctx.authConfig,
        abortSignal: ctx.abortSignal,
        eventBus: ctx.eventBus,
        subagentId: ctx.subagentId,
        subagentName: ctx.subagentName,
        sandbox: ctx.sandbox,
        target: spec.target,
        enableThinking: ctx.enableThinking,
        thinkingEffort: ctx.thinkingEffort,
        openAIReasoningEffort: ctx.openAIReasoningEffort,
        languageModelMiddleware: ctx.languageModelMiddleware,
        usageRecorder: ctx.usageRecorder,
        streamIdFactory: ctx.streamIdFactory,
      }),
  };
};

const RUNNERS: { [T in SubagentType]: SubagentRunner<T> } = {
  pentest: runPentestChild,
  code: runCodeChild,
  "whitebox-attack-surface": runWhiteboxChild,
  "blackbox-attack-surface": runBlackboxChild,
  authentication: runAuthChild,
  "finding-judge": runJudgeChild,
};

function drainBounded(
  drained: Promise<void> | undefined,
  graceMs: number,
): Promise<void> {
  return Promise.race([
    drained?.catch(() => {}) ?? Promise.resolve(),
    new Promise<void>((resolve) => {
      setTimeout(resolve, graceMs).unref?.();
    }),
  ]);
}

/**
 * Default spawner: constructs the real agent and consumes it in-process — a
 * faithful extraction of the hand-rolled `newSessionId → new AgentEventBus →
 * attachChild → new Agent → consume` pattern the tools used before.
 *
 * Optionally takes the `ids` / `browser` {@link WorkflowSeams} (`../../workflows/seams.ts`)
 * so a durable host can mint deterministic child ids and reattach a browser
 * session by scope instead of the in-process defaults (random ULID, no
 * session). Unconfigured, behavior is unchanged from before these seams existed.
 */
class InProcessSubagentSpawner implements SubagentSpawner {
  private ordinal = 0;

  constructor(
    private readonly ids: SessionIdFactory = randomSessionIdFactory,
    private readonly browser?: BrowserSessionProvider,
  ) {}

  private mintChildId(name?: string): string {
    return this.ids.newSessionId(name ?? "subagent", this.ordinal++);
  }

  async spawn<TResult = unknown>(
    opts: SpawnOptions<TResult>,
  ): Promise<TResult> {
    const childId = opts.subagentId ?? this.mintChildId(opts.subagentName);
    opts.onSpawned?.(childId);

    const lifecycleBase = {
      subagentId: childId,
      ...(opts.stampChildSessionId ? { sessionId: childId } : {}),
      ...(opts.parentSubagentId !== undefined
        ? { parentSubagentId: opts.parentSubagentId }
        : {}),
      ...(opts.parentSessionId !== undefined
        ? { parentSessionId: opts.parentSessionId }
        : {}),
    };

    opts.parentBus?.emit("subagent-spawn", {
      ...lifecycleBase,
      name: opts.subagentName,
      input: opts.lifecycleInput,
    });

    let handle: AgentHandle<unknown> | undefined;
    try {
      const childBus = new AgentEventBus();
      AgentEventBus.attachChild(childBus, opts.parentBus, childId);

      const spec =
        opts.spec.type === "pentest" &&
        !opts.spec.browserSession &&
        this.browser
          ? {
              ...opts.spec,
              browserSession: this.browser.forChild({
                subagentId: childId,
                subagentName: opts.subagentName,
              }),
            }
          : opts.spec;

      const runner = RUNNERS[spec.type] as unknown as AnyRunner;
      handle = await runner(spec, {
        ...opts.runtime,
        eventBus: childBus,
        subagentId: childId,
        subagentName: opts.subagentName,
      });

      opts.beforeConsume?.(childBus);

      const result = (await handle.run()) as TResult;
      await opts.onConsumed?.(result);
      if (opts.drainGraceMs != null) {
        await drainBounded(handle.drained?.(), opts.drainGraceMs);
      }
      opts.parentBus?.emit("subagent-complete", {
        ...lifecycleBase,
        status: opts.resolveStatus?.(result) ?? "completed",
      });
      return result;
    } catch (error) {
      try {
        await opts.onError?.(error);
        if (opts.drainGraceMs != null) {
          await drainBounded(handle?.drained?.(), opts.drainGraceMs);
        }
      } finally {
        opts.parentBus?.emit("subagent-complete", {
          ...lifecycleBase,
          status: "failed",
        });
      }
      throw error;
    }
  }

  spawnMany<TItem, TResult>(
    items: readonly TItem[],
    worker: (item: TItem, index: number) => Promise<TResult>,
    opts: { concurrency: number; abortSignal?: AbortSignal },
  ): Promise<(TResult | null)[]> {
    return runWithBoundedConcurrency(
      items as TItem[],
      opts.concurrency,
      worker,
      opts.abortSignal,
    );
  }
}

/** Shared default used by every spawn call site when none is injected. */
export const inProcessSubagentSpawner = new InProcessSubagentSpawner();

/**
 * Build an in-process spawner wired to the `ids` / `browser` seams of a
 * {@link WorkflowSeams} (`../../workflows/seams.ts`), e.g.
 * `createInProcessSubagentSpawner(inProcessSeams({ ids: myFactory }))`.
 */
export function createInProcessSubagentSpawner(
  seams?: Partial<Pick<WorkflowSeams, "ids" | "browser">>,
): SubagentSpawner {
  return new InProcessSubagentSpawner(seams?.ids, seams?.browser);
}
