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
import { newSessionId } from "../../id/id";
import type { SessionInfo } from "../../session";
import { runWithBoundedConcurrency } from "../../utils/concurrency";
import type { GrpcPentestContext } from "../specialized/attackSurface/grpcSchema";
import type { SystemPentestScope } from "./types";
import type { AuthenticationAgentInput } from "../specialized/authenticationAgent/agent";
import type { FindingJudgeInput } from "../specialized/findingJudge";
import type { PlaywrightMcpSession, UnifiedSandbox } from "./tools";
import type { StreamIdFactory } from "./types";

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
  const { TargetedPentestAgent } = await import("../specialized/pentest/agent");
  const agent = new TargetedPentestAgent({
    target: spec.target,
    grpc: spec.grpc,
    systemScope: spec.systemScope,
    objectives: spec.objectives,
    context: spec.context,
    role: spec.role,
    findingsRegistry: spec.findingsRegistry,
    browserSession: spec.browserSession,
    model: ctx.model,
    session: ctx.session,
    authConfig: ctx.authConfig,
    abortSignal: ctx.abortSignal,
    onStepFinish: ctx.onStepFinish,
    onCacheMetrics: ctx.onCacheMetrics,
    eventBus: ctx.eventBus,
    subagentId: ctx.subagentId,
    subagentName: ctx.subagentName,
    sandbox: ctx.sandbox,
    environmentVariables: ctx.environmentVariables,
    secretValues: ctx.secretValues,
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
 */
class InProcessSubagentSpawner implements SubagentSpawner {
  constructor(private readonly idFactory: () => string = newSessionId) {}

  async spawn<TResult = unknown>(
    opts: SpawnOptions<TResult>,
  ): Promise<TResult> {
    const childId = opts.subagentId ?? this.idFactory();
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

      const runner = RUNNERS[opts.spec.type] as unknown as AnyRunner;
      handle = await runner(opts.spec, {
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
