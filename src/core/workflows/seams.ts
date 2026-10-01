import type { AgentHooks, Finding } from "../agents/offSecAgent";
import type { PlaywrightMcpSession } from "../agents/offSecAgent/tools";
import {
  AttackSurfaceRegistry,
  type AttackSurfaceRegistryOps,
} from "../findings/attackSurfaceRegistry";
import {
  FindingsRegistry,
  type FindingsRegistryOps,
} from "../findings/registry";
import { newSessionId } from "../id/id";
import { runWithBoundedConcurrency } from "../utils/concurrency";

// ---------------------------------------------------------------------------
// fanOut
// ---------------------------------------------------------------------------

/**
 * Bounded-concurrency fan-out. Same contract as
 * {@link SubagentSpawner.spawnMany} (`subagentSpawner.ts`) — pulled out here
 * so a workflow can fan out without depending on subagent-spawning specifics.
 */
export interface ConcurrencyRunner {
  spawnMany<TItem, TResult>(
    items: readonly TItem[],
    worker: (item: TItem, index: number) => Promise<TResult>,
    opts: { concurrency: number; abortSignal?: AbortSignal },
  ): Promise<(TResult | null)[]>;
}

function inProcessSpawnMany<TItem, TResult>(
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

/** In-process default: the same `runWithBoundedConcurrency` pool every workflow already runs on. */
export const inProcessConcurrencyRunner: ConcurrencyRunner = {
  spawnMany: inProcessSpawnMany,
};

// ---------------------------------------------------------------------------
// registries
// ---------------------------------------------------------------------------

export interface RegistryProvider {
  findings(): FindingsRegistryOps;
  attackSurface(): AttackSurfaceRegistryOps;
}

/** In-process default: fresh in-memory registries, same classes workflows construct today. */
export const inMemoryRegistryProvider: RegistryProvider = {
  findings: () => new FindingsRegistry(),
  attackSurface: () => new AttackSurfaceRegistry(),
};

// ---------------------------------------------------------------------------
// ids
// ---------------------------------------------------------------------------

export interface SessionIdFactory {
  newSessionId(name: string, ordinal: number): string;
}

/** In-process default: today's random time-descending ULID, name/ordinal ignored. */
export const randomSessionIdFactory: SessionIdFactory = {
  newSessionId: () => newSessionId(),
};

// ---------------------------------------------------------------------------
// browser
// ---------------------------------------------------------------------------

export interface BrowserSessionScope {
  subagentId: string;
  subagentName?: string;
}

export interface BrowserSessionProvider {
  forChild(scope: BrowserSessionScope): PlaywrightMcpSession | undefined;
}

/** Wraps a single live session so every child gets the same by-reference session — today's behavior. */
export function sharedBrowserSessionProvider(
  session?: PlaywrightMcpSession,
): BrowserSessionProvider {
  return { forChild: () => session };
}

/** In-process default: no session held, matching sandbox-mode agents that never had one. */
export const noBrowserSessionProvider: BrowserSessionProvider = {
  forChild: () => undefined,
};

// ---------------------------------------------------------------------------
// hooks
// ---------------------------------------------------------------------------

export interface EndpointScope {
  subagentId: string;
  subagentName?: string;
  target: string;
}

export interface OrchestrationHooks {
  onEndpointStart?(scope: EndpointScope): void | Promise<void>;
  onEndpointDone?(scope: EndpointScope, result: unknown): void | Promise<void>;
  onEndpointFailed?(scope: EndpointScope, error: unknown): void | Promise<void>;
  onFindingPersisted?(finding: Finding): void | Promise<void>;
}

/** In-process default: no-op — nothing observes endpoint/finding lifecycle today. */
export const noopOrchestrationHooks: OrchestrationHooks = {};

/**
 * Wraps a {@link FindingsRegistryOps} so a successful (non-duplicate) `register`
 * also invokes `hooks.onFindingPersisted`. Returns `registry` unchanged when no
 * hook is set, so this is a no-op under the in-process default.
 */
export function withFindingPersistedHook(
  registry: FindingsRegistryOps,
  onFindingPersisted?: OrchestrationHooks["onFindingPersisted"],
): FindingsRegistryOps {
  if (!onFindingPersisted) return registry;
  return {
    get size() {
      return registry.size;
    },
    getFindings: () => registry.getFindings(),
    isDuplicate: (finding) => registry.isDuplicate(finding),
    groupByRootCause: () => registry.groupByRootCause(),
    unregister: (finding) => registry.unregister(finding),
    async register(finding) {
      const result = await registry.register(finding);
      if (!result.duplicate) await onFindingPersisted(finding);
      return result;
    },
  };
}

// ---------------------------------------------------------------------------
// limits
// ---------------------------------------------------------------------------

export interface WorkflowLimits {
  maxDepth: number;
  maxConcurrentChildren: number;
}

/** pentest is root -> endpoint -> worker -> judge = 3 edges. */
export const DEFAULT_MAX_DEPTH = 3;

/**
 * Matches `DEFAULT_CONCURRENCY` in `./pentest.ts`. Duplicated rather than
 * imported so `seams.ts` (which workflows will depend on from A9 onward)
 * never depends back on a workflow module.
 */
export const DEFAULT_MAX_CONCURRENT_CHILDREN = 10;

const defaultLimits: WorkflowLimits = {
  maxDepth: DEFAULT_MAX_DEPTH,
  maxConcurrentChildren: DEFAULT_MAX_CONCURRENT_CHILDREN,
};

export class WorkflowLimitExceededError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "WorkflowLimitExceededError";
  }
}

/** Throws {@link WorkflowLimitExceededError} when `depth` exceeds `limits.maxDepth`. */
export function assertDepth(depth: number, limits: WorkflowLimits): void {
  if (depth > limits.maxDepth) {
    throw new WorkflowLimitExceededError(
      `workflow depth ${depth} exceeds maxDepth ${limits.maxDepth}`,
    );
  }
}

/** Wraps a `ConcurrencyRunner` so a `concurrency` above `limits.maxConcurrentChildren` fails loudly instead of silently over-subscribing. */
function withConcurrencyLimit(
  runner: ConcurrencyRunner,
  limits: WorkflowLimits,
): ConcurrencyRunner {
  return {
    async spawnMany<TItem, TResult>(
      items: readonly TItem[],
      worker: (item: TItem, index: number) => Promise<TResult>,
      opts: { concurrency: number; abortSignal?: AbortSignal },
    ): Promise<(TResult | null)[]> {
      if (opts.concurrency > limits.maxConcurrentChildren) {
        throw new WorkflowLimitExceededError(
          `concurrency ${opts.concurrency} exceeds maxConcurrentChildren ${limits.maxConcurrentChildren}`,
        );
      }
      return runner.spawnMany(items, worker, opts);
    },
  };
}

// ---------------------------------------------------------------------------
// WorkflowSeams
// ---------------------------------------------------------------------------

/**
 * The four seams (plus ids + limits) apex's workflow layer runs on. Every
 * member has an in-process default that is exactly today's behavior — see
 * {@link inProcessSeams}. Console (or any durable host) overrides members to
 * swap in DBOS-backed child workflows, DB-backed registries, deterministic
 * ids, browser reattach-by-lease, and persistence hooks, without the
 * workflows (`pentest.ts` / `whiteboxAttackSurface.ts` / `fastStrike.ts`)
 * changing.
 */
export interface WorkflowSeams {
  fanOut: ConcurrencyRunner;
  registries: RegistryProvider;
  ids: SessionIdFactory;
  browser: BrowserSessionProvider;
  hooks: OrchestrationHooks;
  limits: WorkflowLimits;
  /**
   * Per-item {@link AgentHooks} override for one item in a workflow's fan-out
   * (e.g. an endpoint's dedicated lease/backends, its own politeness budget).
   * Unset → every item runs under the workflow's shared hooks unchanged.
   */
  hooksForItem?<TItem = unknown>(
    item: TItem,
    index: number,
  ): Partial<AgentHooks>;
}

/** Builds a `WorkflowSeams` from in-process defaults, overridable per-member. */
export function inProcessSeams(
  overrides?: Partial<WorkflowSeams>,
): WorkflowSeams {
  const limits: WorkflowLimits = overrides?.limits
    ? { ...defaultLimits, ...overrides.limits }
    : defaultLimits;

  return {
    fanOut: withConcurrencyLimit(
      overrides?.fanOut ?? inProcessConcurrencyRunner,
      limits,
    ),
    registries: overrides?.registries ?? inMemoryRegistryProvider,
    ids: overrides?.ids ?? randomSessionIdFactory,
    browser: overrides?.browser ?? noBrowserSessionProvider,
    hooks: overrides?.hooks ?? noopOrchestrationHooks,
    limits,
    hooksForItem: overrides?.hooksForItem,
  };
}

/**
 * Merges a workflow's shared {@link AgentHooks} with `seams.hooksForItem`'s
 * per-item override, so every agent a fan-out constructs gets the caller's
 * hooks object unless a durable host swaps one field in for this item.
 */
export function resolveItemHooks<TItem>(
  hooks: AgentHooks | undefined,
  seams: WorkflowSeams,
  item: TItem,
  index: number,
): AgentHooks {
  return { ...hooks, ...seams.hooksForItem?.(item, index) };
}
