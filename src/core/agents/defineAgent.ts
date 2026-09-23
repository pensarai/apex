import type {
  StopCondition,
  StreamTextOnStepFinishCallback,
  StreamTextResult,
  ToolSet,
} from "ai";
import type { z } from "zod";
import type {
  AgentMode,
  SpecializedAgentInput,
  SystemPentestScope,
} from "./offSecAgent/types";
import type { GrpcPentestContext } from "./specialized/attackSurface/grpcSchema";

/**
 * A specialized agent as data, not a hand-written constructor (design doc
 * §3.5, Appendix F): the prompt builder, tool roster builder, response
 * schema, stop rules and any per-agent step hooks, parameterized over the
 * agent's own input type `TOpts` (which must extend {@link SpecializedAgentInput}
 * — and therefore {@link AgentHooks} — so every hook is always in scope).
 *
 * `TState` is the per-construction scratch state a definition needs to share
 * across its builders (e.g. a `reportedError` capture read by both
 * `extraTools` and `resolveResult`) — computed once by {@link createState}
 * and threaded into every other builder. Definitions with no such state
 * leave it `void`.
 *
 * A definition is pure data: none of its functions may reference `this` —
 * {@link AgentRuntime} calls them before `super()` runs.
 */
export interface AgentDefinition<
  TOpts extends SpecializedAgentInput,
  TResult = void,
  TState = void,
> {
  /** Unique name for this definition (span labels, registries, logs). */
  name: string;

  /** Operating role — documentation only; not read by the runtime. */
  role: "orchestrator" | "worker" | "judge" | "analyst" | "utility";

  /** Builds per-construction scratch state shared across the other builders. */
  createState?: (opts: TOpts) => TState;

  /** System prompt. Omit to fall back to the harness default. */
  system?: (opts: TOpts, state: TState) => string | undefined;

  /** User prompt builder — the only required builder. */
  prompt: (opts: TOpts, state: TState) => string;

  /** Tool roster builder (design doc §3.2: fixed at session start). */
  activeTools: (opts: TOpts, state: TState) => string[];

  /** Structured-output schema, when this agent captures a typed result via the `response` tool. */
  responseSchema?: (opts: TOpts, state: TState) => z.ZodSchema | undefined;

  /** Stop condition(s) beyond the harness default (`response`/`report_error` tool calls). */
  stopWhen?: (
    opts: TOpts,
    state: TState,
  ) => StopCondition<ToolSet> | StopCondition<ToolSet>[] | undefined;

  /** Extra tools this definition injects, merged on top of `opts.extraTools`. */
  extraTools?: (opts: TOpts, state: TState) => ToolSet | undefined;

  /** Produces `consume()`'s typed result from the finished stream. */
  resolveResult?: (
    opts: TOpts,
    state: TState,
    streamResult: StreamTextResult<ToolSet, never>,
  ) => TResult | Promise<TResult>;

  /** Target URL/host, when this definition derives one instead of taking it verbatim from `opts`. */
  target?: (opts: TOpts, state: TState) => string | undefined;

  /** gRPC context forwarded to `spawn_pentest_agent` workers. */
  grpc?: (opts: TOpts, state: TState) => GrpcPentestContext | undefined;

  /** Structured multi-application scope for a System pentest. */
  systemScope?: (opts: TOpts, state: TState) => SystemPentestScope | undefined;

  /** Overrides the subagent id the harness tags stream events with. */
  subagentId?: (opts: TOpts, state: TState) => string | undefined;

  /** Overrides the OTel span / UI display label. */
  subagentName?: (opts: TOpts, state: TState) => string | undefined;

  /** Harness operating mode (tool surface). */
  mode?: (opts: TOpts, state: TState) => AgentMode | undefined;

  /**
   * Wraps/overrides the per-step callback. Most definitions leave this unset
   * and let `opts.onStepFinish` forward through unchanged; a definition that
   * needs its own step side effect (e.g. mirroring messages to a log file)
   * is responsible for calling `opts.onStepFinish` itself if it should still fire.
   */
  onStepFinish?: (
    opts: TOpts,
    state: TState,
  ) => StreamTextOnStepFinishCallback<ToolSet> | undefined;
}

/**
 * Identity function that names and type-checks an {@link AgentDefinition}.
 * Kept separate from the interface so call sites read as
 * `defineAgent({ name, role, prompt, activeTools, ... })`, matching every
 * other `defineX` factory in the codebase.
 */
export function defineAgent<
  TOpts extends SpecializedAgentInput,
  TResult = void,
  TState = void,
>(
  definition: AgentDefinition<TOpts, TResult, TState>,
): AgentDefinition<TOpts, TResult, TState> {
  return definition;
}
