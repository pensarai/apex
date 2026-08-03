import type {
  StopCondition,
  StreamTextOnStepFinishCallback,
  StreamTextResult,
  ToolSet,
} from "ai";
import type { z } from "zod";
import type { SessionInfo } from "../../session";
import type { ToolName } from "./tools";
import type { AgentMode } from "./types";

/** Per-run context handed to a definition's function-valued fields. */
export interface AgentDefinitionContext<TResult = void> {
  /** The session the runtime is operating within. */
  session: SessionInfo;

  /** Operating role, when the agent type is role-parameterized (e.g. pentest orchestrator/worker). */
  role?: string;

  /**
   * Fresh per run. A definition's `extraTools` and `resolveResult` share it to
   * pass a captured value from the model-facing tool to the resolver — e.g. the
   * whitebox `submit_results` tool stashes its payload here and `resolveResult`
   * reads it back.
   */
  capturedResult: { current: TResult | null };
}

/** A definition field that is either a constant or a builder over the run context. */
export type Contextual<T, TResult = void> =
  | T
  | ((ctx: AgentDefinitionContext<TResult>) => T);

/**
 * The per-agent-type configuration consumed by {@link AgentRuntime}. Captures
 * everything that varied across the specialized agent classes — prompt, tools,
 * result schema, stop conditions, and the few function-valued hooks — as data,
 * so the classes collapse to thin shims over the one runtime.
 */
export interface AgentDefinition<TResult = void> {
  /** Literal discriminator naming the agent type. */
  type: string;

  /** System prompt, or a builder over the run context. */
  systemPrompt: Contextual<string, TResult>;

  /** Tool allowlist, or a builder over the run context. */
  activeTools: Contextual<(ToolName | (string & {}))[], TResult>;

  /** Operating mode controlling which tools are available. */
  mode?: AgentMode;

  /** Zod schema for structured output via the `response` tool. */
  resultSchema?: z.ZodSchema;

  /** Agent-specific tools merged on top of the built-ins. */
  extraTools?: (ctx: AgentDefinitionContext<TResult>) => ToolSet;

  /** Stop condition(s). Merged with the response-tool stop the base adds for `resultSchema`. */
  stopWhen?: StopCondition<ToolSet> | StopCondition<ToolSet>[];

  /** Produces the typed result once the stream is consumed. */
  resolveResult?: (
    streamResult: StreamTextResult<ToolSet, never>,
    ctx: AgentDefinitionContext<TResult>,
  ) => TResult | Promise<TResult>;

  /** Extra per-step side effect, composed after the caller's own `onStepFinish`. */
  onStepFinish?: StreamTextOnStepFinishCallback<ToolSet>;
}

/** Identity helper that pins the `TResult` inference for a definition literal. */
export function defineAgent<TResult = void>(
  definition: AgentDefinition<TResult>,
): AgentDefinition<TResult> {
  return definition;
}

/** Resolve a {@link Contextual} field against the run context. */
export function resolveContextual<T, TResult>(
  value: Contextual<T, TResult>,
  ctx: AgentDefinitionContext<TResult>,
): T {
  return typeof value === "function"
    ? (value as (c: AgentDefinitionContext<TResult>) => T)(ctx)
    : value;
}
