import type {
  StreamTextOnStepFinishCallback,
  StreamTextResult,
  ToolSet,
} from "ai";
import {
  type AgentDefinition,
  type AgentDefinitionContext,
  resolveContextual,
} from "./defineAgent";
import { OffensiveSecurityAgent } from "./offensiveSecurityAgent";
import type { ToolName } from "./tools";
import type { OffensiveSecurityAgentInput } from "./types";

/**
 * The full harness input plus the {@link AgentDefinition} that supplies this
 * agent's per-type config. `activeTools` is optional here — it defaults to the
 * definition's — so a shim need only pass the run-specific fields.
 */
export type AgentRuntimeInput<TResult = void> = Omit<
  OffensiveSecurityAgentInput<TResult>,
  "activeTools"
> & {
  activeTools?: (ToolName | (string & {}))[];
  definition: AgentDefinition<TResult>;
  /** Operating role forwarded into the definition context (e.g. pentest role). */
  role?: string;
};

/**
 * The single runtime that every specialized agent routes through. It merges an
 * {@link AgentDefinition} with the run input and forwards the base input —
 * including the durable hooks (`languageModelMiddleware`, `usageRecorder`,
 * `streamIdFactory`) and `sandbox` — into {@link OffensiveSecurityAgent} in one
 * place, so no shim can drop them.
 *
 * Merge rules (explicit input wins over the definition):
 * - `system` / `activeTools` / `mode` / `responseSchema` / `stopWhen` — input
 *   value when present, else the definition's.
 * - `extraTools` — input and definition tools merged.
 * - `resolveResult` — input's when present, else the definition's (bound to ctx).
 * - `onStepFinish` — input's runs first, then the definition's.
 */
export class AgentRuntime<
  TResult = void,
> extends OffensiveSecurityAgent<TResult> {
  constructor(input: AgentRuntimeInput<TResult>) {
    const { definition, role, ...base } = input;

    const ctx: AgentDefinitionContext<TResult> = {
      session: base.session,
      role,
      capturedResult: { current: null },
    };

    const definitionExtraTools = definition.extraTools?.(ctx);
    const extraTools =
      base.extraTools || definitionExtraTools
        ? { ...base.extraTools, ...definitionExtraTools }
        : undefined;

    const definitionResolveResult = definition.resolveResult;
    const resolveResult = base.resolveResult
      ? base.resolveResult
      : definitionResolveResult
        ? (streamResult: StreamTextResult<ToolSet, never>) =>
            definitionResolveResult(streamResult, ctx)
        : undefined;

    const activeTools =
      base.activeTools && base.activeTools.length > 0
        ? base.activeTools
        : resolveContextual(definition.activeTools, ctx);

    super({
      ...base,
      system: base.system ?? resolveContextual(definition.systemPrompt, ctx),
      activeTools,
      mode: base.mode ?? definition.mode,
      responseSchema: base.responseSchema ?? definition.resultSchema,
      stopWhen: base.stopWhen ?? definition.stopWhen,
      extraTools,
      resolveResult,
      onStepFinish: composeStepFinish(base.onStepFinish, definition.onStepFinish),
    });
  }
}

/** Run `first` then `second` per step; used to append a definition's step side effect after the caller's. */
function composeStepFinish(
  first?: StreamTextOnStepFinishCallback<ToolSet>,
  second?: StreamTextOnStepFinishCallback<ToolSet>,
): StreamTextOnStepFinishCallback<ToolSet> | undefined {
  if (!first) return second;
  if (!second) return first;
  return async (event) => {
    await first(event);
    await second(event);
  };
}
