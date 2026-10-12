import type { LanguageModelMiddleware, ToolSet } from "ai";
import type { InferenceRecorder, UsageRecorder } from "../ai";
import type { RunContextRecorder } from "../runtime/runContext";
import type { ToolExecutionRecorder } from "../runtime/runToolStore";
import type { ToolBackends } from "../tools/backends/types";
import type { AgentDefinition } from "./defineAgent";
import {
  type AgentHooks,
  OffensiveSecurityAgent,
  type SpecializedAgentInput,
} from "./offSecAgent";
import type { SubagentSpawner } from "./offSecAgent/subagentSpawner";
import type { EmailAdapterResolver } from "./offSecAgent/tools/email/adapters";
import type { UnifiedSandbox } from "./offSecAgent/tools/sandbox";
import type { SmsInbox } from "./offSecAgent/tools/smsInbox";
import type { StreamIdFactory } from "./offSecAgent/types";

/**
 * {@link AgentHooks} with every key required (value types keep their
 * `| undefined`). Hand-listed, not mapped from {@link AgentHooks}, so that
 * adding a field there without updating this type — and {@link assembleAgentHooks}
 * below — fails `tsc` instead of a review: the compile-time guarantee behind
 * "dropping a hook is a type error".
 */
export interface RequiredAgentHooks {
  backends: ToolBackends | undefined;
  subagentSpawner: SubagentSpawner | undefined;
  languageModelMiddleware:
    | LanguageModelMiddleware
    | LanguageModelMiddleware[]
    | undefined;
  inferenceRecorder: InferenceRecorder | undefined;
  contextRecorder: RunContextRecorder | undefined;
  toolExecutionRecorder: ToolExecutionRecorder | undefined;
  usageRecorder: UsageRecorder | undefined;
  streamIdFactory: StreamIdFactory | undefined;
  smsInbox: SmsInbox | undefined;
  emailAdapterFor: EmailAdapterResolver | undefined;
  abortSignal: AbortSignal | undefined;
  extraTools: ToolSet | undefined;
  sandbox: UnifiedSandbox | undefined;
}

/**
 * The ONE place every hook is named. {@link AgentRuntime} calls this once
 * and spreads the result into the underlying `OffensiveSecurityAgent`
 * (which threads it into `streamResponse`); the AI layer's
 * `generateObjectResponse` reads the same `languageModelMiddleware` /
 * `usageRecorder` pair for structured-output callers (`cvssScorer`,
 * `findings/registry`'s semantic dedup) that never go through this runtime.
 */
export function assembleAgentHooks(opts: AgentHooks): RequiredAgentHooks {
  return {
    backends: opts.backends,
    subagentSpawner: opts.subagentSpawner,
    languageModelMiddleware: opts.languageModelMiddleware,
    inferenceRecorder: opts.inferenceRecorder,
    contextRecorder: opts.contextRecorder,
    toolExecutionRecorder: opts.toolExecutionRecorder,
    usageRecorder: opts.usageRecorder,
    streamIdFactory: opts.streamIdFactory,
    smsInbox: opts.smsInbox,
    emailAdapterFor: opts.emailAdapterFor,
    abortSignal: opts.abortSignal,
    extraTools: opts.extraTools,
    sandbox: opts.sandbox,
  };
}

function mergeExtraTools(
  fromHooks: ToolSet | undefined,
  fromDefinition: ToolSet | undefined,
): ToolSet | undefined {
  if (!fromHooks && !fromDefinition) return undefined;
  return { ...fromHooks, ...fromDefinition };
}

/** Builds a specialized agent while forwarding every execution hook. */
export class AgentRuntime<
  TOpts extends SpecializedAgentInput,
  TResult = void,
  TState = void,
> extends OffensiveSecurityAgent<TResult> {
  constructor(
    definition: AgentDefinition<TOpts, TResult, TState>,
    opts: TOpts,
  ) {
    const state = (definition.createState?.(opts) ?? undefined) as TState;
    const resolveResult = definition.resolveResult;

    super({
      ...opts,
      ...assembleAgentHooks(opts),
      system: definition.system?.(opts, state),
      prompt: definition.prompt(opts, state),
      activeTools: definition.activeTools(opts, state),
      responseSchema: definition.responseSchema?.(opts, state),
      stopWhen: definition.stopWhen?.(opts, state) ?? opts.stopWhen,
      extraTools: mergeExtraTools(
        opts.extraTools,
        definition.extraTools?.(opts, state),
      ),
      resolveResult: resolveResult
        ? (streamResult) => resolveResult(opts, state, streamResult)
        : undefined,
      target: definition.target?.(opts, state) ?? opts.target,
      grpc: definition.grpc?.(opts, state) ?? opts.grpc,
      browserEngine:
        definition.browserEngine?.(opts, state) ?? opts.browserEngine,
      agentCwd: definition.agentCwd?.(opts, state) ?? opts.agentCwd,
      fileWorkspaceRoot:
        definition.fileWorkspaceRoot?.(opts, state) ?? opts.fileWorkspaceRoot,
      systemScope: definition.systemScope?.(opts, state) ?? opts.systemScope,
      subagentId: definition.subagentId?.(opts, state) ?? opts.subagentId,
      subagentName: definition.subagentName?.(opts, state) ?? opts.subagentName,
      mode: definition.mode?.(opts, state) ?? opts.mode,
      onStepFinish: definition.onStepFinish?.(opts, state) ?? opts.onStepFinish,
    });
  }
}
