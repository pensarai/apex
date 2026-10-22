import { getModelSettings } from "../ai";
import type { ReasoningInput } from "../ai/reasoning";
import type { AIAuthConfig } from "../ai/utils";
import { type SessionInfo, sessions } from "../session";

type AgentReasoningInput = ReasoningInput & {
  model: string;
  authConfig?: AIAuthConfig;
  session?: SessionInfo;
  subagentId?: string;
};

export function resolveRootReasoning<T extends AgentReasoningInput>(
  input: T,
): T {
  const saved = input.session?.config?.modelReasoning;
  const reasoning = getModelSettings({
    ...input,
    reasoning:
      input.reasoning ??
      (!input.subagentId && saved?.model === input.model
        ? saved.setting
        : undefined),
  }).reasoning;
  return reasoning === input.reasoning ? input : { ...input, reasoning };
}

export function persistRootReasoningOverride(
  input: AgentReasoningInput,
): Promise<SessionInfo> | undefined {
  const saved = input.session?.config?.modelReasoning;
  if (
    input.session &&
    !input.subagentId &&
    input.reasoning !== undefined &&
    (saved?.model !== input.model || saved.setting !== input.reasoning)
  ) {
    return sessions.updateModelReasoning(
      input.session.id,
      input.model,
      input.reasoning,
    );
  }
}
