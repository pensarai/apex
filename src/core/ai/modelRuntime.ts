import type { AIModel } from "./ai";
import { getModelInfo } from "./models";

export type AgentToolProtocol = "direct" | "schema-code" | "native-code";

export type AgentToolProtocolPreference = "auto" | AgentToolProtocol;

export type ModelRuntimeProfile = {
  protocol: AgentToolProtocol;
  provider: ReturnType<typeof getModelInfo>["provider"];
  supportsParallelNestedCalls: boolean;
};

/**
 * Resolve the model-facing tool protocol without leaking provider concerns into
 * agent workflows or canonical tool implementations.
 */
export function resolveModelRuntimeProfile(
  model: AIModel,
  preference: AgentToolProtocolPreference = "auto",
): ModelRuntimeProfile {
  const { provider } = getModelInfo(model);

  if (preference === "native-code" && provider !== "openai") {
    throw new Error(
      `native-code requires the OpenAI Responses provider; ${model} uses ${provider}`,
    );
  }

  if (preference !== "auto") {
    return {
      protocol: preference,
      provider,
      supportsParallelNestedCalls: preference !== "direct",
    };
  }

  if (provider === "openai" && /(^|\/)gpt-5\.6-sol(?:$|[-:])/i.test(model)) {
    return {
      protocol: "native-code",
      provider,
      supportsParallelNestedCalls: true,
    };
  }

  if (
    (provider === "bedrock" && /claude-opus-4-8/i.test(model)) ||
    (provider === "openrouter" && /(?:^|\/)glm-5\.2(?:$|[-:])/i.test(model))
  ) {
    return {
      protocol: "schema-code",
      provider,
      supportsParallelNestedCalls: true,
    };
  }

  return {
    protocol: "direct",
    provider,
    supportsParallelNestedCalls: false,
  };
}
