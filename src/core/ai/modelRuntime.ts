import type { AIModel } from "./ai";
import { getModelInfo } from "./models";

export type AgentToolProtocol = "direct" | "schema-code" | "native-code";

export type AgentToolProtocolPreference = "auto" | AgentToolProtocol;

export type ModelRuntimeProfile = {
  protocol: AgentToolProtocol;
  provider: ReturnType<typeof getModelInfo>["provider"];
  supportsParallelNestedCalls: boolean;
};

function environmentPreference(): AgentToolProtocolPreference | undefined {
  const value = process.env.APEX_CODE_MODE?.trim().toLowerCase();
  if (!value) return undefined;
  if (["0", "false", "off", "direct"].includes(value)) return "direct";
  if (["1", "true", "on", "auto"].includes(value)) return "auto";
  if (value === "schema-code" || value === "native-code") return value;
  throw new Error(
    `Invalid APEX_CODE_MODE value: ${process.env.APEX_CODE_MODE}. Expected auto, on, off, schema-code, or native-code.`,
  );
}

/**
 * Resolve the model-facing tool protocol without leaking provider concerns into
 * agent workflows or canonical tool implementations.
 */
export function resolveModelRuntimeProfile(
  model: AIModel,
  preference: AgentToolProtocolPreference = "auto",
): ModelRuntimeProfile {
  const { provider } = getModelInfo(model);
  const resolvedPreference =
    preference === "auto"
      ? (environmentPreference() ?? preference)
      : preference;

  if (resolvedPreference === "native-code" && provider !== "openai") {
    throw new Error(
      `native-code requires the OpenAI Responses provider; ${model} uses ${provider}`,
    );
  }

  if (resolvedPreference !== "auto") {
    return {
      protocol: resolvedPreference,
      provider,
      supportsParallelNestedCalls: resolvedPreference !== "direct",
    };
  }

  // OpenAI Responses supports freeform custom tools. Every other provider uses
  // the portable JSON-schema exec wrapper. Selection is provider-capability
  // based; model names never participate in the harness architecture.
  if (provider === "openai") {
    return {
      protocol: "native-code",
      provider,
      supportsParallelNestedCalls: true,
    };
  }

  return {
    protocol: "schema-code",
    provider,
    supportsParallelNestedCalls: true,
  };
}
