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

  // Only the OpenAI Responses provider supports freeform custom tools.
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
