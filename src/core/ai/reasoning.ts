import type { JSONValue } from "@ai-sdk/provider";
import {
  type CustomProviders,
  parseCustomModelId,
  resolveCustomModel,
} from "../config/customProviders";
import type { OpenAIReasoningEffort, ThinkingEffort } from "./ai";
import { getClaudeCapabilities, getModelInfo } from "./models";
import openRouterReasoning from "./models/openrouter-reasoning.json";
import {
  CONCENTRATE_GLM_5_3_MODEL_ID,
  CONCENTRATE_REASONING_MODEL_IDS,
} from "./providers/concentrate";
import type { AIAuthConfig } from "./utils";

export const REASONING_SETTINGS = [
  "default",
  "enabled",
  "disabled",
  "none",
  "minimal",
  "low",
  "medium",
  "high",
  "xhigh",
  "max",
] as const;
export type ReasoningSetting = (typeof REASONING_SETTINGS)[number];
export type ReasoningEffort = Exclude<
  ReasoningSetting,
  "default" | "enabled" | "disabled"
>;

export type ReasoningInput = {
  reasoning?: ReasoningSetting;
  enableThinking?: boolean;
  thinkingEffort?: ThinkingEffort | null;
  openAIReasoningEffort?: OpenAIReasoningEffort | null;
};

export function resolveReasoningSetting(
  model: string,
  input: ReasoningInput & { customProviders?: CustomProviders },
  defaults: "legacy" | "model" = "legacy",
): ReasoningSetting | undefined {
  if (input.reasoning !== undefined)
    return validateReasoningSetting(
      model,
      input.reasoning,
      input.customProviders,
    );
  const cap = getReasoningCapabilities(model, input.customProviders);
  if (cap.control === "none") return undefined;
  if (
    (cap.thinking || model.startsWith("anthropic/claude-")) &&
    cap.transport !== "google"
  ) {
    if (
      defaults === "model" &&
      input.enableThinking === undefined &&
      input.thinkingEffort == null
    )
      return "default";
    if (!input.enableThinking && !cap.alwaysOn)
      return cap.efforts.includes("none") ? "none" : "disabled";
    const effort =
      input.thinkingEffort ??
      getClaudeCapabilities(model)?.defaultEffort ??
      cap.defaultEffort;
    return effort && cap.efforts.includes(effort)
      ? effort
      : cap.control === "toggle"
        ? "enabled"
        : "default";
  }
  // Legacy controls did not override Google or custom endpoint defaults.
  if (cap.transport === "google" || model.startsWith("custom:"))
    return undefined;
  const effort = input.openAIReasoningEffort;
  if (defaults === "model" && effort == null) return "default";
  if (model === CONCENTRATE_GLM_5_3_MODEL_ID && effort)
    return effort === "none" || effort === "low"
      ? "low"
      : effort === "medium" || effort === "high"
        ? "high"
        : "max";
  const value = effort === "ultra" ? "max" : effort;
  return value && cap.efforts.includes(value)
    ? value
    : (cap.defaultEffort ?? "default");
}

export function getModelSettings(
  input: ReasoningInput & { model?: string; authConfig?: AIAuthConfig },
): { model: string; authConfig?: AIAuthConfig; reasoning?: ReasoningSetting } {
  if (!input.model) throw new Error("Model settings require a model.");
  return {
    model: input.model,
    authConfig: input.authConfig,
    reasoning: resolveReasoningSetting(input.model, {
      ...input,
      customProviders: input.authConfig?.customProviders,
    }),
  };
}

type Transport = "openai" | "openrouter" | "anthropic" | "bedrock" | "google";
export type ReasoningCapabilities = {
  control: "effort" | "toggle" | "none";
  efforts: readonly ReasoningEffort[];
  defaultEffort?: ReasoningEffort;
  defaultEnabled?: boolean;
  canDisable: boolean;
  transport?: Transport;
  thinking?: "adaptive" | "budget";
  alwaysOn?: boolean;
};

export type ReasoningProviderOptions = Record<
  string,
  Record<string, JSONValue | undefined>
>;
const UNKNOWN: ReasoningCapabilities = {
  control: "none",
  efforts: [],
  canDisable: false,
};
const BASIC = ["low", "medium", "high"] as const;
const EXTENDED = [...BASIC, "xhigh", "max"] as const;

function effort(
  transport: Transport,
  efforts: readonly ReasoningEffort[],
  defaultEffort: ReasoningEffort = "medium",
): ReasoningCapabilities {
  return {
    control: "effort",
    transport,
    efforts,
    defaultEffort,
    canDisable: efforts.includes("none"),
  };
}

// Reviewed against the provider documentation linked in docs/model-reasoning.md.
export function getReasoningCapabilities(
  modelId: string,
  customProviders?: CustomProviders,
): ReasoningCapabilities {
  if (parseCustomModelId(modelId)) {
    let resolved: ReturnType<typeof resolveCustomModel>;
    try {
      resolved = resolveCustomModel(modelId, customProviders);
    } catch {
      // Removed endpoint configuration must not break the model picker.
      return UNKNOWN;
    }
    const { provider, model } = resolved;
    if (
      provider.apiType === "responses" &&
      model.supportedReasoningEfforts?.length
    ) {
      return {
        ...effort("openai", model.supportedReasoningEfforts),
        defaultEffort: model.reasoningEffort,
      };
    }
    return UNKNOWN;
  }
  const { provider } = getModelInfo(modelId);
  if (
    provider === "local" ||
    provider === "hoonify" ||
    provider === "inference" ||
    provider === "inception"
  )
    return UNKNOWN;
  if (provider === "openrouter") {
    const metadata = (
      openRouterReasoning.models as Record<
        string,
        {
          mandatory?: boolean;
          default_enabled?: boolean;
          supported_efforts?: string[] | null;
          default_effort?: string;
        } | null
      >
    )[modelId];
    if (!metadata) return UNKNOWN;
    const allowed: readonly ReasoningEffort[] = [
      "none",
      "minimal",
      ...EXTENDED,
    ];
    const efforts = allowed.filter(
      (value) =>
        (metadata.supported_efforts === null ||
          metadata.supported_efforts?.includes(value)) &&
        !(metadata.mandatory && value === "none"),
    );
    return {
      control: efforts.length
        ? "effort"
        : metadata.mandatory
          ? "none"
          : "toggle",
      transport: "openrouter",
      efforts,
      canDisable: !metadata.mandatory,
      alwaysOn: metadata.mandatory,
      defaultEnabled: metadata.default_enabled,
      ...(getClaudeCapabilities(modelId)
        ? { thinking: "adaptive" as const }
        : {}),
      defaultEffort: efforts.includes(
        metadata.default_effort as ReasoningEffort,
      )
        ? (metadata.default_effort as ReasoningEffort)
        : undefined,
    };
  }
  const native = modelId
    .replace(/^(?:pensar:|concentrate:|bedrock-mantle:)/, "")
    .replace(/^(?:(?:us|global|eu|au|jp|ap)\.)?anthropic[./]/, "")
    .replace(/^(?:openai[/.]|google\/)/, "")
    .replace(/-\d{4}-\d{2}-\d{2}$/, "")
    .replace(/-\d{8}(?:-v\d+:\d+)?$/, "")
    .replace(/-v\d+(?::\d+)?$/, "");
  const claudeId = native.replace(/(\d)\.(\d)/g, "$1-$2");
  const claude = getClaudeCapabilities(modelId);
  const adaptive =
    claude || /^(?:claude-opus-4-[678]|claude-sonnet-4-6)$/.test(claudeId);
  const budget =
    /^(?:claude-opus-4(?:-1|-5)?|claude-sonnet-4(?:-5)?|claude-haiku-4-5|claude-3-7-sonnet)$/.test(
      claudeId,
    );
  if (adaptive || budget) {
    const transport: Transport =
      provider === "concentrate"
        ? "openai"
        : provider === "bedrock"
          ? "bedrock"
          : "anthropic";
    const efforts = adaptive
      ? /^claude-(?:opus|sonnet)-4-6$/.test(claudeId)
        ? ([...BASIC, "max"] as const)
        : EXTENDED
      : claudeId === "claude-opus-4-5"
        ? BASIC
        : [];
    // Concentrate's Responses route has no manual thinking-budget channel.
    if (budget && transport === "openai") return UNKNOWN;
    return {
      control: efforts.length ? "effort" : "toggle",
      efforts,
      defaultEffort: claude?.defaultEffort ?? "high",
      canDisable: !claude?.alwaysOnThinking,
      alwaysOn: claude?.alwaysOnThinking,
      defaultEnabled: !!claude,
      transport,
      thinking: adaptive ? "adaptive" : "budget",
    };
  }
  if (provider === "google") {
    if (["gemini-3-pro-preview"].includes(native))
      return effort("google", ["low", "high"], "high");
    if (
      [
        "gemini-3.1-pro-preview",
        "gemini-3.1-pro-preview-customtools",
        "gemini-3.8-flash",
        "gemini-4-argon",
      ].includes(native)
    )
      return effort(
        "google",
        BASIC,
        native.startsWith("gemini-3.1") ? "high" : "medium",
      );
    if (
      [
        "gemini-3-flash-preview",
        "gemini-3.1-flash-lite-preview",
        "gemini-3.5-flash-lite",
        "gemini-3.6-flash",
      ].includes(native)
    )
      return effort(
        "google",
        ["minimal", ...BASIC],
        native.includes("lite")
          ? "minimal"
          : native === "gemini-3-flash-preview"
            ? "high"
            : "medium",
      );
    if (["gemini-2.5-flash", "gemini-2.5-flash-lite"].includes(native))
      return {
        control: "toggle",
        efforts: [],
        canDisable: true,
        transport: "google",
        thinking: "budget",
        defaultEnabled: native !== "gemini-2.5-flash-lite",
      };
    // Gemini 2.5 Pro requires thinking and exposes a budget, not an effort level.
    return UNKNOWN;
  }
  const transport = "openai";
  if (modelId === "concentrate:glm-5.3")
    return effort(transport, ["low", "high", "max"], "high");
  if (CONCENTRATE_REASONING_MODEL_IDS.has(modelId))
    return effort(transport, EXTENDED);
  if (!["openai", "pensar", "concentrate", "bedrock-mantle"].includes(provider))
    return UNKNOWN;
  if (
    [
      "gpt-6.1-sol",
      "gpt-6.1-terra",
      "gpt-6-astra",
      "gpt-5.6-sol",
      "gpt-5.6-terra",
      "gpt-5.6-luna",
    ].includes(native)
  )
    return effort(transport, EXTENDED);
  if (["gpt-6-sol", "gpt-6-luna"].includes(native))
    return effort(transport, ["none", ...EXTENDED]);
  if (["gpt-5.2-pro", "gpt-5.4-pro", "gpt-5.5-pro"].includes(native))
    return effort(transport, ["medium", "high", "xhigh"]);
  if (["gpt-5-pro", "o3-pro"].includes(native))
    return effort(transport, ["high"], "high");
  if (
    ["gpt-5.2", "gpt-5.4", "gpt-5.5", "gpt-5.4-mini", "gpt-5.4-nano"].includes(
      native,
    )
  )
    return effort(transport, [
      "none",
      ...BASIC,
      ...(provider === "concentrate" && /-(mini|nano)$/.test(native)
        ? []
        : ["xhigh" as const]),
    ]);
  if (native === "gpt-5.1") return effort(transport, ["none", ...BASIC]);
  if (["gpt-5", "gpt-5-mini", "gpt-5-nano"].includes(native))
    return effort(transport, ["minimal", ...BASIC]);
  if (
    [
      "o1",
      "o3",
      "o3-mini",
      "o4-mini",
      "gpt-5-codex",
      "gpt-5.1-codex",
      "gpt-5.1-codex-mini",
    ].includes(native)
  )
    return effort(transport, BASIC);
  if (["gpt-5.1-codex-max", "gpt-5.2-codex", "gpt-5.3-codex"].includes(native))
    return effort(transport, [...BASIC, "xhigh"]);
  return UNKNOWN;
}

export function getReasoningChoices(
  capabilities: ReasoningCapabilities,
): ReasoningSetting[] {
  if (capabilities.control === "none") return [];
  if (capabilities.control === "toggle")
    return [
      "default",
      "enabled",
      ...(capabilities.canDisable ? ["disabled" as const] : []),
    ];
  return [
    "default",
    ...capabilities.efforts,
    ...(capabilities.canDisable && !capabilities.efforts.includes("none")
      ? ["disabled" as const]
      : []),
  ];
}

export function validateReasoningSetting(
  model: string,
  value: string,
  customProviders?: CustomProviders,
): ReasoningSetting {
  const choices = getReasoningChoices(
    getReasoningCapabilities(model, customProviders),
  );
  if (value === "default" || choices.includes(value as ReasoningSetting))
    return value as ReasoningSetting;
  throw new Error(
    `Reasoning setting "${value}" is not supported by ${model}. Supported settings: ${["default", ...choices.filter((choice) => choice !== "default")].join(", ")}.`,
  );
}

export function buildModelReasoningOptions(
  model: string,
  setting: ReasoningSetting,
  options: { customProviders?: CustomProviders; maxOutputTokens?: number } = {},
): ReasoningProviderOptions | undefined {
  const cap = getReasoningCapabilities(model, options.customProviders);
  validateReasoningSetting(model, setting, options.customProviders);
  if (cap.control === "none") return undefined;
  if (
    setting === "default" &&
    cap.transport === "openrouter" &&
    cap.defaultEffort === undefined &&
    cap.defaultEnabled === undefined
  )
    return undefined;
  if (setting === "default" && cap.defaultEnabled === false)
    return buildModelReasoningOptions(
      model,
      cap.efforts.includes("none") ? "none" : "disabled",
      options,
    );
  const budgetTokens =
    options.maxOutputTokens === undefined
      ? 10_000
      : Math.min(10_000, Math.floor(options.maxOutputTokens / 2));
  if (
    cap.thinking === "budget" &&
    cap.transport !== "google" &&
    setting !== "disabled" &&
    budgetTokens < 1024
  )
    throw new Error(
      "Extended thinking requires an output limit of at least 2048 tokens.",
    );
  const disabled = setting === "disabled" || setting === "none";
  const selectedEffort =
    setting === "default" || setting === "enabled"
      ? cap.defaultEffort
      : disabled
        ? undefined
        : setting;
  if (cap.transport === "openrouter") {
    return {
      openrouter: {
        reasoning: disabled
          ? {
              enabled: false,
              ...(cap.efforts.includes("none") ? { effort: "none" } : {}),
            }
          : {
              enabled: true,
              ...(selectedEffort ? { effort: selectedEffort } : {}),
              ...(cap.thinking === "budget"
                ? { max_tokens: budgetTokens }
                : {}),
            },
      },
    };
  }
  if (cap.transport === "openai")
    return {
      openai: {
        reasoningEffort: disabled ? "none" : selectedEffort,
        ...(model.startsWith("custom:") ? { forceReasoning: true } : {}),
      },
    };
  if (cap.transport === "google")
    return {
      google: {
        thinkingConfig:
          cap.thinking === "budget"
            ? { thinkingBudget: disabled ? 0 : -1, includeThoughts: !disabled }
            : { thinkingLevel: selectedEffort, includeThoughts: true },
      },
    };
  const thinking = disabled
    ? { type: "disabled" }
    : cap.thinking === "budget"
      ? { type: "enabled", budgetTokens }
      : { type: "adaptive", display: "summarized" };
  const anthropic = {
    thinking,
    ...(!disabled && cap.control === "effort"
      ? { effort: selectedEffort }
      : {}),
  };
  if (cap.transport === "bedrock")
    return {
      anthropic,
      bedrock: {
        reasoningConfig: {
          ...thinking,
          ...(!disabled && cap.control === "effort"
            ? { maxReasoningEffort: selectedEffort }
            : {}),
        },
        ...(disabled
          ? { additionalModelRequestFields: { thinking: { type: "disabled" } } }
          : {}),
      },
    };
  return { anthropic };
}
