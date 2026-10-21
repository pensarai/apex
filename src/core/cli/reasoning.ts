import {
  getReasoningCapabilities,
  getReasoningChoices,
  type ReasoningEffort,
  type ReasoningSetting,
  resolveReasoningSetting,
  validateReasoningSetting,
} from "../ai";
import type { Config } from "../config/config";

export function getSavedReasoning(
  model: string,
  config: Pick<
    Config,
    | "modelReasoning"
    | "customProviders"
    | "openAIReasoningEffort"
    | "reasoningEnabled"
  >,
): ReasoningSetting | undefined {
  const cap = getReasoningCapabilities(model, config.customProviders);
  const saved = config.modelReasoning?.[model];
  if (saved !== undefined)
    return getReasoningChoices(cap).includes(saved) ? saved : "default";
  if (cap.control === "none") return undefined;
  return (
    resolveReasoningSetting(
      model,
      {
        enableThinking: config.reasoningEnabled,
        openAIReasoningEffort: config.openAIReasoningEffort,
        customProviders: config.customProviders,
      },
      "model",
    ) ?? "default"
  );
}

export function resolveCliReasoning(
  args: string[],
  model: string,
  config: Pick<
    Config,
    | "modelReasoning"
    | "customProviders"
    | "openAIReasoningEffort"
    | "reasoningEnabled"
  >,
): ReasoningSetting | undefined {
  const index = args.findIndex(
    (arg) => arg === "--effort" || arg.startsWith("--effort="),
  );
  const enable = args.includes("--extended-thinking");
  const disable = args.includes("--no-extended-thinking");
  if (Number(index >= 0) + Number(enable) + Number(disable) > 1)
    throw new Error(
      "Use only one of --effort, --extended-thinking, or --no-extended-thinking.",
    );
  if (index >= 0) {
    const value = args[index].startsWith("--effort=")
      ? args[index].slice("--effort=".length)
      : args[index + 1];
    if (!value || value.startsWith("--"))
      throw new Error("--effort requires a level or default.");
    const cap = getReasoningCapabilities(model, config.customProviders);
    if (
      value !== "default" &&
      (cap.control !== "effort" ||
        !cap.efforts.includes(value as ReasoningEffort))
    )
      throw new Error(
        `--effort is not supported at "${value}" for ${model}. Available levels: ${["default", ...cap.efforts].join(", ")}.`,
      );
    return validateReasoningSetting(model, value, config.customProviders);
  }
  if (enable || disable) {
    const cap = getReasoningCapabilities(model, config.customProviders);
    if (cap.control === "none")
      throw new Error(
        `Thinking controls are not known for ${model}; use the model default.`,
      );
    return validateReasoningSetting(
      model,
      enable
        ? cap.control === "effort"
          ? (cap.defaultEffort ?? "default")
          : "enabled"
        : cap.efforts.includes("none")
          ? "none"
          : "disabled",
      config.customProviders,
    );
  }
  return getSavedReasoning(model, config);
}
