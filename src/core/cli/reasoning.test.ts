import { describe, expect, it } from "vitest";
import { buildReasoningProviderOptions } from "../ai";
import type { Config } from "../config/config";
import { getSavedReasoning, resolveCliReasoning } from "./reasoning";

describe("CLI reasoning selection", () => {
  it.each([
    ["concentrate:glm-5.3", "none", "low"],
    ["concentrate:glm-5.3", "minimal", "max"],
    ["concentrate:glm-5.3", "low", "low"],
    ["concentrate:glm-5.3", "medium", "high"],
    ["concentrate:glm-5.3", "high", "high"],
    ["concentrate:glm-5.3", "xhigh", "max"],
    ["concentrate:glm-5.3", "max", "max"],
    ["concentrate:glm-5.3", "ultra", "max"],
    ["gpt-6.1-sol", "ultra", "max"],
    ["gpt-5", "xhigh", "medium"],
  ] as const)("migrates %s / %s to %s identically to the API", (model, legacy, expected) => {
    const reasoning = getSavedReasoning(model, {
      openAIReasoningEffort: legacy,
    });
    expect(reasoning).toBe(expected);
    expect(buildReasoningProviderOptions(model, { reasoning })).toEqual(
      buildReasoningProviderOptions(model, { openAIReasoningEffort: legacy }),
    );
  });
  it.each([
    "claude-sonnet-4-5",
    "claude-opus-5-5",
    "anthropic/claude-opus-4.6",
  ])("migrates the %s thinking toggle identically to the API", (model) => {
    for (const enabled of [true, false]) {
      const reasoning = getSavedReasoning(model, { reasoningEnabled: enabled });
      expect(buildReasoningProviderOptions(model, { reasoning })).toEqual(
        buildReasoningProviderOptions(model, { enableThinking: enabled }),
      );
    }
  });
  it("keeps explicit canonical values ahead of legacy migration and rejects invalid new selections", () => {
    const model = "concentrate:glm-5.3";
    const config: Pick<Config, "modelReasoning" | "openAIReasoningEffort"> = {
      modelReasoning: { [model]: "low" },
      openAIReasoningEffort: "xhigh",
    };
    const reasoning = getSavedReasoning(model, config);
    expect(reasoning).toBe("low");
    expect(
      buildReasoningProviderOptions(model, {
        reasoning,
        openAIReasoningEffort: "xhigh",
      }),
    ).toEqual(
      buildReasoningProviderOptions(model, { openAIReasoningEffort: "low" }),
    );
    expect(() =>
      resolveCliReasoning(["--effort", "xhigh"], model, config),
    ).toThrow("not supported");
    expect(() =>
      buildReasoningProviderOptions(model, { reasoning: "xhigh" }),
    ).toThrow("not supported");
  });
  it("gives an invocation precedence over the saved per-model preference", () => {
    expect(
      resolveCliReasoning(["--effort", "low"], "claude-opus-5-5", {
        modelReasoning: { "claude-opus-5-5": "max" },
      }),
    ).toBe("low");
    expect(resolveCliReasoning(["--effort=high"], "gpt-6.1-sol", {})).toBe(
      "high",
    );
  });
  it("does not carry incompatible settings between models", () => {
    const config = { modelReasoning: { "gpt-6.1-sol": "max" as const } };
    expect(getSavedReasoning("gemini-3-pro-preview", config)).toBe("default");
    expect(getSavedReasoning("gpt-6.1-sol", config)).toBe("max");
  });
  it("migrates supported legacy preferences without offering the ultra alias", () => {
    expect(
      getSavedReasoning("gpt-6.1-sol", { openAIReasoningEffort: "ultra" }),
    ).toBe("max");
    expect(
      getSavedReasoning("claude-sonnet-4-5", { reasoningEnabled: true }),
    ).toBe("enabled");
    expect(
      getSavedReasoning("anthropic/claude-opus-4.6", {
        reasoningEnabled: true,
      }),
    ).toBe("high");
    expect(
      getSavedReasoning("anthropic/claude-opus-4.6", {
        reasoningEnabled: false,
      }),
    ).toBe("none");
  });
  it.each([
    ["--effort"],
    ["--effort", "--model"],
    ["--effort", "ultra"],
    ["--effort", "none"],
    ["--effort", "low", "--extended-thinking"],
  ])("rejects invalid flags before execution: %j", (...args) => {
    expect(() => resolveCliReasoning(args, "gpt-6.1-sol", {})).toThrow();
  });
  it("uses a toggle only where the model supports it", () => {
    expect(
      resolveCliReasoning(["--extended-thinking"], "claude-sonnet-4-5", {}),
    ).toBe("enabled");
    expect(
      resolveCliReasoning(["--no-extended-thinking"], "gemini-2.5-flash", {}),
    ).toBe("disabled");
    expect(() =>
      resolveCliReasoning(["--no-extended-thinking"], "claude-opus-5-5", {}),
    ).toThrow();
    expect(() =>
      resolveCliReasoning(["--extended-thinking"], "unknown", {}),
    ).toThrow();
  });
});
