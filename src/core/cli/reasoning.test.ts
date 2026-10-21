import { describe, expect, it } from "vitest";
import { getSavedReasoning, resolveCliReasoning } from "./reasoning";

describe("CLI reasoning selection", () => {
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
