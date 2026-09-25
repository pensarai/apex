import { describe, expect, it } from "vitest";
import { resolveModelRuntimeProfile } from "./modelRuntime";

describe("resolveModelRuntimeProfile", () => {
  it("uses native code mode for any OpenAI Responses model", () => {
    expect(resolveModelRuntimeProfile("gpt-5.6-sol").protocol).toBe(
      "native-code",
    );
    expect(resolveModelRuntimeProfile("gpt-5.5").protocol).toBe("native-code");
  });

  it("uses schema code mode for Opus 4.8 on Bedrock", () => {
    expect(
      resolveModelRuntimeProfile("us.anthropic.claude-opus-4-8").protocol,
    ).toBe("schema-code");
  });

  it("uses schema code mode for GLM-5.2 on OpenRouter", () => {
    expect(resolveModelRuntimeProfile("z-ai/glm-5.2").protocol).toBe(
      "schema-code",
    );
  });

  it("uses the portable schema protocol for unknown and local models", () => {
    expect(resolveModelRuntimeProfile("local-model").protocol).toBe(
      "schema-code",
    );
  });

  it("allows forcing schema code mode for any provider", () => {
    expect(
      resolveModelRuntimeProfile("local-model", "schema-code").protocol,
    ).toBe("schema-code");
  });

  it("rejects native code mode outside OpenAI", () => {
    expect(() =>
      resolveModelRuntimeProfile("z-ai/glm-5.2", "native-code"),
    ).toThrow("native-code requires the OpenAI Responses provider");
  });
});
