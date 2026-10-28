import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { resolveModelRuntimeProfile } from "./modelRuntime";

beforeEach(() => vi.stubEnv("APEX_CODE_MODE", ""));
afterEach(() => vi.unstubAllEnvs());

describe("resolveModelRuntimeProfile", () => {
  it("supports the environment opt-out and explicit per-agent overrides", () => {
    vi.stubEnv("APEX_CODE_MODE", "off");
    expect(resolveModelRuntimeProfile("gpt-5.5").protocol).toBe("direct");
    expect(resolveModelRuntimeProfile("gpt-5.5", "schema-code").protocol).toBe(
      "schema-code",
    );
    vi.stubEnv("APEX_CODE_MODE", "invalid");
    expect(() => resolveModelRuntimeProfile("gpt-5.5")).toThrow(
      "Invalid APEX_CODE_MODE",
    );
  });
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

  it("uses schema code mode for GLM-5 models on OpenRouter", () => {
    expect(resolveModelRuntimeProfile("z-ai/glm-5.2").protocol).toBe(
      "schema-code",
    );
    expect(resolveModelRuntimeProfile("z-ai/glm-5.3").protocol).toBe(
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
