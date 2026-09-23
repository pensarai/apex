import { describe, expect, it } from "vitest";
import { extractNativeSamplingEvidence } from "./provider-metadata";

describe("extractNativeSamplingEvidence", () => {
  it("preserves already-exposed OpenAI logprobs without requesting them", () => {
    const evidence = extractNativeSamplingEvidence({
      provider: "openai.chat",
      providerMetadata: {
        openai: {
          responseId: "response-1",
          logprobs: [
            {
              token: "A",
              logprob: 0,
              top_logprobs: [{ token: "B", logprob: -1 }],
            },
            [
              {
                token: "B",
                logprob: -0.25,
                top_logprobs: [],
              },
            ],
          ],
        },
      },
    });

    expect(evidence.logprobs).toEqual({
      state: "available",
      value: [0, -0.25],
    });
    expect(evidence.extra).toMatchObject({
      state: "available",
      value: {
        schema: "pensar.native_rollout_provider_extra.openai",
        provider: "openai.chat",
        value: { responseId: "response-1" },
      },
    });
    expect(evidence.promptTokenIds.state).toBe("unsupported");
    expect(evidence.completionTokenIds.state).toBe("unsupported");
  });

  it("distinguishes OpenAI omission from an unsupported provider", () => {
    expect(
      extractNativeSamplingEvidence({ provider: "openai.responses" }).logprobs,
    ).toMatchObject({ state: "omitted" });
    expect(
      extractNativeSamplingEvidence({ provider: "anthropic.messages" })
        .logprobs,
    ).toMatchObject({ state: "unsupported" });
  });

  it("preserves explicit empty OpenAI logprob collections", () => {
    expect(
      extractNativeSamplingEvidence({
        provider: "openai.chat",
        providerMetadata: { openai: { logprobs: [] } },
      }).logprobs,
    ).toEqual({ state: "available", value: [] });
    expect(
      extractNativeSamplingEvidence({
        provider: "openai.responses",
        providerMetadata: { openai: { logprobs: { content: [] } } },
      }).logprobs,
    ).toEqual({ state: "available", value: [] });
  });

  it("does not turn malformed native metadata into fabricated values", () => {
    const evidence = extractNativeSamplingEvidence({
      provider: "openai.chat",
      providerMetadata: {
        openai: {
          logprobs: [
            { token: "A", logprob: Number.NaN },
            { token: "B", logprob: "-1" },
          ],
        },
      },
    });

    expect(evidence.logprobs).toMatchObject({ state: "omitted" });
  });
});
