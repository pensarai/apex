import { describe, expect, it } from "vitest";
import { getUsageCacheDetails } from "./ai";

describe("getUsageCacheDetails", () => {
  it("reads the SDK's normalized inputTokenDetails", () => {
    expect(
      getUsageCacheDetails({
        inputTokenDetails: { cacheReadTokens: 24_000, cacheWriteTokens: 1_200 },
      }),
    ).toEqual({ cacheReadTokens: 24_000, cacheWriteTokens: 1_200 });
  });

  it("prefers normalized details over providerMetadata", () => {
    expect(
      getUsageCacheDetails(
        {
          inputTokenDetails: { cacheReadTokens: 10, cacheWriteTokens: 20 },
        },
        {
          anthropic: { cacheReadInputTokens: 99, cacheCreationInputTokens: 98 },
        },
      ),
    ).toEqual({ cacheReadTokens: 10, cacheWriteTokens: 20 });
  });

  it("falls back to Anthropic providerMetadata when details are absent", () => {
    expect(
      getUsageCacheDetails(
        { inputTokenDetails: {} },
        {
          anthropic: {
            cacheReadInputTokens: 8_000,
            cacheCreationInputTokens: 512,
          },
        },
      ),
    ).toEqual({ cacheReadTokens: 8_000, cacheWriteTokens: 512 });
  });

  it("ignores providerMetadata from other providers", () => {
    expect(
      getUsageCacheDetails(undefined, {
        openai: { cachedPromptTokens: 4_000 },
      }),
    ).toEqual({ cacheReadTokens: 0, cacheWriteTokens: 0 });
  });

  it("returns zeros when usage is absent", () => {
    expect(getUsageCacheDetails(undefined)).toEqual({
      cacheReadTokens: 0,
      cacheWriteTokens: 0,
    });
  });
});
