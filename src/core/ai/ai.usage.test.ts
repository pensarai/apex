import { describe, expect, it } from "vitest";
import { getUsageCacheDetails } from "./ai";

describe("getUsageCacheDetails", () => {
  it("uses normalized AI SDK cache details for OpenRouter and Bedrock", () => {
    expect(
      getUsageCacheDetails({
        inputTokenDetails: {
          cacheReadTokens: 900,
          cacheWriteTokens: 100,
        },
      }),
    ).toEqual({
      cacheReadTokens: 900,
      cacheWriteTokens: 100,
    });
  });

  it("falls back to Anthropic provider metadata", () => {
    expect(
      getUsageCacheDetails(undefined, {
        anthropic: {
          cacheReadInputTokens: 700,
          cacheCreationInputTokens: 80,
        },
      }),
    ).toEqual({
      cacheReadTokens: 700,
      cacheWriteTokens: 80,
    });
  });
});
