import { describe, expect, it } from "vitest";
import { checkIfRetryableProviderError } from "./ai";

describe("checkIfRetryableProviderError", () => {
  it("recognizes the numeric OpenRouter 429 shape", () => {
    expect(
      checkIfRetryableProviderError({
        code: 429,
        message: "Provider returned error",
        metadata: { error_type: "rate_limit_exceeded" },
      }),
    ).toBe(true);
  });

  it("recognizes the OpenRouter gateway timeout shape", () => {
    expect(
      checkIfRetryableProviderError({
        code: 504,
        message: "The operation was aborted",
        metadata: { error_type: "timeout" },
      }),
    ).toBe(true);
  });

  it("walks provider causes and response metadata", () => {
    expect(
      checkIfRetryableProviderError({
        message: "Provider returned error",
        cause: {
          response: { status: 429 },
          data: { error: { type: "rate_limit_exceeded" } },
        },
      }),
    ).toBe(true);
  });

  it("does not retry permanent request errors or local cancellation", () => {
    expect(
      checkIfRetryableProviderError({
        code: 400,
        message: "Invalid tool schema",
      }),
    ).toBe(false);

    expect(
      checkIfRetryableProviderError({
        name: "AbortError",
        message: "The operation was aborted",
      }),
    ).toBe(false);
  });
});
