import { describe, expect, it } from "vitest";
import { parseReasoningEffort } from "./reasoningEffort";

describe("parseReasoningEffort", () => {
  it("preserves an explicit high effort request", () => {
    expect(parseReasoningEffort("high")).toBe("high");
  });

  it("leaves an omitted effort unset", () => {
    expect(parseReasoningEffort(undefined)).toBeUndefined();
  });

  it("rejects unsupported effort names", () => {
    expect(() => parseReasoningEffort("minimal")).toThrow(
      "--reasoning-effort must be one of",
    );
  });
});
