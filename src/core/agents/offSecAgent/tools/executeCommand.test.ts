import { describe, expect, it } from "vitest";

import { normalizeExecuteCommandTimeout } from "./executeCommand";

describe("normalizeExecuteCommandTimeout", () => {
  it("preserves valid second-based timeouts", () => {
    expect(normalizeExecuteCommandTimeout(30)).toBe(30);
    expect(normalizeExecuteCommandTimeout(120)).toBe(120);
  });

  it("converts obvious millisecond values to seconds", () => {
    expect(normalizeExecuteCommandTimeout(30_000)).toBe(30);
    expect(normalizeExecuteCommandTimeout(100_000)).toBe(100);
    expect(normalizeExecuteCommandTimeout(120_000)).toBe(120);
  });

  it("drops invalid timeout values", () => {
    expect(normalizeExecuteCommandTimeout()).toBeUndefined();
    expect(normalizeExecuteCommandTimeout(0)).toBeUndefined();
    expect(normalizeExecuteCommandTimeout(-5)).toBeUndefined();
    expect(normalizeExecuteCommandTimeout(Number.NaN)).toBeUndefined();
  });
});
