import { describe, expect, it } from "vitest";
import { parseLanceBudget } from "./lance-budget";

describe("Lance CLI budget", () => {
  it("leaves the default to the runtime and accepts each explicit budget", () => {
    expect(parseLanceBudget(["--lance"])).toEqual({});
    expect(parseLanceBudget(["--lance", "--max-steps", "5000"])).toEqual({
      budget: { kind: "steps", limit: 5000 },
    });
    expect(parseLanceBudget(["--lance", "--max-tokens", "1000000"])).toEqual({
      budget: { kind: "tokens", limit: 1000000 },
    });
    expect(parseLanceBudget(["--lance", "--timeout-ms", "3600000"])).toEqual({
      timeoutMs: 3600000,
    });
  });
  it.each([
    ["--lance", "--max-steps"],
    ["--lance", "--max-steps", "0"],
    ["--lance", "--max-tokens", "1.5"],
    ["--lance", "--timeout-ms", "Infinity"],
    ["--lance", "--timeout-ms", "2147483648"],
    ["--lance", "--deadline-at", "1"],
    ["--max-steps", "50"],
    ["--lance", "--max-steps", "50", "--max-tokens", "1000"],
    ["--lance", "--max-tokens", "50", "--timeout-ms", "1000"],
    ["--lance", "--max-steps", "50", "--max-steps", "100"],
  ])("rejects malformed or conflicting arguments: %j", (...args) => {
    expect(() => parseLanceBudget(args)).toThrow();
  });
});
