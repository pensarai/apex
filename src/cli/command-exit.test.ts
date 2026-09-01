import { afterEach, describe, expect, it } from "vitest";
import { markCommandFailed } from "./command-exit";

const originalExitCode = process.exitCode;

afterEach(() => {
  process.exitCode = originalExitCode;
});

describe("markCommandFailed", () => {
  it("records failure without terminating the process", () => {
    expect(markCommandFailed()).toBeUndefined();
    expect(process.exitCode).toBe(1);
  });
});
