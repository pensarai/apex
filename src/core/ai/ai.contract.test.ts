// Structural contract for the context-recovery state machine. No network.
import { describe, it, expect } from "vitest";
import { streamResponse, ContextLengthExhaustedError } from "./ai";

describe("streamResponse recovery-depth contract", () => {
  it("throws ContextLengthExhaustedError when _restartDepth exceeds the bound", () => {
    expect(() =>
      streamResponse({
        model: "claude-sonnet-4-5",
        prompt: "anything",
        _restartDepth: 10,
      }),
    ).toThrow(ContextLengthExhaustedError);
  });

  it("ContextLengthExhaustedError carries the depth that triggered it", () => {
    try {
      streamResponse({
        model: "claude-sonnet-4-5",
        prompt: "anything",
        _restartDepth: 7,
      });
      throw new Error("expected ContextLengthExhaustedError");
    } catch (err) {
      expect(err).toBeInstanceOf(ContextLengthExhaustedError);
      expect((err as ContextLengthExhaustedError).restartDepth).toBe(7);
      expect((err as ContextLengthExhaustedError).name).toBe(
        "ContextLengthExhaustedError",
      );
    }
  });

  it("does NOT throw the depth guard on the initial call", () => {
    // Other errors are fine (e.g. missing API key) — the guard mustn't fire.
    let thrown: unknown;
    try {
      streamResponse({ model: "claude-sonnet-4-5", prompt: "anything" });
    } catch (err) {
      thrown = err;
    }
    expect(thrown).not.toBeInstanceOf(ContextLengthExhaustedError);
  });
});
