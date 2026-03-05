import { describe, expect, it } from "vitest";
import {
  isTerminalCopyShortcut,
  shouldHandleOperatorCtrlC,
} from "./keyboard";

describe("operator dashboard keyboard helpers", () => {
  it("detects terminal copy shortcuts", () => {
    expect(
      isTerminalCopyShortcut({
        name: "c",
        ctrl: false,
        meta: true,
        super: false,
      }),
    ).toBe(true);
    expect(
      isTerminalCopyShortcut({
        name: "c",
        ctrl: false,
        meta: false,
        super: true,
      }),
    ).toBe(true);
    expect(
      isTerminalCopyShortcut({
        name: "c",
        ctrl: true,
        meta: false,
        super: false,
      }),
    ).toBe(false);
  });

  it("handles Ctrl+C while running or waiting", () => {
    const ctrlC = { name: "c", ctrl: true, meta: false, super: false };
    expect(shouldHandleOperatorCtrlC(ctrlC, "running", "")).toBe(true);
    expect(shouldHandleOperatorCtrlC(ctrlC, "waiting", "")).toBe(true);
  });

  it("handles Ctrl+C for clearing non-empty input", () => {
    const ctrlC = { name: "c", ctrl: true, meta: false, super: false };
    expect(shouldHandleOperatorCtrlC(ctrlC, "idle", "has text")).toBe(true);
  });

  it("does not handle Ctrl+C when idle with empty input", () => {
    const ctrlC = { name: "c", ctrl: true, meta: false, super: false };
    expect(shouldHandleOperatorCtrlC(ctrlC, "idle", "")).toBe(false);
    expect(shouldHandleOperatorCtrlC(ctrlC, "idle", "   ")).toBe(false);
  });

  it("never handles command/super copy chords", () => {
    expect(
      shouldHandleOperatorCtrlC(
        { name: "c", ctrl: false, meta: true, super: false },
        "running",
        "text",
      ),
    ).toBe(false);
    expect(
      shouldHandleOperatorCtrlC(
        { name: "c", ctrl: false, meta: false, super: true },
        "waiting",
        "text",
      ),
    ).toBe(false);
  });
});
