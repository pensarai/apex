import { describe, expect, it } from "vitest";
import { resolveCtrlCAction } from "./ctrl-c";

describe("resolveCtrlCAction", () => {
  it("clears a non-empty focused composer", () => {
    expect(resolveCtrlCAction("draft", true, null, 2_000)).toBe("clear-input");
  });

  it("starts the exit chord when the composer is empty", () => {
    expect(resolveCtrlCAction("", true, null, 2_000)).toBe("warn-exit");
    expect(resolveCtrlCAction("draft", false, null, 2_000)).toBe("warn-exit");
  });

  it("exits on the second press within one second", () => {
    expect(resolveCtrlCAction("", true, 1_500, 2_000)).toBe("exit");
  });

  it("restarts the exit chord after the timeout", () => {
    expect(resolveCtrlCAction("", true, 500, 2_000)).toBe("warn-exit");
  });
});
