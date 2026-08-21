import { describe, expect, it } from "vitest";
import {
  chatKeyBindings,
  redirectKeyBindings,
} from "../shared/text-input-keybindings";

function actionFor(
  bindings: typeof chatKeyBindings,
  name: string,
  shift = false,
) {
  return bindings.find(
    (binding) => binding.name === name && !!binding.shift === shift,
  )?.action;
}

describe("operator input keybindings", () => {
  it("submits on Enter and inserts a newline on Shift+Enter in the normal prompt", () => {
    expect(actionFor(chatKeyBindings, "return")).toBe("submit");
    expect(actionFor(chatKeyBindings, "enter")).toBe("submit");
    expect(actionFor(chatKeyBindings, "return", true)).toBe("newline");
    expect(actionFor(chatKeyBindings, "enter", true)).toBe("newline");
  });

  it("submits on Enter and inserts a newline on Shift+Enter in approval redirect input", () => {
    expect(actionFor(redirectKeyBindings, "return")).toBe("submit");
    expect(actionFor(redirectKeyBindings, "enter")).toBe("submit");
    expect(actionFor(redirectKeyBindings, "return", true)).toBe("newline");
    expect(actionFor(redirectKeyBindings, "enter", true)).toBe("newline");
  });
});
