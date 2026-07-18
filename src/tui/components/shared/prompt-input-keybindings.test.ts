import { describe, expect, it } from "vitest";
import {
  CHAT_KEY_BINDINGS,
  isChatNewlineKey,
} from "./prompt-input-keybindings";

function actionFor(
  name: string,
  modifiers: { shift?: boolean; ctrl?: boolean } = {},
) {
  return CHAT_KEY_BINDINGS.find(
    (binding) =>
      binding.name === name &&
      Boolean(binding.shift) === Boolean(modifiers.shift) &&
      Boolean(binding.ctrl) === Boolean(modifiers.ctrl),
  )?.action;
}

describe("CHAT_KEY_BINDINGS", () => {
  it("submits with Enter and keypad Enter", () => {
    expect(actionFor("return")).toBe("submit");
    expect(actionFor("kpenter")).toBe("submit");
  });

  it("inserts a newline with Shift+Enter", () => {
    expect(actionFor("return", { shift: true })).toBe("newline");
    expect(actionFor("kpenter", { shift: true })).toBe("newline");
    expect(actionFor("linefeed", { shift: true })).toBe("newline");
  });

  it("retains linefeed as the Ctrl+J-compatible newline", () => {
    expect(actionFor("linefeed")).toBe("newline");
  });

  it("normalizes shifted Enter names emitted by supported terminal protocols", () => {
    expect(isChatNewlineKey({ name: "return", shift: true })).toBe(true);
    expect(isChatNewlineKey({ name: "enter", shift: true })).toBe(true);
    expect(isChatNewlineKey({ name: "kpenter", shift: true })).toBe(true);
    expect(isChatNewlineKey({ name: "linefeed", shift: true })).toBe(true);
    expect(isChatNewlineKey({ name: "return", raw: "\u001b[13;2u" })).toBe(
      true,
    );
    expect(isChatNewlineKey({ name: "return", raw: "\u001b[27;2;13~" })).toBe(
      true,
    );
    expect(isChatNewlineKey({ name: "return" })).toBe(false);
  });

  it("supports the modified Enter fallbacks used by OpenCode", () => {
    expect(isChatNewlineKey({ name: "return", ctrl: true })).toBe(true);
    expect(isChatNewlineKey({ name: "return", meta: true })).toBe(true);
    expect(actionFor("return", { ctrl: true })).toBe("newline");
    expect(
      CHAT_KEY_BINDINGS.find(
        (binding) => binding.name === "return" && binding.meta,
      )?.action,
    ).toBe("newline");
  });
});
