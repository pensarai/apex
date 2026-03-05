import { describe, expect, it } from "vitest";
import { shouldHandlePromptSensitiveShortcut } from "./guards";

describe("shouldHandlePromptSensitiveShortcut", () => {
  it("blocks ? when prompt has content", () => {
    const shouldHandle = shouldHandlePromptSensitiveShortcut({
      combo: "?",
      isPromptFocused: true,
      promptValue: "hello",
    });

    expect(shouldHandle).toBe(false);
  });

  it("allows ? when prompt is focused and empty", () => {
    const shouldHandle = shouldHandlePromptSensitiveShortcut({
      combo: "?",
      isPromptFocused: true,
      promptValue: "   ",
    });

    expect(shouldHandle).toBe(true);
  });

  it("blocks shift shortcuts when prompt is not focused", () => {
    const shouldHandle = shouldHandlePromptSensitiveShortcut({
      combo: "shift+tab",
      isPromptFocused: false,
      promptValue: "",
    });

    expect(shouldHandle).toBe(false);
  });

  it("allows non prompt-sensitive shortcuts regardless of prompt state", () => {
    const shouldHandle = shouldHandlePromptSensitiveShortcut({
      combo: "ctrl+s",
      isPromptFocused: false,
      promptValue: "non-empty",
    });

    expect(shouldHandle).toBe(true);
  });
});
