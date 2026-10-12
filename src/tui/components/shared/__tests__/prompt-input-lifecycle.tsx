import assert from "node:assert/strict";
import type { KeyEvent } from "@opentui/core";
import { testRender } from "@opentui/react/test-utils";
import { act, createRef } from "react";
import { FocusProvider } from "../../../context/focus";
import { InputProvider } from "../../../context/input";
import { registerBuiltinThemes, ThemeProvider } from "../../../theme";
import { PromptInput, type PromptInputRef } from "../prompt-input";

const scenario = process.argv[2];
const exitDuringKey = scenario.endsWith("after-exit");
const prompt = createRef<PromptInputRef>();
const errors: unknown[][] = [];
const originalError = console.error;
console.error = (...args: unknown[]) => errors.push(args);
registerBuiltinThemes();

const { renderer, mockInput } = await testRender(
  <ThemeProvider>
    <InputProvider>
      <FocusProvider>
        <PromptInput ref={prompt} commandHistory={["previous command"]} />
      </FocusProvider>
    </InputProvider>
  </ThemeProvider>,
  { width: 80, height: 24, exitOnCtrlC: false },
);

try {
  await act(async () => prompt.current?.setValue("unsent input"));
  const textarea = prompt.current?.getTextareaRef();
  assert.ok(textarea);
  assert.equal(textarea.plainText, "unsent input");

  if (exitDuringKey) {
    // Exit can destroy native buffers before the listener snapshot finishes.
    renderer.keyInput.prependOnceListener("keypress", (_key: KeyEvent) => {
      renderer.destroy();
      assert.equal(textarea.isDestroyed, true);
    });
  }

  await act(async () => {
    if (scenario.startsWith("history")) mockInput.pressArrow("up");
    else mockInput.pressCtrlC();
  });

  if (!exitDuringKey) {
    const expected = scenario === "clear-input" ? "" : "previous command";
    assert.equal(textarea.plainText, expected);
    assert.equal(prompt.current?.getValue(), expected);
    assert.equal(renderer.isDestroyed, false);
  } else {
    assert.equal(renderer.isDestroyed, true);
  }
  assert.deepEqual(
    errors,
    [],
    "Keyboard handling must not touch destroyed buffers",
  );
} finally {
  await act(async () => renderer.destroy());
  console.error = originalError;
}
