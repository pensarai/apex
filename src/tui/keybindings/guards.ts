export interface PromptSensitiveShortcutContext {
  combo: string;
  isPromptFocused: boolean;
  promptValue: string;
}

/**
 * Global shortcuts that can conflict with prompt typing should only run when
 * the prompt is focused and currently empty.
 */
export function shouldHandlePromptSensitiveShortcut({
  combo,
  isPromptFocused,
  promptValue,
}: PromptSensitiveShortcutContext): boolean {
  const normalizedCombo = combo.toLowerCase();
  const isPromptSensitive =
    normalizedCombo.startsWith("shift") || normalizedCombo === "?";

  if (!isPromptSensitive) {
    return true;
  }

  return isPromptFocused && promptValue.trim().length === 0;
}
