import type { KeyEvent } from "@opentui/core";
import { useKeyboard } from "@opentui/react";
import { createContext, useContext, type ReactNode } from "react";
import {
  createKeybindings,
  fromParsedKey,
  parseKeybind,
  matchesKeybind,
  shouldHandlePromptSensitiveShortcut,
  type KeybindingDependencies,
  type KeybindingEntry,
} from "../keybindings";
import { useFocus } from "./focus";
import { useDialog } from "./dialog";

export type { KeybindingEntry };

interface KeybindingContextType {
  registry: KeybindingEntry[];
}

type ContextDeps = Omit<
  KeybindingDependencies,
  "refocusPrompt" | "setExternalDialogOpen"
>;

const KeybindingContext = createContext<KeybindingContextType | undefined>(
  undefined,
);

export function KeybindingProvider({
  children,
  deps,
}: {
  children: ReactNode;
  deps: ContextDeps;
}) {
  const { promptRef, refocusPrompt } = useFocus();
  const { setExternalDialogOpen } = useDialog();

  const registry = createKeybindings({
    ...deps,
    refocusPrompt,
    setExternalDialogOpen,
  });

  useKeyboard((key: KeyEvent) => {
    const pressedKey = fromParsedKey(key);

    for (const binding of registry) {
      const parsedCombos = parseKeybind(binding.combo);

      for (const combo of parsedCombos) {
        if (matchesKeybind(pressedKey, combo)) {
          // Prompt-sensitive shortcuts only run when prompt is focused + empty.
          const textareaRef = promptRef.current?.getTextareaRef();
          const isInputFocused = Boolean(
            textareaRef && !textareaRef.isDestroyed && textareaRef.focused,
          );
          const promptValue = promptRef.current?.getValue() ?? "";

          if (
            !shouldHandlePromptSensitiveShortcut({
              combo: binding.combo,
              isPromptFocused: isInputFocused,
              promptValue,
            })
          ) {
            continue;
          }

          // Execute the keybinding function
          binding.fn();
          return;
        }
      }
    }
  });

  return (
    <KeybindingContext.Provider value={{ registry }}>
      {children}
    </KeybindingContext.Provider>
  );
}

export function useKeybinding() {
  const context = useContext(KeybindingContext);
  if (!context) {
    throw new Error("useKeybinding must be used within KeybindingProvider");
  }
  return context;
}
