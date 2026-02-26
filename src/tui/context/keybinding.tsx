import type { KeyEvent } from "@opentui/core";
import { useKeyboard } from "@opentui/react";
import { createContext, useContext, type ReactNode } from "react";
import {
  useKeybindings,
  Keybind,
  type KeybindingEntry,
  type UseKeybindingsOptions,
} from "../keybindings";
import { useInput } from "./input";
import { useFocus } from "./focus";

export type { KeybindingEntry };

interface KeybindingContextType {
  registry: KeybindingEntry[];
}

const KeybindingContext = createContext<KeybindingContextType | undefined>(
  undefined,
);

export function KeybindingProvider({
  children,
  options,
}: {
  children: ReactNode;
  options?: UseKeybindingsOptions;
}) {
  const { promptRef } = useFocus();
  const { isInputEmpty } = useInput();

  const registry = useKeybindings(options);

  useKeyboard((key: KeyEvent) => {
    const pressedKey = Keybind.fromParsedKey(key);

    for (const binding of registry) {
      const parsedCombos = Keybind.parse(binding.combo);

      for (const combo of parsedCombos) {
        if (Keybind.matches(pressedKey, combo)) {
          // If combo starts with "shift", require input to be focused and empty
          if (
            binding.combo.toLowerCase().startsWith("shift") ||
            binding.combo.toLowerCase() === "?"
          ) {
            const textareaRef = promptRef.current?.getTextareaRef();
            const isInputFocused =
              textareaRef && !textareaRef.isDestroyed && textareaRef.focused;

            if (!isInputFocused || !isInputEmpty) {
              continue;
            }
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
