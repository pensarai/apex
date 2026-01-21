import type { KeyEvent } from "@opentui/core";
import { useKeyboard } from "@opentui/react";
import { createContext, useContext, useState, type ReactNode } from "react";
import { createKeybindings, Keybind, type KeybindingDependencies, type KeybindingEntry } from "../keybindings";
import { useInput } from "./input";
import { useFocus } from "./focus";
import { useDialog } from "./dialog";

export type { KeybindingEntry };

interface KeybindingContextType {
    registry: KeybindingEntry[];
}

type ContextDeps = Omit<KeybindingDependencies, "refocusPrompt" | "setExternalDialogOpen">;

const KeybindingContext = createContext<KeybindingContextType | undefined>(undefined);

export function KeybindingProvider({
    children,
    deps
}: {
    children: ReactNode;
    deps: ContextDeps;
}) {

    const { promptRef, refocusPrompt } = useFocus();
    const { isInputEmpty } = useInput();
    const { setExternalDialogOpen } = useDialog();

    const registry = createKeybindings({
       ...deps,
       refocusPrompt,
       setExternalDialogOpen
    });

    useKeyboard((key: KeyEvent) => {
        const pressedKey = Keybind.fromParsedKey(key);

        for (const binding of registry) {
            const parsedCombos = Keybind.parse(binding.combo);

            for (const combo of parsedCombos) {
                if (Keybind.matches(pressedKey, combo)) {
                    // If combo starts with "shift", require input to be focused and empty
                    if (binding.combo.toLowerCase().startsWith("shift") || binding.combo.toLowerCase() === "?") {
                        const textareaRef = promptRef.current?.getTextareaRef();
                        const isInputFocused = textareaRef && !textareaRef.isDestroyed && textareaRef.focused;

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