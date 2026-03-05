import type { KeyEvent } from "@opentui/core";
import { useKeyboard, useRenderer } from "@opentui/react";
import { createContext, useContext, type ReactNode } from "react";
import {
  createKeybindings,
  fromParsedKey,
  resolveKeybinding,
  type KeybindingRuntimeContext,
  type KeybindingDependencies,
  type KeybindingEntry,
} from "../keybindings";
import { useFocus } from "./focus";
import { useDialog } from "./dialog";
import { useRoute } from "./route";

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
  const { setExternalDialogOpen, stack, externalDialogOpen } = useDialog();
  const route = useRoute();
  const renderer = useRenderer();

  const registry = createKeybindings({
    ...deps,
    refocusPrompt,
    setExternalDialogOpen,
  });

  useKeyboard((key: KeyEvent) => {
    const pressedKey = fromParsedKey(key);
    const textareaRef = promptRef.current?.getTextareaRef();
    const isPromptFocused = Boolean(
      textareaRef && !textareaRef.isDestroyed && textareaRef.focused,
    );
    const promptValue = promptRef.current?.getValue() ?? "";

    const runtimeContext: KeybindingRuntimeContext = {
      routeType: route.data.type,
      routePath: route.data.type === "base" ? route.data.path : undefined,
      dialogStackDepth: stack.length,
      externalDialogOpen,
      isPromptFocused,
      promptValue,
    };

    const match = resolveKeybinding(registry, pressedKey, runtimeContext);
    if (!match) {
      return;
    }

    void match.handler({
      ...runtimeContext,
      route: route.data,
      navigate: route.navigate,
      toggleConsole: () => renderer.console.toggle(),
      clearPromptInput: () => {
        promptRef.current?.reset();
      },
      blurPrompt: () => {
        promptRef.current?.blur();
      },
      exitApp: () => {
        renderer.destroy();
        process.exit(0);
      },
    });
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
