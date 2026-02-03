import { createContext, useContext, useRef, useCallback, type ReactNode } from "react";
import type { PromptInputRef } from "../components/shared/prompt-input";

interface FocusContextType {
  promptRef: React.MutableRefObject<PromptInputRef | null>;
  // Existing
  refocusPrompt: () => void;
  // Ref control methods
  focusPrompt: () => void;
  blurPrompt: () => void;
  resetPrompt: () => void;
  setPromptValue: (value: string) => void;
  getPromptValue: () => string;
  registerPromptRef: (ref: PromptInputRef | null) => void;
}

const FocusContext = createContext<FocusContextType | undefined>(undefined);

export function FocusProvider({ children }: { children: ReactNode }) {
  const promptRef = useRef<PromptInputRef | null>(null);

  const refocusPrompt = useCallback(() => {
    setTimeout(() => {
      promptRef.current?.focus();
    }, 1);
  }, []);

  const focusPrompt = useCallback(() => promptRef.current?.focus(), []);
  const blurPrompt = useCallback(() => promptRef.current?.blur(), []);
  const resetPrompt = useCallback(() => promptRef.current?.reset(), []);
  const setPromptValue = useCallback((value: string) => promptRef.current?.setValue(value), []);
  const getPromptValue = useCallback(() => promptRef.current?.getValue() ?? "", []);
  const registerPromptRef = useCallback((ref: PromptInputRef | null) => {
    promptRef.current = ref;
  }, []);

  return (
    <FocusContext.Provider
      value={{
        promptRef,
        refocusPrompt,
        focusPrompt,
        blurPrompt,
        resetPrompt,
        setPromptValue,
        getPromptValue,
        registerPromptRef,
      }}
    >
      {children}
    </FocusContext.Provider>
  );
}

export function useFocus() {
  const context = useContext(FocusContext);
  if (!context) {
    throw new Error("useFocus must be used within FocusProvider");
  }
  return context;
}
