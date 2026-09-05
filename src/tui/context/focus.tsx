import { useRenderer } from "@opentui/react";
import {
  createContext,
  type ReactNode,
  useCallback,
  useContext,
  useRef,
} from "react";
import type { PromptInputRef } from "../components/shared";
import { shouldRefocusPrompt } from "./focus-ownership";

interface FocusContextType {
  promptRef: React.MutableRefObject<PromptInputRef | null>;
  refocusPrompt: () => void;
  refocusPromptIfNoActiveEditor: () => void;
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
  const renderer = useRenderer();

  const refocusPrompt = useCallback(() => {
    setTimeout(() => {
      promptRef.current?.focus();
    }, 1);
  }, []);

  const refocusPromptIfNoActiveEditor = useCallback(() => {
    setTimeout(() => {
      const prompt = promptRef.current?.getTextareaRef() ?? null;
      if (!shouldRefocusPrompt(renderer.currentFocusedEditor, prompt)) {
        return;
      }
      promptRef.current?.focus();
    }, 1);
  }, [renderer]);

  const focusPrompt = useCallback(() => promptRef.current?.focus(), []);
  const blurPrompt = useCallback(() => promptRef.current?.blur(), []);
  const resetPrompt = useCallback(() => promptRef.current?.reset(), []);
  const setPromptValue = useCallback(
    (value: string) => promptRef.current?.setValue(value),
    [],
  );
  const getPromptValue = useCallback(
    () => promptRef.current?.getValue() ?? "",
    [],
  );
  const registerPromptRef = useCallback((ref: PromptInputRef | null) => {
    promptRef.current = ref;
  }, []);

  return (
    <FocusContext.Provider
      value={{
        promptRef,
        refocusPrompt,
        refocusPromptIfNoActiveEditor,
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
