import {
  useState,
  useEffect,
  useImperativeHandle,
  forwardRef,
  useRef,
  useMemo,
} from "react";
import { useKeyboard } from "@opentui/react";
import type { TextareaRenderable, RGBA } from "@opentui/core";
import { useTheme } from "../../theme";
import { useInput } from "../../context/input";
import { useFocus } from "../../context/focus";
import {
  filterSuggestions,
  resolveSubmitValue,
  computeUpArrow,
  computeDownArrow,
  computeTab,
  shouldResetHistory,
} from "./prompt-input-logic";
export interface AutocompleteOption {
  value: string;
  label: string;
  description?: string;
}

/**
 * Textarea keybindings for chat-style input.
 *
 * Terminal key semantics:
 * - Enter sends \r (carriage return) → @opentui parses as "return"
 * - Shift+Enter / Ctrl+J send \n (linefeed) → @opentui parses as "linefeed"
 * - Kitty keyboard protocol reports Shift+Enter as shift+return explicitly
 *
 * We override @opentui's textarea defaults (return=newline, Cmd+return=submit)
 * to make Enter submit and Shift+Enter / Ctrl+J insert newlines.
 */
const chatKeyBindings = [
  { name: "return", action: "submit" },
  { name: "linefeed", action: "newline" },
  { name: "return", shift: true, action: "newline" },
] as const;

export interface PromptInputRef {
  focus: () => void;
  blur: () => void;
  reset: () => void;
  setValue: (value: string) => void;
  getValue: () => string;
  getTextareaRef: () => TextareaRenderable | null;
}

interface PromptInputProps {
  // Appearance props
  width?: number | "auto" | `${number}%`;
  minHeight?: number;
  maxHeight?: number;
  focused?: boolean;
  placeholder?: string;
  textColor?: string | RGBA;
  focusedTextColor?: string | RGBA;
  backgroundColor?: string;
  focusedBackgroundColor?: string;
  cursorColor?: string;

  // Callbacks
  onSubmit?: (value: string) => void;

  // Autocomplete configuration
  enableAutocomplete?: boolean;
  autocompleteOptions?: AutocompleteOption[];
  maxSuggestions?: number;

  // Command execution
  enableCommands?: boolean;
  onCommandExecute?: (command: string) => Promise<void>;

  // Command history (up/down arrow navigation)
  commandHistory?: string[];

  // When true, Up/Down history navigation is suppressed (e.g. queue navigation takes priority)
  disableHistoryNavigation?: boolean;

  // Visual customization
  showPromptIndicator?: boolean;
}

export const PromptInput = forwardRef<PromptInputRef, PromptInputProps>(
  function PromptInput(
    {
      width,
      minHeight = 1,
      maxHeight = 6,
      focused = true,
      placeholder,
      textColor,
      focusedTextColor,
      backgroundColor,
      focusedBackgroundColor,
      cursorColor,
      onSubmit,
      enableAutocomplete = false,
      autocompleteOptions = [],
      maxSuggestions = 10,
      enableCommands = false,
      onCommandExecute,
      commandHistory = [],
      disableHistoryNavigation = false,
      showPromptIndicator = false,
    },
    ref,
  ) {
    const { colors } = useTheme();
    const { inputValue, setInputValue } = useInput();
    const { registerPromptRef } = useFocus();
    const textareaRef = useRef<TextareaRenderable | null>(null);
    const [selectedSuggestionIndex, setSelectedSuggestionIndex] = useState(-1);

    // Command history navigation state
    // -1 = not browsing history (showing current input)
    const [historyIndex, setHistoryIndex] = useState(-1);
    const savedInputRef = useRef("");
    const historyRef = useRef(commandHistory);
    historyRef.current = commandHistory;
    // Guard to prevent handleContentChange from resetting historyIndex during programmatic setText
    const isNavigatingHistoryRef = useRef(false);

    // Refs to avoid stale closures in handleSubmit (textarea caches onSubmit)
    const selectedIndexRef = useRef(selectedSuggestionIndex);
    const suggestionsRef = useRef<AutocompleteOption[]>([]);
    const onCommandExecuteRef = useRef(onCommandExecute);
    onCommandExecuteRef.current = onCommandExecute;
    const onSubmitRef = useRef(onSubmit);
    onSubmitRef.current = onSubmit;

    const suggestions = useMemo(
      () =>
        enableAutocomplete
          ? filterSuggestions(inputValue, autocompleteOptions, maxSuggestions)
          : [],
      [enableAutocomplete, autocompleteOptions, inputValue, maxSuggestions],
    );

    // Keep refs in sync
    useEffect(() => {
      suggestionsRef.current = suggestions;
    }, [suggestions]);

    useEffect(() => {
      selectedIndexRef.current = selectedSuggestionIndex;
    }, [selectedSuggestionIndex]);

    // Reset selection when suggestions change
    useEffect(() => {
      setSelectedSuggestionIndex(suggestions.length > 0 ? 0 : -1);
    }, [suggestions.length]);

    // Create imperative handle
    const imperativeRef = useRef<PromptInputRef>({
      focus: () => textareaRef.current?.focus(),
      blur: () => textareaRef.current?.blur(),
      reset: () => {
        setInputValue("");
        textareaRef.current?.setText("");
        setSelectedSuggestionIndex(-1);
      },
      setValue: (value: string) => {
        setInputValue(value);
        textareaRef.current?.setText(value);
      },
      getValue: () => inputValue,
      getTextareaRef: () => textareaRef.current,
    });

    // Update the imperative ref when inputValue changes
    useEffect(() => {
      imperativeRef.current.getValue = () => inputValue;
    }, [inputValue]);

    // Expose methods via ref
    useImperativeHandle(ref, () => imperativeRef.current, []);

    // Register with focus context on mount
    useEffect(() => {
      registerPromptRef(imperativeRef.current);
      return () => registerPromptRef(null);
    }, [registerPromptRef]);

    // Handle keyboard navigation for suggestions and command history.
    //
    // Priority: up/down navigate command history. When the user reaches
    // the bottom of history (current input) and presses down again with
    // autocomplete suggestions visible, navigation overflows into the
    // suggestion list. Pressing up past the top of the list exits back
    // to history. Tab always accepts the highlighted suggestion.
    useKeyboard((key) => {
      if (!focused) return;

      // --- Ctrl+C: clear input ------------------------------------------
      if (key.ctrl && key.name === "c") {
        textareaRef.current?.setText("");
        setInputValue("");
        setHistoryIndex(-1);
        setSelectedSuggestionIndex(-1);
        return;
      }

      // --- Tab: accept the highlighted autocomplete suggestion -----------
      if (suggestions.length > 0 && key.name === "tab") {
        key.preventDefault?.();
        const tabResult = computeTab(suggestions, selectedIndexRef.current);
        if (tabResult) {
          setSelectedSuggestionIndex(tabResult.selectedSuggestionIndex);
          if (tabResult.acceptedValue !== null) {
            textareaRef.current?.setText(tabResult.acceptedValue);
            setInputValue(tabResult.acceptedValue);
            textareaRef.current?.gotoLineEnd();
          }
        }
        return;
      }

      // Skip history navigation when parent handles Up/Down (e.g. queue navigation)
      if (disableHistoryNavigation) return;

      const history = historyRef.current;
      const currentState = {
        historyIndex,
        selectedSuggestionIndex: selectedIndexRef.current,
      };

      // --- Up arrow -----------------------------------------------------
      if (key.name === "up") {
        const result = computeUpArrow(
          currentState,
          history,
          suggestions.length,
        );
        if (!result) return;

        if (result.saveCurrentInput) {
          savedInputRef.current = textareaRef.current?.plainText ?? "";
        }
        setSelectedSuggestionIndex(result.nextState.selectedSuggestionIndex);
        if (result.textToSet !== null) {
          isNavigatingHistoryRef.current = true;
          textareaRef.current?.setText(result.textToSet);
          setInputValue(result.textToSet);
          setHistoryIndex(result.nextState.historyIndex);
          setTimeout(() => {
            isNavigatingHistoryRef.current = false;
            textareaRef.current?.gotoLineEnd();
          }, 0);
        } else {
          setHistoryIndex(result.nextState.historyIndex);
        }
        return;
      }

      // --- Down arrow ---------------------------------------------------
      if (key.name === "down") {
        const result = computeDownArrow(
          currentState,
          history,
          suggestions.length,
          savedInputRef.current,
        );
        if (!result) return;

        setSelectedSuggestionIndex(result.nextState.selectedSuggestionIndex);
        if (result.textToSet !== null) {
          isNavigatingHistoryRef.current = true;
          textareaRef.current?.setText(result.textToSet);
          setInputValue(result.textToSet);
          setHistoryIndex(result.nextState.historyIndex);
          setTimeout(() => {
            isNavigatingHistoryRef.current = false;
            textareaRef.current?.gotoLineEnd();
          }, 0);
        } else {
          setHistoryIndex(result.nextState.historyIndex);
        }
        return;
      }
    });

    // Submit handler called by textarea's onSubmit.
    // Uses refs for all callbacks because textarea caches onSubmit at mount.
    const handleSubmit = async () => {
      const currentSuggestions = suggestionsRef.current;
      const currentSelectedIndex = selectedIndexRef.current;

      const valueToSubmit = resolveSubmitValue(
        textareaRef.current?.plainText ?? "",
        currentSuggestions,
        currentSelectedIndex,
      );
      if (currentSuggestions.length > 0 && currentSelectedIndex >= 0) {
        setSelectedSuggestionIndex(-1);
      }

      if (!valueToSubmit) return;

      if (enableCommands && valueToSubmit.startsWith("/")) {
        await onCommandExecuteRef.current?.(valueToSubmit);
        setInputValue("");
        textareaRef.current?.setText("");
        setSelectedSuggestionIndex(-1);
        setHistoryIndex(-1);
        return;
      }

      setHistoryIndex(-1);
      onSubmitRef.current?.(valueToSubmit);
    };

    // Content change syncs to context and resets history browsing
    const handleContentChange = () => {
      const text = textareaRef.current?.plainText ?? "";
      setInputValue(text);
      if (shouldResetHistory(historyIndex, isNavigatingHistoryRef.current)) {
        setHistoryIndex(-1);
      }
    };

    return (
      <box flexDirection="column">
        {/* Input row with optional prompt indicator */}
        <box flexDirection="row">
          {showPromptIndicator && (
            <text marginRight={2} fg={colors.primary}>
              {"❯ "}
            </text>
          )}
          <textarea
            ref={textareaRef}
            width={width}
            minHeight={minHeight}
            maxHeight={maxHeight}
            focused={focused}
            placeholder={placeholder}
            textColor={textColor}
            focusedTextColor={focusedTextColor}
            backgroundColor={backgroundColor}
            focusedBackgroundColor={focusedBackgroundColor}
            cursorColor={cursorColor ?? colors.textMuted}
            keyBindings={chatKeyBindings}
            onContentChange={handleContentChange}
            onSubmit={handleSubmit}
          />
        </box>

        {/* Autocomplete suggestions */}
        {suggestions.length > 0 && (
          <box flexDirection="column" marginTop={1}>
            {suggestions.map((suggestion, index) => {
              const isSelected = index === selectedSuggestionIndex;
              return (
                <box key={suggestion.value} flexDirection="row" gap={1}>
                  <text fg={isSelected ? colors.primary : colors.textMuted}>
                    {isSelected ? " ▸" : "  "}
                  </text>
                  <text fg={isSelected ? colors.text : colors.textMuted}>
                    {suggestion.label}
                  </text>
                  {suggestion.description && (
                    <text fg={colors.textMuted}> {suggestion.description}</text>
                  )}
                </box>
              );
            })}
          </box>
        )}
      </box>
    );
  },
);

export default PromptInput;
