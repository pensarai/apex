import {
  useState,
  useEffect,
  useImperativeHandle,
  forwardRef,
  useRef,
  useMemo,
} from "react";
import { useKeyboard } from "@opentui/react";
import type {
  TextareaRenderable,
  KeyBinding as TextareaKeyBinding,
  RGBA,
} from "@opentui/core";
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
 * Chat-style keybindings: Enter submits, Shift+Enter / Ctrl+J inserts newline.
 * Overrides @opentui defaults (return=newline, Cmd+return=submit).
 *
 * Both "return" (\r) and "linefeed" (\n) need shift variants because
 * @opentui matches modifiers exactly (Kitty protocol reports shift explicitly).
 */
const chatKeyBindings: TextareaKeyBinding[] = [
  { name: "return", action: "submit" },
  { name: "linefeed", action: "newline" },
  { name: "return", shift: true, action: "newline" },
  { name: "linefeed", shift: true, action: "newline" },
];

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

    // Paste extmark tracking — virtual extmarks for atomic inline placeholders
    const pasteCountRef = useRef(0);
    const pasteTypeIdRef = useRef<number>(-1);
    // Own map of extmark ID → { fullText, placeholder } for paste resolution
    const pasteDataRef = useRef<
      Map<number, { fullText: string; placeholder: string }>
    >(new Map());

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
        textareaRef.current?.extmarks.clear();
        pasteCountRef.current = 0;
        pasteDataRef.current.clear();
        setSelectedSuggestionIndex(-1);
      },
      setValue: (value: string) => {
        setInputValue(value);
        textareaRef.current?.setText(value);
        textareaRef.current?.extmarks.clear();
        pasteCountRef.current = 0;
        pasteDataRef.current.clear();
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
        textareaRef.current?.extmarks.clear();
        pasteCountRef.current = 0;
        pasteDataRef.current.clear();
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

    // Paste handler: intercept large pastes, insert inline placeholder with virtual extmark
    const handlePaste = (event: {
      text: string;
      preventDefault: () => void;
    }) => {
      const textarea = textareaRef.current;
      if (!textarea) return;

      const text = event.text;
      const lineCount = text.split("\n").length;

      // Small pastes pass through normally
      if (lineCount < 5 && text.length < 500) return;

      event.preventDefault();

      // Register extmark type on first use
      if (pasteTypeIdRef.current === -1) {
        pasteTypeIdRef.current =
          textarea.extmarks.registerType("pasted-block");
      }

      pasteCountRef.current += 1;
      const n = pasteCountRef.current;
      const placeholder = `[Pasted text #${n} +${lineCount} lines]`;

      const startOffset = textarea.cursorOffset;
      textarea.insertText(placeholder);
      const endOffset = startOffset + placeholder.length;

      const extmarkId = textarea.extmarks.create({
        start: startOffset,
        end: endOffset,
        virtual: true,
        typeId: pasteTypeIdRef.current,
      });
      pasteDataRef.current.set(extmarkId, { fullText: text, placeholder });
    };

    // Resolve paste extmark placeholders back to their full text.
    // Only expands if the placeholder text at the extmark range is unmodified.
    const resolvePasteExtmarks = (plainText: string): string => {
      const dataMap = pasteDataRef.current;
      if (dataMap.size === 0) return plainText;

      const textarea = textareaRef.current;
      if (!textarea) return plainText;

      const allExtmarks = textarea.extmarks.getAll();
      const pasteExtmarks = allExtmarks.filter((ext) => dataMap.has(ext.id));

      if (pasteExtmarks.length === 0) return plainText;

      // Sort by start offset ascending, splice in full text
      const sorted = [...pasteExtmarks].sort((a, b) => a.start - b.start);
      let result = "";
      let lastEnd = 0;
      for (const ext of sorted) {
        result += plainText.slice(lastEnd, ext.start);
        const entry = dataMap.get(ext.id)!;
        const currentText = plainText.slice(ext.start, ext.end);
        // Only expand if placeholder is still intact
        if (currentText === entry.placeholder) {
          result += entry.fullText;
        } else {
          result += currentText;
        }
        lastEnd = ext.end;
      }
      result += plainText.slice(lastEnd);
      return result;
    };

    // Submit handler called by textarea's onSubmit.
    // Uses refs for all callbacks because textarea caches onSubmit at mount.
    const handleSubmit = async () => {
      const currentSuggestions = suggestionsRef.current;
      const currentSelectedIndex = selectedIndexRef.current;

      // Resolve paste placeholders to full text before submit
      const rawText = resolvePasteExtmarks(
        textareaRef.current?.plainText ?? "",
      );

      const valueToSubmit = resolveSubmitValue(
        rawText,
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
        textareaRef.current?.extmarks.clear();
        pasteCountRef.current = 0;
        pasteDataRef.current.clear();
        setSelectedSuggestionIndex(-1);
        setHistoryIndex(-1);
        return;
      }

      setHistoryIndex(-1);
      textareaRef.current?.extmarks.clear();
      pasteCountRef.current = 0;
      pasteDataRef.current.clear();
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
            onPaste={handlePaste}
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
